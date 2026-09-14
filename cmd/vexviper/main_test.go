package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/mfahlandt/vexviper/internal/bomhort"
	"github.com/mfahlandt/vexviper/internal/bomhort/bomhorttest"
)

const sbomID = "11111111-1111-1111-1111-111111111111"

func fakeBOMHort(t *testing.T) *bomhorttest.Server {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "bomhort-0.6.1.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := bomhorttest.New("secret")
	t.Cleanup(srv.Close)
	srv.AddSBOM(bomhort.SBOM{ID: sbomID, DocumentName: ".", SourceFile: "bomhort-0.6.1.spdx.json", PackageCount: 118, IngestedAt: "2025-01-01T00:00:00Z"},
		[]bomhort.Vulnerability{
			{VulnID: "GO-2025-0001", Severity: "HIGH", PURL: "pkg:golang/golang.org/x/net@v0.30.0", FixedVersion: "v0.31.0"},
			{VulnID: "GO-2025-0002", Severity: "LOW", PURL: "pkg:golang/github.com/foo/bar@v1.0.0", VEXStatus: "not_affected"},
		}, nil, raw)
	return srv
}

func writeConfig(t *testing.T, srv *bomhorttest.Server, outDir string) string {
	t.Helper()
	cfg := `
bomhort:
  url: ` + srv.URL + `
  api_key: secret
llm:
  provider: heuristic
repo:
  clone: false
  govulncheck: false
vex:
  out_dir: ` + outDir + `
  author: Test Author
watch:
  state_file: ` + filepath.Join(outDir, "state.json") + `
`
	p := filepath.Join(t.TempDir(), "vexviper.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGenerateCommand(t *testing.T) {
	srv := fakeBOMHort(t)
	out := t.TempDir()
	cfg := writeConfig(t, srv, out)
	var stdout, stderr bytes.Buffer

	code := run([]string{"generate", "--config", cfg, "--sbom", "bomhort-0.6.1.spdx.json", "--stdout", "--upload", "--wait", "5s", "--log-level", "error"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
	var doc vex.VEX
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout not a VEX doc: %v\n%s", err, stdout.String())
	}
	if doc.Author != "Test Author" || len(doc.Statements) != 1 || string(doc.Statements[0].Vulnerability.Name) != "GO-2025-0001" {
		t.Fatalf("doc = %+v", doc)
	}
	if _, err := os.Stat(filepath.Join(out, "bomhort-0.6.1.vexviper.openvex.json")); err != nil {
		t.Fatal(err)
	}
	uploads, statements := srv.Snapshot()
	if len(uploads) != 1 || !strings.HasSuffix(uploads[0].Filename, ".openvex.json") {
		t.Fatalf("uploads = %+v", uploads)
	}
	if len(statements) != 1 || statements[0].DocumentID != doc.ID || statements[0].VulnID != "GO-2025-0001" {
		t.Fatalf("statements = %+v", statements)
	}
	if !strings.Contains(stderr.String(), "VEXViper summary") || !strings.Contains(stderr.String(), "uploaded:") {
		t.Fatalf("summary missing:\n%s", stderr.String())
	}

	// After ingestion the finding carries a vex_status → nothing left to assess.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"generate", "--config", cfg, "--sbom", sbomID, "--out", "-", "--log-level", "error"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stderr.String(), "findings assessed: 0 (skipped: 2, re-assessed: 0)") {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}

	// --regenerate revisits the under_investigation finding but keeps the
	// settled not_affected one (no provider tokens spent on it).
	stderr.Reset()
	code = run([]string{"generate", "--config", cfg, "--sbom", sbomID, "--out", "-", "--regenerate", "--log-level", "error"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stderr.String(), "findings assessed: 1 (skipped: 1, re-assessed: 0)") ||
		!strings.Contains(stderr.String(), "settled verdicts kept: 1") {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}

	// --force is the hard regenerate: everything is re-assessed.
	stderr.Reset()
	code = run([]string{"generate", "--config", cfg, "--sbom", sbomID, "--out", "-", "--force", "--log-level", "error"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stderr.String(), "findings assessed: 2 (skipped: 0, re-assessed: 0)") ||
		strings.Contains(stderr.String(), "settled verdicts kept") {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
}

func TestGenerateErrors(t *testing.T) {
	srv := fakeBOMHort(t)
	cfg := writeConfig(t, srv, t.TempDir())
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"generate", "--config", cfg}, "--sbom is required"},
		{[]string{"generate", "--config", cfg, "--sbom", "nope", "--log-level", "error"}, "no SBOM matches"},
		{[]string{"generate", "--config", cfg, "--sbom", sbomID, "--provider", "quantum"}, "llm.provider"},
		{[]string{"generate", "--config", "/nonexistent.yaml", "--sbom", sbomID}, "read config"},
		{[]string{"generate", "--config", cfg, "--sbom", sbomID, "--bomhort", "http://127.0.0.1:1", "--log-level", "error"}, "connection refused"},
		{[]string{"bogus"}, "unknown command"},
		{nil, "Usage"},
	}
	for _, c := range cases {
		var stdout, stderr bytes.Buffer
		if code := run(c.args, &stdout, &stderr); code == 0 {
			t.Errorf("%v: expected non-zero exit", c.args)
		}
		if !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%v: stderr %q does not contain %q", c.args, stderr.String(), c.want)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "vexviper dev") {
		t.Fatalf("code=%d out=%q", code, stdout.String())
	}
	stdout.Reset()
	if code := run([]string{"help"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "mcp-serve") {
		t.Fatalf("help: code=%d out=%q", code, stdout.String())
	}
	if code := run([]string{"generate", "-h"}, &stdout, &stderr); code != 0 {
		t.Fatalf("-h should exit 0, got %d", code)
	}
}

func TestWatchOnce(t *testing.T) {
	srv := fakeBOMHort(t)
	out := t.TempDir()
	cfg := writeConfig(t, srv, out)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"watch", "--config", cfg, "--once", "--upload", "--log-level", "error"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
	uploads, _ := srv.Snapshot()
	if len(uploads) != 1 {
		t.Fatalf("uploads = %d", len(uploads))
	}
	state, err := os.ReadFile(filepath.Join(out, "state.json"))
	if err != nil || !strings.Contains(string(state), sbomID) {
		t.Fatalf("state file: %v %s", err, state)
	}
}

func TestMCPServeHTTP(t *testing.T) {
	srv := fakeBOMHort(t)
	cfg := writeConfig(t, srv, t.TempDir())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	var stderr bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- cmdMCPServe(ctx, []string{"--config", cfg, "--transport", "http", "--addr", addr, "--log-level", "error"}, &stderr)
	}()

	var cs *mcp.ClientSession
	deadline := time.Now().Add(5 * time.Second)
	for {
		cs, err = mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "http://" + addr}, nil)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect: %v\n%s", err, stderr.String())
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_findings", Arguments: map[string]any{"sbom": sbomID}})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	_ = cs.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("server error: %v", err)
	}

	var e bytes.Buffer
	if err := cmdMCPServe(context.Background(), []string{"--config", cfg, "--transport", "smoke"}, &e); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestDocumentIDAndTruncate(t *testing.T) {
	if got := documentID([]byte(`{"@context":"x","@id":"https://a/b","author":"c"}`)); got != "https://a/b" {
		t.Fatalf("documentID = %q", got)
	}
	if documentID([]byte(`{}`)) != "" {
		t.Fatal("expected empty id")
	}
	if truncate("abcdef", 4) != "abc…" || truncate("ab", 4) != "ab" {
		t.Fatal("truncate")
	}
}
