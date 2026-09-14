package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/mfahlandt/vexviper/internal/bomhort"
	"github.com/mfahlandt/vexviper/internal/config"
	"github.com/mfahlandt/vexviper/internal/evidence"
	"github.com/mfahlandt/vexviper/internal/llm"
	"github.com/mfahlandt/vexviper/internal/pipeline"
)

type fakeBOMHort struct {
	sboms      []bomhort.SBOM
	vulns      []bomhort.Vulnerability
	raw        []byte
	uploads    []string
	statements []bomhort.VEXStatement
}

func (f *fakeBOMHort) FindSBOM(_ context.Context, ref string) (bomhort.SBOM, error) {
	for _, s := range f.sboms {
		if ref == s.ID || ref == s.DocumentName || ref == s.SourceFile {
			return s, nil
		}
	}
	return bomhort.SBOM{}, errors.New("sbom not found: " + ref)
}
func (f *fakeBOMHort) AllSBOMs(context.Context) ([]bomhort.SBOM, error) { return f.sboms, nil }
func (f *fakeBOMHort) Vulnerabilities(context.Context, string) ([]bomhort.Vulnerability, error) {
	return f.vulns, nil
}
func (f *fakeBOMHort) Dependencies(context.Context, string) ([]bomhort.DependencyNode, error) {
	return nil, nil
}
func (f *fakeBOMHort) DownloadSBOM(context.Context, string) ([]byte, error) { return f.raw, nil }
func (f *fakeBOMHort) UploadVEX(_ context.Context, name string, doc []byte) (bomhort.UploadResult, error) {
	f.uploads = append(f.uploads, name)
	var d vex.VEX
	if err := json.Unmarshal(doc, &d); err != nil {
		return bomhort.UploadResult{}, err
	}
	for _, s := range d.Statements {
		f.statements = append(f.statements, bomhort.VEXStatement{DocumentID: d.ID, VulnID: string(s.Vulnerability.Name), ProductPURL: s.Products[0].ID, Status: string(s.Status)})
	}
	return bomhort.UploadResult{Status: "pending", JobID: "j1", SHA256Hash: "abc"}, nil
}
func (f *fakeBOMHort) VEXStatements(_ context.Context, page, size int) (bomhort.Paginated[bomhort.VEXStatement], error) {
	start := (page - 1) * size
	if start > len(f.statements) {
		start = len(f.statements)
	}
	end := start + size
	if end > len(f.statements) {
		end = len(f.statements)
	}
	return bomhort.Paginated[bomhort.VEXStatement]{Data: f.statements[start:end], Total: uint64(len(f.statements)), Page: uint64(page), PageSize: uint64(size)}, nil
}

type session struct {
	*mcp.ClientSession
	bh  *fakeBOMHort
	out string
}

func newSession(t *testing.T) *session {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "bomhort-0.6.1.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	bh := &fakeBOMHort{
		sboms: []bomhort.SBOM{
			{ID: "s1", DocumentName: ".", SourceFile: "bomhort-0.6.1.spdx.json", PackageCount: 118, VulnCount: 2},
			{ID: "s2", DocumentName: "other-app", SourceFile: "other.spdx.json"},
		},
		vulns: []bomhort.Vulnerability{
			{VulnID: "GO-2025-0001", PURL: "pkg:golang/golang.org/x/net@v0.30.0", Severity: "HIGH", FixedVersion: "v0.31.0"},
			{VulnID: "GO-2025-0002", PURL: "pkg:golang/github.com/foo/bar@v1.2.3", Severity: "LOW", VEXStatus: "not_affected"},
		},
		raw: raw,
	}
	cfg := config.Default()
	cfg.Repo.Clone = false
	cfg.VEX.OutDir = t.TempDir()
	p := &pipeline.Pipeline{
		Cfg:      cfg,
		BOMHort:  bh,
		Provider: llm.Heuristic{},
		Evidence: &evidence.Collector{},
		Log:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	srv := (&Server{Pipeline: p, Lister: bh, Version: "test"}).New()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-host", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return &session{ClientSession: cs, bh: bh, out: cfg.VEX.OutDir}
}

// call invokes a tool and decodes its structured content into out.
func (s *session) call(t *testing.T, name string, args map[string]any, out any) *mcp.CallToolResult {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		return res
	}
	data, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("%s: decode %s: %v", name, data, err)
	}
	return res
}

func errText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestToolsRegistered(t *testing.T) {
	s := newSession(t)
	tools, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"list_sboms": true, "list_findings": true, "get_repo_context": true, "draft_vex": true, "generate_vex": true, "upload_vex": true, "list_vex_statements": true}
	for _, tl := range tools.Tools {
		delete(want, tl.Name)
		if tl.InputSchema == nil {
			t.Errorf("%s has no input schema", tl.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing tools: %v", want)
	}
}

func TestListSBOMsAndFindings(t *testing.T) {
	s := newSession(t)
	var out listSBOMsOut
	s.call(t, "list_sboms", nil, &out)
	if len(out.SBOMs) != 2 || out.SBOMs[0].ID != "s1" || out.SBOMs[0].VulnCount != 2 {
		t.Fatalf("sboms = %+v", out.SBOMs)
	}
	s.call(t, "list_sboms", map[string]any{"search": "OTHER"}, &out)
	if len(out.SBOMs) != 1 || out.SBOMs[0].ID != "s2" {
		t.Fatalf("filtered sboms = %+v", out.SBOMs)
	}

	var f findingsOut
	s.call(t, "list_findings", map[string]any{"sbom": "bomhort-0.6.1.spdx.json"}, &f)
	if f.Product.SBOMID != "s1" || len(f.Findings) != 2 || f.Findings[1].VEXStatus != "not_affected" {
		t.Fatalf("findings = %+v", f)
	}
	if len(f.Product.RepoHints) == 0 || f.Product.RepoHints[0] != "https://github.com/seebom-labs/bomhort" {
		t.Fatalf("repo hints = %v", f.Product.RepoHints)
	}

	res := s.call(t, "list_findings", map[string]any{"sbom": "missing"}, &f)
	if !res.IsError || !strings.Contains(errText(res), "not found") {
		t.Fatalf("expected error, got %+v", res)
	}
}

func TestGetRepoContext(t *testing.T) {
	s := newSession(t)
	var out repoContextOut
	s.call(t, "get_repo_context", map[string]any{"sbom": "s1"}, &out)
	if out.RepoURL != "https://github.com/seebom-labs/bomhort" || out.RepoDir != "" {
		t.Fatalf("repo = %q dir=%q", out.RepoURL, out.RepoDir)
	}
	if len(out.Findings) != 1 || out.Findings[0].Finding.VulnID != "GO-2025-0001" {
		t.Fatalf("findings = %+v", out.Findings)
	}
	fc := out.Findings[0]
	if !strings.Contains(fc.Prompt, "GO-2025-0001") || out.SystemPrompt == "" || out.Schema["type"] != "object" {
		t.Fatalf("prompt/schema missing: %+v", fc)
	}
	kinds := map[evidence.Kind]bool{}
	for _, it := range fc.Evidence {
		kinds[it.Kind] = true
	}
	if !kinds[evidence.KindVersionVulnerable] || !kinds[evidence.KindRepoUnavailable] {
		t.Fatalf("evidence kinds = %v", kinds)
	}

	s.call(t, "get_repo_context", map[string]any{"sbom": "s1", "include_assessed": true}, &out)
	if len(out.Findings) != 2 {
		t.Fatalf("include_assessed: %d findings", len(out.Findings))
	}
}

func TestDraftUploadAndList(t *testing.T) {
	s := newSession(t)
	var out docOut
	res := s.call(t, "draft_vex", map[string]any{
		"sbom": "s1",
		"assessments": []map[string]any{
			{"vuln_id": "GO-2025-0001", "purl": "pkg:golang/golang.org/x/net@v0.30.0", "status": "affected", "action_statement": "upgrade to v0.31.0", "confidence": 0.9, "reasoning": "reviewed by human"},
			{"vuln_id": "GO-2025-0002", "purl": "pkg:golang/github.com/foo/bar@v1.2.3", "status": "not_affected", "justification": "vulnerable_code_not_present", "confidence": 0.9, "reasoning": "no evidence"},
		},
		"author": "Jane Reviewer",
	}, &out)
	if res.IsError {
		t.Fatal(errText(res))
	}
	if out.Filename != "bomhort-0.6.1.vexviper.openvex.json" || out.Path == "" || out.DocumentID == "" {
		t.Fatalf("out = %+v", out)
	}
	if out.Counts["affected"] != 1 || out.Counts["under_investigation"] != 1 || len(out.Guardrails) != 1 {
		t.Fatalf("counts=%v guardrails=%v", out.Counts, out.Guardrails)
	}
	if _, err := os.Stat(out.Path); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out.Document)
	var doc vex.VEX
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Author != "Jane Reviewer" || len(doc.Statements) != 2 {
		t.Fatalf("doc = %+v", doc.Metadata)
	}
	if len(s.bh.uploads) != 0 {
		t.Fatal("draft should not upload without upload=true")
	}

	// unknown finding is rejected
	res = s.call(t, "draft_vex", map[string]any{"sbom": "s1", "assessments": []map[string]any{{"vuln_id": "X", "purl": "pkg:golang/x@1", "status": "affected", "confidence": 1, "reasoning": "r"}}}, &out)
	if !res.IsError || !strings.Contains(errText(res), "must match exactly") {
		t.Fatalf("expected mismatch error: %s", errText(res))
	}
	res = s.call(t, "draft_vex", map[string]any{"sbom": "s1", "assessments": []map[string]any{}}, &out)
	if !res.IsError {
		t.Fatal("expected error for empty assessments")
	}

	// upload by path
	var up uploadOut
	res = s.call(t, "upload_vex", map[string]any{"path": out.Path}, &up)
	if res.IsError {
		t.Fatal(errText(res))
	}
	if up.JobID != "j1" || s.bh.uploads[0] != out.Filename {
		t.Fatalf("upload = %+v uploads=%v", up, s.bh.uploads)
	}
	// upload inline
	res = s.call(t, "upload_vex", map[string]any{"filename": "x.openvex.json", "document": out.Document}, &up)
	if res.IsError {
		t.Fatal(errText(res))
	}
	// bad filename
	res = s.call(t, "upload_vex", map[string]any{"filename": "x.json", "document": out.Document}, &up)
	if !res.IsError {
		t.Fatal("expected filename error")
	}
	// invalid statement
	bad := map[string]any{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "x", "author": "a", "timestamp": "2025-01-01T00:00:00Z", "version": 1,
		"statements": []map[string]any{{"vulnerability": map[string]any{"name": "V"}, "products": []map[string]any{{"@id": "p"}}, "status": "not_affected"}}}
	res = s.call(t, "upload_vex", map[string]any{"filename": "bad.openvex.json", "document": bad}, &up)
	if !res.IsError || !strings.Contains(errText(res), "invalid") {
		t.Fatalf("expected validation error: %s", errText(res))
	}

	var st statementsOut
	s.call(t, "list_vex_statements", map[string]any{"document_id": out.DocumentID, "vuln_id": "GO-2025-0001"}, &st)
	if len(st.Statements) != 2 || st.Statements[0].Status != "affected" {
		t.Fatalf("statements = %+v (total %d)", st.Statements, st.Total)
	}
}

func TestGenerateVEX(t *testing.T) {
	s := newSession(t)
	var out generateOut
	res := s.call(t, "generate_vex", map[string]any{"sbom": "s1", "upload": true}, &out)
	if res.IsError {
		t.Fatal(errText(res))
	}
	if out.Findings != 1 || out.Skipped != 1 || out.Upload == nil || out.Upload.JobID != "j1" || out.DocumentID == "" {
		t.Fatalf("out = %+v", out)
	}
	if out.Assessments[0].Status != vex.StatusUnderInvestigation {
		t.Fatalf("heuristic offline should yield under_investigation: %+v", out.Assessments)
	}
	if _, err := os.Stat(filepath.Join(s.out, out.Filename)); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateVEXRegenerateAndForce(t *testing.T) {
	s := newSession(t)
	var out generateOut
	// GO-2025-0002 is not_affected: regenerate keeps it, force re-assesses it.
	if res := s.call(t, "generate_vex", map[string]any{"sbom": "s1", "regenerate": true}, &out); res.IsError {
		t.Fatal(errText(res))
	}
	if out.Findings != 1 || out.Skipped != 1 || out.Settled != 1 {
		t.Fatalf("regenerate: %+v", out)
	}
	out = generateOut{}
	if res := s.call(t, "generate_vex", map[string]any{"sbom": "s1", "force": true}, &out); res.IsError {
		t.Fatal(errText(res))
	}
	if out.Findings != 2 || out.Skipped != 0 || out.Settled != 0 {
		t.Fatalf("force: %+v", out)
	}
}

func TestHTTPHandler(t *testing.T) {
	s := newSession(t)
	cfg := config.Default()
	cfg.Repo.Clone = false
	p := &pipeline.Pipeline{Cfg: cfg, BOMHort: s.bh, Provider: llm.Heuristic{}, Evidence: &evidence.Collector{}}
	ts := httptest.NewServer((&Server{Pipeline: p, Lister: s.bh}).Handler())
	defer ts.Close()

	cs, err := mcp.NewClient(&mcp.Implementation{Name: "http-host", Version: "0"}, nil).Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_sboms", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
}
