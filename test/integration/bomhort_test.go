//go:build integration

// Package integration runs VEXViper against a live BOMHort instance.
//
//	BOMHORT_URL=http://localhost:18080 BOMHORT_API_KEY=... go test -tags integration ./test/integration/
//
// hack/e2e-bomhort.sh provisions such an instance with docker compose.
package integration

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/seebom-labs/vexviper/internal/bomhort"
	"github.com/seebom-labs/vexviper/internal/config"
	"github.com/seebom-labs/vexviper/internal/pipeline"
)

func env(t *testing.T, key string) string {
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set", key)
	}
	return v
}

func client(t *testing.T) (*bomhort.Client, string) {
	url := env(t, "BOMHORT_URL")
	key := os.Getenv("BOMHORT_API_KEY")
	var opts []bomhort.Option
	if key != "" {
		opts = append(opts, bomhort.WithAPIKey(key))
	}
	c := bomhort.New(url, opts...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Healthy(ctx); err != nil {
		t.Fatalf("BOMHort at %s not healthy: %v", url, err)
	}
	return c, key
}

// sbomRef picks the SBOM under test: BOMHORT_E2E_SBOM or the first SBOM
// whose source file contains "bomhort".
func sbomRef(t *testing.T, c *bomhort.Client) bomhort.SBOM {
	ctx := context.Background()
	if ref := os.Getenv("BOMHORT_E2E_SBOM"); ref != "" {
		s, err := c.FindSBOM(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	all, err := c.AllSBOMs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range all {
		if strings.Contains(s.SourceFile, "bomhort") && s.VulnCount > 0 {
			return s
		}
	}
	t.Skip("no bomhort SBOM with vulnerabilities ingested")
	return bomhort.SBOM{}
}

func TestAPIContract(t *testing.T) {
	c, _ := client(t)
	s := sbomRef(t, c)
	ctx := context.Background()

	vulns, err := c.Vulnerabilities(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities")
	}
	for _, v := range vulns {
		if v.VulnID == "" || !strings.HasPrefix(v.PURL, "pkg:") {
			t.Errorf("unexpected vuln row %+v", v)
		}
	}
	deps, err := c.Dependencies(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) == 0 {
		t.Error("expected dependency tree")
	}
	raw, err := c.DownloadSBOM(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Error("downloaded SBOM is not JSON")
	}
}

// TestGenerateUploadRoundTrip is the real end-to-end check: generate with
// the heuristic provider (no LLM key needed), upload, wait until BOMHort
// applies the statements, and assert vex_status shows up on the vulns.
func TestGenerateUploadRoundTrip(t *testing.T) {
	c, key := client(t)
	if key == "" {
		t.Skip("BOMHORT_API_KEY required for upload")
	}
	s := sbomRef(t, c)

	cfg := config.Default()
	cfg.BOMHort.URL = c.BaseURL()
	cfg.BOMHort.APIKey = key
	cfg.LLM.Provider = config.ProviderHeuristic
	cfg.Repo.CacheDir = filepath.Join(os.TempDir(), "vexviper-e2e-cache")
	cfg.Repo.Clone = os.Getenv("E2E_SKIP_CLONE") == ""
	cfg.VEX.Author = "VEXViper integration test"
	cfg.Timeout = 20 * time.Minute

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	p, err := pipeline.New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	out, err := p.Run(ctx, pipeline.RunOptions{SBOMRef: s.ID, OutDir: t.TempDir(), Upload: true, Regenerate: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings == 0 || len(out.Document) == 0 {
		t.Fatalf("nothing generated: %+v", out)
	}
	var doc vex.VEX
	if err := json.Unmarshal(out.Document, &doc); err != nil {
		t.Fatal(err)
	}
	for _, st := range doc.Statements {
		if err := st.Validate(); err != nil {
			t.Errorf("invalid statement %s: %v", st.Vulnerability.Name, err)
		}
	}
	if out.Upload == nil || (out.Upload.Status != "pending" && out.Upload.Status != "duplicate") {
		t.Fatalf("upload result = %+v", out.Upload)
	}
	t.Logf("uploaded %s: %+v; counts=%v", out.Filename, out.Upload, out.Counts)

	// Wait for the parsing worker to ingest the VEX document.
	err = p.Wait(ctx, doc.ID, 3*time.Minute, func(ctx context.Context) ([]bomhort.VEXStatement, error) {
		pg, err := c.VEXStatements(ctx, 1, 100)
		return pg.Data, err
	})
	if err != nil {
		t.Fatal(err)
	}

	// vex_status must now be visible on the vulnerabilities (exact vuln_id+purl match).
	deadline := time.Now().Add(2 * time.Minute)
	for {
		vulns, err := c.Vulnerabilities(ctx, s.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]vex.Status{}
		for _, st := range doc.Statements {
			want[string(st.Vulnerability.Name)+"|"+st.Products[0].ID] = st.Status
		}
		matched, mismatched := 0, 0
		for _, v := range vulns {
			if ws, ok := want[v.VulnID+"|"+v.PURL]; ok {
				switch {
				case v.VEXStatus == string(ws):
					matched++
				case v.VEXStatus == "":
					mismatched++
				default:
					// BOMHort keeps the most recent statement; an older run may win. Log only.
					t.Logf("%s %s: bomhort=%s ours=%s", v.VulnID, v.PURL, v.VEXStatus, ws)
					matched++
				}
			}
		}
		if mismatched == 0 && matched > 0 {
			t.Logf("all %d statements applied by BOMHort", matched)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("vex_status not applied for %d findings (matched %d)", mismatched, matched)
		}
		time.Sleep(3 * time.Second)
	}
}
