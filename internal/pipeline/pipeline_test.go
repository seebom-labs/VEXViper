package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/seebom-labs/vexviper/internal/assesscache"
	"github.com/seebom-labs/vexviper/internal/bomhort"
	"github.com/seebom-labs/vexviper/internal/config"
	"github.com/seebom-labs/vexviper/internal/evidence"
	"github.com/seebom-labs/vexviper/internal/gitops"
	"github.com/seebom-labs/vexviper/internal/llm"
	"github.com/seebom-labs/vexviper/internal/repo"
	"github.com/seebom-labs/vexviper/internal/source"
	"github.com/seebom-labs/vexviper/internal/vexgen"
)

type fakeBOMHort struct {
	sbom         bomhort.SBOM
	vulns        []bomhort.Vulnerability
	deps         []bomhort.DependencyNode
	raw          []byte
	uploads      []string
	uploaded     [][]byte
	uploadScopes []string
	upErr        error
	stmts        []bomhort.VEXStatement
	stmtErr      error
}

func (f *fakeBOMHort) AllVEXStatements(context.Context) ([]bomhort.VEXStatement, error) {
	return f.stmts, f.stmtErr
}

func (f *fakeBOMHort) FindSBOM(_ context.Context, ref string) (bomhort.SBOM, error) {
	if ref != f.sbom.ID && ref != f.sbom.DocumentName {
		return bomhort.SBOM{}, errors.New("not found")
	}
	return f.sbom, nil
}
func (f *fakeBOMHort) Vulnerabilities(context.Context, string) ([]bomhort.Vulnerability, error) {
	return f.vulns, nil
}
func (f *fakeBOMHort) Dependencies(context.Context, string) ([]bomhort.DependencyNode, error) {
	return f.deps, nil
}
func (f *fakeBOMHort) DownloadSBOM(context.Context, string) ([]byte, error) { return f.raw, nil }
func (f *fakeBOMHort) UploadVEX(_ context.Context, name string, doc []byte, sbomID string) (bomhort.UploadResult, error) {
	if f.upErr != nil {
		return bomhort.UploadResult{}, f.upErr
	}
	f.uploads = append(f.uploads, name)
	f.uploaded = append(f.uploaded, doc)
	f.uploadScopes = append(f.uploadScopes, sbomID)
	return bomhort.UploadResult{Status: "pending", JobID: "job-1", JobType: "vex"}, nil
}

type fakeCloner struct {
	dir  string
	locs []repo.Location
	err  error
}

func (c *fakeCloner) Clone(_ context.Context, loc repo.Location) (string, error) {
	c.locs = append(c.locs, loc)
	return c.dir, c.err
}

func newTestPipeline(t *testing.T, bh *fakeBOMHort, prov llm.Provider, cl Cloner) *Pipeline {
	t.Helper()
	cfg := config.Default()
	cfg.Repo.Clone = cl != nil
	cfg.Repo.Govulncheck = false
	return &Pipeline{
		Cfg:      cfg,
		BOMHort:  bh,
		Provider: prov,
		Cloner:   cl,
		Evidence: &evidence.Collector{}, // no OSV → offline
		Log:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}
}

func bomhortFixture(t *testing.T) *fakeBOMHort {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "bomhort-0.6.1.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeBOMHort{
		sbom: bomhort.SBOM{ID: "sbom-1", DocumentName: ".", SourceFile: "bomhort-0.6.1.spdx.json"},
		vulns: []bomhort.Vulnerability{
			{VulnID: "GO-2025-0001", PURL: "pkg:golang/golang.org/x/net@v0.30.0", Severity: "HIGH", FixedVersion: "v0.31.0"},
			{VulnID: "GO-2025-0002", PURL: "pkg:golang/github.com/foo/bar@v1.2.3", Severity: "LOW"},
			{VulnID: "GO-2025-0003", PURL: "pkg:golang/github.com/baz/qux@v2.0.0", Severity: "MEDIUM", VEXStatus: "not_affected"},
		},
		raw: raw,
	}
}

func TestRunWritesDocumentAndUploads(t *testing.T) {
	bh := bomhortFixture(t)
	mock := &llm.Mock{
		ByVulnID: map[string]llm.Assessment{
			"GO-2025-0001": {Status: vex.StatusAffected, ActionStatement: "upgrade to v0.31.0", Confidence: 0.9, Reasoning: "outdated"},
			"GO-2025-0002": {Status: vex.StatusNotAffected, Justification: vex.VulnerableCodeNotInExecutePath, Confidence: 0.95, Reasoning: "unsupported claim"},
		},
	}
	cl := &fakeCloner{dir: t.TempDir()}
	p := newTestPipeline(t, bh, mock, cl)

	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", OutDir: t.TempDir(), Upload: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings != 2 || out.Skipped != 1 {
		t.Fatalf("findings=%d skipped=%d, want 2/1", out.Findings, out.Skipped)
	}
	if len(mock.Calls) != 2 {
		t.Fatalf("provider called %d times", len(mock.Calls))
	}
	// Repo resolved from SBOM hints of the BOMHort SBOM.
	if len(cl.locs) == 0 || cl.locs[0].URL != "https://github.com/seebom-labs/bomhort" || cl.locs[0].Ref != "v0.6.1" {
		t.Fatalf("cloner locs = %+v", cl.locs)
	}
	if out.RepoDir != cl.dir {
		t.Fatalf("RepoDir = %q", out.RepoDir)
	}
	if _, err := os.Stat(out.Path); err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	if out.Filename != "bomhort-0.6.1.vexviper.openvex.json" {
		t.Fatalf("filename = %q", out.Filename)
	}
	if len(bh.uploads) != 1 || bh.uploads[0] != out.Filename {
		t.Fatalf("uploads = %v", bh.uploads)
	}
	if bh.uploadScopes[0] != "sbom-1" {
		t.Fatalf("upload must be scoped to the SBOM (#350), got %q", bh.uploadScopes[0])
	}
	if out.Upload == nil || out.Upload.JobID != "job-1" {
		t.Fatalf("upload result = %+v", out.Upload)
	}

	var doc vex.VEX
	if err := json.Unmarshal(out.Document, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d", len(doc.Statements))
	}
	byVuln := map[string]vex.Statement{}
	for _, s := range doc.Statements {
		byVuln[string(s.Vulnerability.Name)] = s
	}
	if s := byVuln["GO-2025-0001"]; s.Status != vex.StatusAffected || s.Products[0].ID != "pkg:golang/golang.org/x/net@v0.30.0" {
		t.Errorf("GO-2025-0001 = %+v", s)
	}
	// not_affected without strong evidence must be downgraded by the guardrail.
	if s := byVuln["GO-2025-0002"]; s.Status != vex.StatusUnderInvestigation {
		t.Errorf("GO-2025-0002 status = %s, want under_investigation (guardrail)", s.Status)
	}
	if len(out.Guardrails) != 1 {
		t.Errorf("guardrails = %+v", out.Guardrails)
	}
}

func TestRunForceOnlyAndOverride(t *testing.T) {
	bh := bomhortFixture(t)
	mock := &llm.Mock{Default: &llm.Assessment{Status: vex.StatusUnderInvestigation, Confidence: 0.5}}
	cl := &fakeCloner{dir: t.TempDir()}
	p := newTestPipeline(t, bh, mock, cl)

	// GO-2025-0003 is not_affected: only Force re-assesses it.
	out, err := p.Run(context.Background(), RunOptions{SBOMRef: ".", Regenerate: true, Force: true, Only: []string{"go-2025-0003"}, RepoOverride: "acme/product"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings != 1 || out.Skipped != 2 || out.Settled != 0 {
		t.Fatalf("findings=%d skipped=%d settled=%d", out.Findings, out.Skipped, out.Settled)
	}
	if len(mock.Calls) != 1 || mock.Calls[0].Report.Finding.VulnID != "GO-2025-0003" {
		t.Fatalf("provider calls = %d", len(mock.Calls))
	}
	if cl.locs[0].URL != "https://github.com/acme/product" || cl.locs[0].How != "flag" {
		t.Fatalf("override not preferred: %+v", cl.locs[0])
	}
	if out.Path != "" {
		t.Fatalf("no OutDir but Path=%q", out.Path)
	}
	if out.Counts[vex.StatusUnderInvestigation] != 1 {
		t.Fatalf("counts = %v", out.Counts)
	}
}

func TestRunCloneFailureDegrades(t *testing.T) {
	bh := bomhortFixture(t)
	cl := &fakeCloner{err: errors.New("git: boom")}
	p := newTestPipeline(t, bh, llm.Heuristic{}, cl)

	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.RepoDir != "" {
		t.Fatalf("expected no repo dir, got %q", out.RepoDir)
	}
	if len(out.Assessments) != 2 {
		t.Fatalf("assessments = %d", len(out.Assessments))
	}
	// heuristic without code evidence is conservative: everything stays under_investigation
	for _, a := range out.Assessments {
		if a.Status != vex.StatusUnderInvestigation {
			t.Fatalf("%s status = %s", a.VulnID, a.Status)
		}
	}
	if out.Counts[vex.StatusUnderInvestigation] != 2 {
		t.Fatalf("counts = %v", out.Counts)
	}
}

func TestRunNoCloner(t *testing.T) {
	bh := bomhortFixture(t)
	p := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.RepoDir != "" || out.RepoHow != "https://github.com/seebom-labs/bomhort" {
		t.Fatalf("RepoDir=%q RepoHow=%q", out.RepoDir, out.RepoHow)
	}
}

func TestRunProviderErrorIsSurvivable(t *testing.T) {
	bh := bomhortFixture(t)
	p := newTestPipeline(t, bh, &llm.Mock{Err: errors.New("llm down")}, nil)
	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range out.Assessments {
		if a.Status != vex.StatusUnderInvestigation {
			t.Fatalf("%s status = %s", a.VulnID, a.Status)
		}
	}
}

func TestRunUploadErrorReturnsOutcome(t *testing.T) {
	bh := bomhortFixture(t)
	bh.upErr = errors.New("401")
	p := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", Upload: true})
	if err == nil || out == nil || len(out.Document) == 0 {
		t.Fatalf("err=%v out=%v", err, out)
	}
}

func TestRunUnknownSBOM(t *testing.T) {
	p := newTestPipeline(t, bomhortFixture(t), llm.Heuristic{}, nil)
	if _, err := p.Run(context.Background(), RunOptions{SBOMRef: "nope"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestFilename(t *testing.T) {
	cases := []struct {
		p    source.Product
		want string
	}{
		{source.Product{SourceFile: "dir/bomhort-0.6.1.spdx.json"}, "bomhort-0.6.1.vexviper.openvex.json"},
		{source.Product{DocumentName: "my app/v1"}, "my-app-v1.vexviper.openvex.json"},
		{source.Product{SBOMID: "abc"}, "abc.vexviper.openvex.json"},
		{source.Product{DocumentName: "."}, "vex.vexviper.openvex.json"},
		{source.Product{SourceFile: "x.cdx.json"}, "x.vexviper.openvex.json"},
	}
	for _, c := range cases {
		if got := Filename(c.p); got != c.want {
			t.Errorf("Filename(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestVersionFromName(t *testing.T) {
	cases := map[string]string{
		"bomhort-0.6.1.spdx.json":                       "v0.6.1",
		"kubermatic_kubelb_1.4.2.spdx.json":             "v1.4.2",
		"dir/agones_1_57_0_spdx.json":                   "",
		"app-v2.0.0-rc.1.cdx.json":                      "v2.0.0-rc.1",
		"github.com/seebom-labs/bomhort/backend":        "",
		"other.spdx.json":                               "",
		"kubermatic_developer-platform_0.9.0.spdx.json": "v0.9.0",
	}
	for in, want := range cases {
		if got := VersionFromName(in); got != want {
			t.Errorf("VersionFromName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := VersionFromName("", "x-1.2.3"); got != "v1.2.3" {
		t.Errorf("second name: %q", got)
	}
}

func TestNewProvider(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cases := []struct {
		cfg     config.LLM
		wantErr bool
		name    string
	}{
		{config.LLM{Provider: config.ProviderHeuristic}, false, "heuristic"},
		{config.LLM{Provider: config.ProviderOpenAI, OpenAI: config.OpenAI{Model: "m"}}, false, "openai:m+heuristic"},
		{config.LLM{Provider: config.ProviderGitHub, GitHub: config.GitHub{BaseURL: "http://x", Model: "openai/gpt-4.1", Token: "ghp"}}, false, "github:openai/gpt-4.1+heuristic"},
		{config.LLM{Provider: config.ProviderCopilot, Copilot: config.Copilot{Command: "copilot", Model: "gpt-5"}}, false, "copilot:gpt-5+heuristic"},
		{config.LLM{Provider: config.ProviderMCPTool, MCP: config.MCP{Transport: config.MCPTransportStdio, Tool: "t"}}, false, "mcptool:t+heuristic"},
		{config.LLM{Provider: config.ProviderMCPTool, MCP: config.MCP{Transport: config.MCPTransportHTTP, Tool: "t"}}, false, "mcptool:t+heuristic"},
		{config.LLM{Provider: config.ProviderMCPTool, MCP: config.MCP{Transport: "carrier-pigeon"}}, true, ""},
		{config.LLM{Provider: "nope"}, true, ""},
	}
	for _, c := range cases {
		p, err := NewProvider(c.cfg, log)
		if (err != nil) != c.wantErr {
			t.Fatalf("%+v: err=%v", c.cfg, err)
		}
		if err == nil && p.Name() != c.name {
			t.Errorf("name = %q want %q", p.Name(), c.name)
		}
	}
}

func TestNewFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Repo.CacheDir = t.TempDir()
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Cloner == nil || p.Evidence == nil || p.Provider == nil {
		t.Fatalf("pipeline not fully wired: %+v", p)
	}
	cfg.Repo.Clone = false
	p, _ = New(cfg, nil)
	if p.Cloner != nil {
		t.Fatal("cloner should be nil when clone disabled")
	}
}

func TestMaterializeRepoPrecedence(t *testing.T) {
	prod := source.Product{SBOMID: "sbom-1", DocumentName: "kubelb", SourceFile: "kubelb-1.4.2.spdx.json",
		RepoHints: []string{"https://github.com/hint/from-sbom"}}
	mk := func(cfgRepo config.Repo) (*Pipeline, *fakeCloner) {
		cl := &fakeCloner{dir: t.TempDir()}
		cfg := config.Default()
		cfg.Repo = cfgRepo
		cfg.Repo.Clone = true
		return &Pipeline{Cfg: cfg, Cloner: cl, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, cl
	}

	t.Run("config sboms beats sbom hints and derives ref", func(t *testing.T) {
		p, cl := mk(config.Repo{SBOMs: []config.SBOMRepo{{Match: "kubelb-*", Repo: "kubermatic/kubelb"}}})
		p.MaterializeRepo(context.Background(), prod, "")
		loc := cl.locs[0]
		if loc.URL != "https://github.com/kubermatic/kubelb" || loc.Ref != "v1.4.2" || loc.How != "config-sbom" {
			t.Fatalf("got %+v", loc)
		}
	})
	t.Run("version placeholder", func(t *testing.T) {
		p, cl := mk(config.Repo{SBOMs: []config.SBOMRepo{{Match: "sbom-1", Repo: "https://gitlab.com/a/b@release-{version}"}}})
		p.MaterializeRepo(context.Background(), prod, "")
		if cl.locs[0].Ref != "release-v1.4.2" {
			t.Fatalf("got %+v", cl.locs[0])
		}
	})
	t.Run("flag beats config", func(t *testing.T) {
		p, cl := mk(config.Repo{Override: "glob/al", SBOMs: []config.SBOMRepo{{Match: "*", Repo: "per/sbom"}}})
		p.MaterializeRepo(context.Background(), prod, "flag/wins@v9")
		if cl.locs[0].URL != "https://github.com/flag/wins" || cl.locs[0].How != "flag" {
			t.Fatalf("got %+v", cl.locs[0])
		}
	})
	t.Run("global override beats per-sbom", func(t *testing.T) {
		p, cl := mk(config.Repo{Override: "glob/al", SBOMs: []config.SBOMRepo{{Match: "*", Repo: "per/sbom"}}})
		p.MaterializeRepo(context.Background(), prod, "")
		if cl.locs[0].URL != "https://github.com/glob/al" || cl.locs[0].How != "config" {
			t.Fatalf("got %+v", cl.locs[0])
		}
	})
	t.Run("no match falls back to sbom hint", func(t *testing.T) {
		p, cl := mk(config.Repo{SBOMs: []config.SBOMRepo{{Match: "other-*", Repo: "x/y"}}})
		p.MaterializeRepo(context.Background(), prod, "")
		if cl.locs[0].URL != "https://github.com/hint/from-sbom" || cl.locs[0].How != "sbom" {
			t.Fatalf("got %+v", cl.locs[0])
		}
	})
	t.Run("bomhort source_repo beats sbom hints and carries source_ref", func(t *testing.T) {
		bp := prod
		bp.SourceRepo, bp.SourceRef = "https://github.com/kubermatic/kubelb", "abc1234"
		p, cl := mk(config.Repo{})
		p.MaterializeRepo(context.Background(), bp, "")
		loc := cl.locs[0]
		if loc.URL != "https://github.com/kubermatic/kubelb" || loc.Ref != "abc1234" || loc.How != "bomhort" {
			t.Fatalf("got %+v", loc)
		}
	})
	t.Run("config sboms beats bomhort source_repo", func(t *testing.T) {
		bp := prod
		bp.SourceRepo = "https://github.com/wrong/repo"
		p, cl := mk(config.Repo{SBOMs: []config.SBOMRepo{{Match: "kubelb-*", Repo: "kubermatic/kubelb"}}})
		p.MaterializeRepo(context.Background(), bp, "")
		if cl.locs[0].URL != "https://github.com/kubermatic/kubelb" || cl.locs[0].How != "config-sbom" {
			t.Fatalf("got %+v", cl.locs[0])
		}
	})
}

func TestRunReassessAfter(t *testing.T) {
	old := time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	fresh := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	mk := func() (*fakeBOMHort, *llm.Mock) {
		bh := bomhortFixture(t)
		bh.vulns = []bomhort.Vulnerability{
			{VulnID: "V-OLD-UI", PURL: "pkg:golang/a/b@v1", VEXStatus: "under_investigation"},
			{VulnID: "V-OLD-NA", PURL: "pkg:golang/a/c@v1", VEXStatus: "not_affected"},
			{VulnID: "V-FRESH-UI", PURL: "pkg:golang/a/d@v1", VEXStatus: "under_investigation"},
			{VulnID: "V-OLD-AFF", PURL: "pkg:golang/a/e@v1", VEXStatus: "affected"},
			{VulnID: "V-NOSTMT", PURL: "pkg:golang/a/f@v1", VEXStatus: "under_investigation"},
			{VulnID: "V-NEW", PURL: "pkg:golang/a/g@v1"},
		}
		bh.stmts = []bomhort.VEXStatement{
			{VulnID: "V-OLD-UI", ProductPURL: "pkg:golang/a/b@v1", Status: "under_investigation", VEXTimestamp: old},
			{VulnID: "V-OLD-UI", ProductPURL: "pkg:golang/a/b@v1", Status: "under_investigation", VEXTimestamp: "2020-01-01 00:00:00"},
			{VulnID: "V-OLD-NA", ProductPURL: "pkg:golang/a/c@v1", Status: "not_affected", VEXTimestamp: old},
			{VulnID: "V-FRESH-UI", ProductPURL: "pkg:golang/a/d@v1", Status: "under_investigation", VEXTimestamp: fresh},
			{VulnID: "V-OLD-AFF", ProductPURL: "pkg:golang/a/e@v1", Status: "affected", IngestedAt: old},
		}
		return bh, &llm.Mock{Default: &llm.Assessment{Status: vex.StatusUnderInvestigation, Confidence: 0.5}}
	}

	t.Run("disabled", func(t *testing.T) {
		bh, mock := mk()
		out, err := newTestPipeline(t, bh, mock, nil).Run(context.Background(), RunOptions{SBOMRef: "."})
		if err != nil {
			t.Fatal(err)
		}
		if out.Findings != 1 || out.Reassessed != 0 || out.Skipped != 5 {
			t.Fatalf("findings=%d reassessed=%d skipped=%d", out.Findings, out.Reassessed, out.Skipped)
		}
	})
	t.Run("7d ttl", func(t *testing.T) {
		bh, mock := mk()
		out, err := newTestPipeline(t, bh, mock, nil).Run(context.Background(), RunOptions{SBOMRef: ".", ReassessAfter: 7 * 24 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		// V-NEW + V-OLD-UI + V-OLD-AFF; not_affected, fresh and unknown-statement ones stay skipped.
		if out.Findings != 3 || out.Reassessed != 2 || out.Skipped != 3 {
			t.Fatalf("findings=%d reassessed=%d skipped=%d", out.Findings, out.Reassessed, out.Skipped)
		}
		got := map[string]bool{}
		for _, c := range mock.Calls {
			got[c.Report.Finding.VulnID] = true
		}
		if !got["V-NEW"] || !got["V-OLD-UI"] || !got["V-OLD-AFF"] || got["V-OLD-NA"] || got["V-FRESH-UI"] || got["V-NOSTMT"] {
			t.Fatalf("assessed = %v", got)
		}
	})
	t.Run("statement listing error keeps statuses", func(t *testing.T) {
		bh, mock := mk()
		bh.stmtErr = errors.New("boom")
		out, err := newTestPipeline(t, bh, mock, nil).Run(context.Background(), RunOptions{SBOMRef: ".", ReassessAfter: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if out.Findings != 1 || out.Reassessed != 0 {
			t.Fatalf("findings=%d reassessed=%d", out.Findings, out.Reassessed)
		}
	})
	t.Run("row vex_timestamp is used without listing statements", func(t *testing.T) {
		// BOMHort >= #335 puts the effective statement's timestamp on the
		// vulnerability row; /vex/statements must not be consulted.
		bh, mock := mk()
		bh.vulns = []bomhort.Vulnerability{
			{VulnID: "V-OLD-UI", PURL: "pkg:golang/a/b@v1", VEXStatus: "under_investigation", VEXTimestamp: old},
			{VulnID: "V-FRESH-UI", PURL: "pkg:golang/a/d@v1", VEXStatus: "under_investigation", VEXTimestamp: fresh},
			{VulnID: "V-OLD-NA", PURL: "pkg:golang/a/c@v1", VEXStatus: "not_affected", VEXTimestamp: old},
		}
		bh.stmts = nil
		bh.stmtErr = errors.New("must not be called")
		out, err := newTestPipeline(t, bh, mock, nil).Run(context.Background(), RunOptions{SBOMRef: ".", ReassessAfter: 7 * 24 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if out.Findings != 1 || out.Reassessed != 1 || out.Skipped != 2 {
			t.Fatalf("findings=%d reassessed=%d skipped=%d", out.Findings, out.Reassessed, out.Skipped)
		}
		if len(mock.Calls) != 1 || mock.Calls[0].Report.Finding.VulnID != "V-OLD-UI" {
			t.Fatalf("assessed = %+v", mock.Calls)
		}
	})
}

func TestFindGoBin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GOROOT", "")
	for _, v := range []string{"go1.24.1", "go1.25.10", "go1.9.0"} {
		dir := filepath.Join(home, "sdk", v, "bin")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "go"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Highest semver wins (not lexical: go1.9.0 < go1.25.10); GOROOT beats all.
	if got := findGoBin(); got != filepath.Join(home, "sdk", "go1.25.10", "bin") {
		t.Fatalf("findGoBin = %q", got)
	}
	root := filepath.Join(home, "root")
	os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	os.WriteFile(filepath.Join(root, "bin", "go"), []byte("#!/bin/sh\n"), 0o755)
	t.Setenv("GOROOT", root)
	if got := findGoBin(); got != filepath.Join(root, "bin") {
		t.Fatalf("GOROOT not preferred: %q", got)
	}
}

// TestRunRegenerateKeepsSettledVerdicts: --regenerate must not spend provider
// tokens on findings whose verdict is already final (not_affected, fixed).
func TestRunRegenerateKeepsSettledVerdicts(t *testing.T) {
	bh := bomhortFixture(t)
	bh.vulns = append(bh.vulns,
		bomhort.Vulnerability{VulnID: "GO-2025-0004", PURL: "pkg:golang/github.com/a/b@v1.0.0", Severity: "LOW", VEXStatus: "fixed"},
		bomhort.Vulnerability{VulnID: "GO-2025-0005", PURL: "pkg:golang/github.com/c/d@v1.0.0", Severity: "LOW", VEXStatus: "under_investigation"},
		bomhort.Vulnerability{VulnID: "GO-2025-0006", PURL: "pkg:golang/github.com/e/f@v1.0.0", Severity: "HIGH", VEXStatus: "affected"},
	)
	mock := &llm.Mock{Default: &llm.Assessment{Status: vex.StatusUnderInvestigation, Confidence: 0.5}}
	p := newTestPipeline(t, bh, mock, nil)

	// Default run: everything with a vex_status is skipped.
	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings != 2 || out.Skipped != 4 || out.Settled != 0 || len(mock.Calls) != 2 {
		t.Fatalf("default: findings=%d skipped=%d settled=%d calls=%d", out.Findings, out.Skipped, out.Settled, len(mock.Calls))
	}

	// Regenerate: under_investigation/affected are re-assessed, not_affected/fixed kept.
	mock.Calls = nil
	out, err = p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", Regenerate: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings != 4 || out.Skipped != 2 || out.Settled != 2 {
		t.Fatalf("regenerate: findings=%d skipped=%d settled=%d", out.Findings, out.Skipped, out.Settled)
	}
	for _, c := range mock.Calls {
		if c.Report.Finding.VulnID == "GO-2025-0003" || c.Report.Finding.VulnID == "GO-2025-0004" {
			t.Fatalf("settled finding %s was sent to the provider", c.Report.Finding.VulnID)
		}
	}

	// Force: hard regenerate touches everything.
	mock.Calls = nil
	out, err = p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", Regenerate: true, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings != 6 || out.Skipped != 0 || out.Settled != 0 || len(mock.Calls) != 6 {
		t.Fatalf("force: findings=%d skipped=%d settled=%d calls=%d", out.Findings, out.Skipped, out.Settled, len(mock.Calls))
	}

	// Force alone (without Regenerate) behaves the same.
	mock.Calls = nil
	out, err = p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings != 6 || len(mock.Calls) != 6 {
		t.Fatalf("force only: findings=%d calls=%d", out.Findings, len(mock.Calls))
	}
}

func TestProductName(t *testing.T) {
	cases := []struct {
		in   source.Product
		want string
	}{
		{source.Product{SBOMID: "id", DocumentName: "my-app", SourceFile: "f.json"}, "my-app"},
		{source.Product{SBOMID: "id", DocumentName: ".", SourceFile: "f.json"}, "f.json"},
		{source.Product{SBOMID: "id", SourceFile: "f.json"}, "f.json"},
		{source.Product{SBOMID: "id"}, "id"},
	}
	for _, c := range cases {
		if got := productName(c.in); got != c.want {
			t.Errorf("productName(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWait(t *testing.T) {
	p := &Pipeline{}
	calls := 0
	lister := func(context.Context) ([]bomhort.VEXStatement, error) {
		calls++
		if calls < 2 {
			return nil, errors.New("transient")
		}
		return []bomhort.VEXStatement{{DocumentID: "other"}, {DocumentID: "doc-1"}}, nil
	}
	// Found on the second poll (after one 2 s back-off).
	if err := p.Wait(context.Background(), "doc-1", 10*time.Second, lister); err != nil || calls != 2 {
		t.Fatalf("Wait: err=%v calls=%d", err, calls)
	}

	// Timeout: deadline already passed → single poll, then error.
	err := p.Wait(context.Background(), "missing", 0, func(context.Context) ([]bomhort.VEXStatement, error) { return nil, nil })
	if err == nil || !strings.Contains(err.Error(), "timeout waiting") {
		t.Fatalf("expected timeout, got %v", err)
	}

	// Context cancellation wins over the back-off sleep.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = p.Wait(ctx, "missing", time.Minute, func(context.Context) ([]bomhort.VEXStatement, error) { return nil, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestRunUsesAssessmentCache: the second SBOM of the same product (same
// repo commit, same evidence) must not call the provider again; --regenerate,
// --force and --no-cache bypass cache reads; usage is aggregated.
func TestRunUsesAssessmentCache(t *testing.T) {
	bh := bomhortFixture(t)
	mock := &llm.Mock{Default: &llm.Assessment{Status: vex.StatusAffected, ActionStatement: "upgrade", Confidence: 0.8, Reasoning: "r",
		Usage: llm.Usage{Calls: 1, PromptTokens: 1000, CompletionTokens: 50, Model: "m"}}}
	// A checkout with a detached HEAD so the cache key carries a commit.
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("deadbeef\n"), 0o644)
	cl := &fakeCloner{dir: dir}
	p := newTestPipeline(t, bh, mock, cl)
	p.Cache = assesscache.New(filepath.Join(t.TempDir(), "assessments"), 0)

	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 2 || out.Usage.Calls != 2 || out.Usage.PromptTokens != 2000 || out.Usage.CacheHits != 0 || out.Usage.Model != "m" {
		t.Fatalf("first run: calls=%d usage=%+v", len(mock.Calls), out.Usage)
	}
	for _, a := range out.Assessments {
		if a.Cached || a.Usage.Calls != 1 || a.Provider != "mock" {
			t.Fatalf("first run record = %+v", a)
		}
	}
	st, _ := p.Cache.Stats()
	if st.Entries != 2 {
		t.Fatalf("cache entries = %d", st.Entries)
	}

	// Same product again (e.g. the same SBOM in another cluster): all hits.
	mock.Calls = nil
	out, err = p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 0 || out.Usage.Calls != 0 || out.Usage.CacheHits != 2 || out.Usage.TotalTokens() != 0 {
		t.Fatalf("second run: calls=%d usage=%+v", len(mock.Calls), out.Usage)
	}
	for _, a := range out.Assessments {
		if !a.Cached || a.Status != vex.StatusAffected || a.Provider != "mock" {
			t.Fatalf("cached record = %+v", a)
		}
	}

	// Bypasses.
	for name, opts := range map[string]RunOptions{
		"no-cache":   {SBOMRef: "sbom-1", NoCache: true},
		"regenerate": {SBOMRef: "sbom-1", Regenerate: true},
		"force":      {SBOMRef: "sbom-1", Force: true},
	} {
		mock.Calls = nil
		out, err = p.Run(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		if len(mock.Calls) == 0 || out.Usage.CacheHits != 0 {
			t.Fatalf("%s must bypass cache reads: calls=%d usage=%+v", name, len(mock.Calls), out.Usage)
		}
	}

	// A different provider verdict is not served for the old key once the
	// commit changes.
	os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("cafebabe\n"), 0o644)
	mock.Calls = nil
	if _, err = p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"}); err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 2 {
		t.Fatalf("new commit must miss the cache, calls=%d", len(mock.Calls))
	}

	// Provider errors are not cached.
	failing := &llm.Mock{Err: errors.New("boom")}
	p2 := newTestPipeline(t, bh, failing, cl)
	p2.Cache = assesscache.New(filepath.Join(t.TempDir(), "assessments"), 0)
	if _, err := p2.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := p2.Cache.Stats(); st.Entries != 0 {
		t.Fatalf("errors must not be cached, entries=%d", st.Entries)
	}

	// Disabled cache (nil) is a no-op.
	p3 := newTestPipeline(t, bh, mock, cl)
	mock.Calls = nil
	if out, err := p3.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"}); err != nil || out.Usage.CacheHits != 0 || len(mock.Calls) != 2 {
		t.Fatalf("nil cache: %v calls=%d", err, len(mock.Calls))
	}
}

func TestRunDefersFindingsWhenBudgetExhausted(t *testing.T) {
	bh := bomhortFixture(t)
	mock := &llm.Mock{Default: &llm.Assessment{Status: vex.StatusAffected, ActionStatement: "upgrade", Confidence: 0.8, Reasoning: "r",
		Usage: llm.Usage{Calls: 1, PremiumRequests: 0.33}}}
	p := newTestPipeline(t, bh, mock, nil)
	p.Cache = assesscache.New(filepath.Join(t.TempDir(), "assessments"), 0)
	p.Budget = llm.NewBudget(llm.BudgetLimits{MaxCalls: 1})

	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", Upload: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 1 || out.Deferred != 1 || out.Usage.Calls != 1 {
		t.Fatalf("calls=%d deferred=%d usage=%+v", len(mock.Calls), out.Deferred, out.Usage)
	}
	if len(out.Assessments) != 1 {
		t.Fatalf("deferred finding must not get a statement: %+v", out.Assessments)
	}
	if !p.Budget.Exceeded() || p.Budget.Spent().PremiumRequests != 0.33 {
		t.Fatalf("budget = %+v", p.Budget.Spent())
	}
	if st, _ := p.Cache.Stats(); st.Entries != 1 {
		t.Fatalf("only the assessed finding may be cached, got %d", st.Entries)
	}

	// Fresh budget: the cached verdict is free, the deferred one is assessed.
	p.Budget.Reset()
	mock.Calls = nil
	out, err = p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Deferred != 0 || len(out.Assessments) != 2 || out.Usage.CacheHits != 1 || len(mock.Calls) != 1 {
		t.Fatalf("second run deferred=%d assessments=%d usage=%+v", out.Deferred, len(out.Assessments), out.Usage)
	}

	// Heuristic provider never spends, so a budget never defers it.
	h := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	h.Budget = llm.NewBudget(llm.BudgetLimits{MaxCalls: 1})
	out, err = h.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Deferred != 0 {
		t.Fatalf("heuristic deferred=%d", out.Deferred)
	}
}

func TestVerifyAndWaitApplied(t *testing.T) {
	bh := bomhortFixture(t)
	p := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	out := &Outcome{Product: source.Product{SBOMID: "sbom-1"}, Assessments: []AssessmentRecord{
		{VulnID: "GO-2025-0002", PURL: "pkg:golang/github.com/foo/bar@v1.2.3", Status: vex.StatusAffected},
		{VulnID: "GO-2025-0003", PURL: "pkg:golang/github.com/baz/qux@v2.0.0", Status: vex.StatusUnderInvestigation},
		{VulnID: "GO-2025-9999", PURL: "pkg:golang/example.com/missing@v1.0.0", Status: vex.StatusNotAffected},
	}}

	// Nothing of ours ingested yet: GO-2025-0003 already carries a human
	// not_affected in the fixture (overridden), the rest is pending.
	v, err := p.Verify(context.Background(), out)
	if err != nil {
		t.Fatal(err)
	}
	if v.Applied != 0 || len(v.Pending) != 2 || len(v.Overridden) != 1 || v.Complete() {
		t.Fatalf("before ingest: %+v", v)
	}

	// BOMHort applied one; the third never matched.
	for i := range bh.vulns {
		if bh.vulns[i].VulnID == "GO-2025-0002" {
			bh.vulns[i].VEXStatus = "affected"
		}
	}
	// Duplicate row without status must not hide the applied one.
	bh.vulns = append(bh.vulns, bomhort.Vulnerability{VulnID: "GO-2025-0002", PURL: "pkg:golang/github.com/foo/bar@v1.2.3"})
	v, err = p.WaitApplied(context.Background(), out, 0)
	if err == nil || !strings.Contains(err.Error(), "1 of 3 statements not applied") {
		t.Fatalf("WaitApplied err = %v", err)
	}
	if v.Applied != 1 || len(v.Overridden) != 1 || v.Overridden[0].Actual != "not_affected" || len(v.Pending) != 1 || v.Pending[0].VulnID != "GO-2025-9999" {
		t.Fatalf("after ingest: %+v", v)
	}

	// All matched → complete without error.
	out.Assessments = out.Assessments[:2]
	v, err = p.WaitApplied(context.Background(), out, time.Second)
	if err != nil || !v.Complete() || v.Applied != 1 {
		t.Fatalf("complete: %+v err=%v", v, err)
	}

	// Cancelled context aborts the poll loop.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out.Assessments = append(out.Assessments, AssessmentRecord{VulnID: "X", PURL: "pkg:golang/x@v1", Status: vex.StatusAffected})
	if _, err := p.WaitApplied(ctx, out, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

type fakePublisher struct {
	docs []gitops.Document
	res  *gitops.Result
	err  error
}

func (f *fakePublisher) Publish(_ context.Context, d gitops.Document) (*gitops.Result, error) {
	f.docs = append(f.docs, d)
	return f.res, f.err
}

func TestRunPublishesToGit(t *testing.T) {
	bh := bomhortFixture(t)
	mock := &llm.Mock{ByVulnID: map[string]llm.Assessment{
		"GO-2025-0001": {Status: vex.StatusAffected, ActionStatement: "upgrade", Confidence: 0.9, Reasoning: "r"},
	}}
	p := newTestPipeline(t, bh, mock, nil)
	pub := &fakePublisher{res: &gitops.Result{Branch: "vexviper/bomhort", Commit: "abc", Path: "vex/x.json", PRURL: "https://gh/pr/1", PRNumber: 1}}
	p.Publisher = pub

	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", Publish: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(pub.docs) != 1 {
		t.Fatalf("publisher called %d times", len(pub.docs))
	}
	d := pub.docs[0]
	if d.Filename != out.Filename || string(d.Content) != string(out.Document) || d.Product == "" {
		t.Fatalf("doc = %+v", d)
	}
	if !strings.Contains(d.Summary, "2 finding(s)") || !strings.Contains(d.Summary, "affected") {
		t.Fatalf("summary = %q", d.Summary)
	}
	if out.Published == nil || out.Published.PRURL != "https://gh/pr/1" {
		t.Fatalf("Published = %+v", out.Published)
	}
	if len(bh.uploads) != 0 {
		t.Fatal("publish must not upload")
	}
}

func TestRunPublishErrors(t *testing.T) {
	bh := bomhortFixture(t)
	p := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	if _, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", Publish: true}); err == nil || !strings.Contains(err.Error(), "vex.git") {
		t.Fatalf("expected configuration error, got %v", err)
	}
	pub := &fakePublisher{res: &gitops.Result{Branch: "b", Commit: "c"}, err: errors.New("HTTP 403")}
	p.Publisher = pub
	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", Publish: true})
	if err == nil || !strings.Contains(err.Error(), "publish: HTTP 403") {
		t.Fatalf("err = %v", err)
	}
	if out == nil || out.Published == nil || out.Published.Commit != "c" || len(out.Document) == 0 {
		t.Fatalf("outcome must carry the partial result: %+v", out)
	}
}

func TestOutcomeSummary(t *testing.T) {
	o := &Outcome{Findings: 5, Counts: map[vex.Status]int{vex.StatusNotAffected: 2, vex.StatusUnderInvestigation: 1}, Assessments: make([]AssessmentRecord, 3), Guardrails: make([]vexgen.Guardrail, 1), Deferred: 2}
	got := o.Summary()
	want := "5 finding(s), 3 statement(s): 2× not_affected, 1× under_investigation; 1 guardrail(s) applied; 2 deferred (budget)"
	if got != want {
		t.Fatalf("Summary = %q\nwant      %q", got, want)
	}
	if got := (&Outcome{}).Summary(); got != "0 finding(s), 0 statement(s)" {
		t.Fatalf("empty = %q", got)
	}
}
