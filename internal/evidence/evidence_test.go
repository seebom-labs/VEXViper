package evidence

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mfahlandt/vexviper/internal/osv"
	"github.com/mfahlandt/vexviper/internal/source"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v0.17.0", "v0.23.0", -1, true},
		{"0.23.0", "v0.23.0", 0, true},
		{"v1.2.3", "1.2.2", 1, true},
		{"v0.0.0-20230101000000-abcdef123456", "v0.1.0", -1, true},
		{"22.0.6", "22.0.5", 1, true},
		{"latest", "v1.0.0", 0, false},
		{"", "v1", 0, false},
	}
	for _, tc := range cases {
		got, ok := CompareVersions(tc.a, tc.b)
		if ok != tc.ok || got != tc.want {
			t.Errorf("CompareVersions(%q,%q) = %d,%v want %d,%v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

func TestVersionEvidence(t *testing.T) {
	fixed := versionEvidence(source.Finding{PURL: "pkg:golang/x/y@v1.5.0", FixedVersion: "v1.4.0"})
	if len(fixed) != 1 || fixed[0].Kind != KindVersionFixed || !fixed[0].Strong {
		t.Fatalf("fixed = %+v", fixed)
	}
	vuln := versionEvidence(source.Finding{PURL: "pkg:golang/x/y@v1.3.0", FixedVersion: "v1.4.0"})
	if len(vuln) != 1 || vuln[0].Kind != KindVersionVulnerable || vuln[0].Strong {
		t.Fatalf("vuln = %+v", vuln)
	}
	if got := versionEvidence(source.Finding{PURL: "pkg:golang/x/y", PackageVersion: "v2.0.0", FixedVersion: "v1.0.0"}); len(got) != 1 || got[0].Kind != KindVersionFixed {
		t.Fatalf("fallback to PackageVersion failed: %+v", got)
	}
	if got := versionEvidence(source.Finding{PURL: "pkg:golang/x/y@v1", FixedVersion: ""}); got != nil {
		t.Fatalf("no fixed version → nil, got %+v", got)
	}
	if got := versionEvidence(source.Finding{PURL: "pkg:npm/x@latest", FixedVersion: "1.0.0"}); got != nil {
		t.Fatalf("non semver → nil, got %+v", got)
	}
}

func loadGVC(t *testing.T) *GovulncheckResult {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "govulncheck.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := ParseGovulncheck(f)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestParseGovulncheck(t *testing.T) {
	res := loadGVC(t)
	if res.ScanLevel != "symbol" {
		t.Errorf("scan level = %q", res.ScanLevel)
	}
	if res.Modules["github.com/ClickHouse/clickhouse-go/v2"] != "v2.48.0" {
		t.Errorf("modules = %v", res.Modules["github.com/ClickHouse/clickhouse-go/v2"])
	}
	if len(res.Findings["GO-2026-6090"]) == 0 {
		t.Error("no findings for GO-2026-6090")
	}
	if res.OSVAliases["CVE-2023-39325"] != "GO-2023-2102" {
		t.Errorf("alias map = %v", res.OSVAliases["CVE-2023-39325"])
	}
}

func TestGovulncheckEvidenceFor(t *testing.T) {
	res := loadGVC(t)

	reach := res.EvidenceFor("GO-2026-6090", nil)
	if len(reach) != 1 || reach[0].Kind != KindReachable || !reach[0].Strong {
		t.Fatalf("reachable = %+v", reach)
	}
	if paths, _ := reach[0].Details["call_paths"].([]string); len(paths) == 0 {
		t.Fatalf("expected call paths, got %+v", reach[0].Details)
	}

	// module-only trace at symbol scan level → not reachable, strong
	notReach := res.EvidenceFor("GHSA-4374-p667-p6c8", nil)
	if len(notReach) != 1 || notReach[0].Kind != KindNotReachable || !notReach[0].Strong {
		t.Fatalf("not reachable = %+v", notReach)
	}

	// alias resolution via the OSV record
	viaOSV := res.EvidenceFor("SOME-OTHER-ID", &osv.Vulnerability{ID: "X", Aliases: []string{"CVE-2023-39325"}})
	if viaOSV[0].Kind != KindNotReachable {
		t.Fatalf("alias via osv failed: %+v", viaOSV)
	}

	none := res.EvidenceFor("GO-1999-0001", nil)
	if len(none) != 1 || none[0].Kind != KindNotImported || none[0].Strong {
		t.Fatalf("unknown = %+v", none)
	}

	res.ScanLevel = "module"
	weak := res.EvidenceFor("GO-2023-2102", nil)
	if weak[0].Kind != KindNotReachable || weak[0].Strong {
		t.Fatalf("module-level should be weak: %+v", weak)
	}
}

func TestParseGovulncheckBadJSON(t *testing.T) {
	if _, err := ParseGovulncheck(strings.NewReader(`{"config":{}}` + "\n{not json")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestIsGoModule(t *testing.T) {
	dir := t.TempDir()
	if _, ok := IsGoModule(dir); ok {
		t.Fatal("empty dir is not a module")
	}
	sub := filepath.Join(dir, "backend")
	_ = os.MkdirAll(sub, 0o755)
	_ = os.WriteFile(filepath.Join(sub, "go.mod"), []byte("module x\n"), 0o644)
	if got, ok := IsGoModule(dir); !ok || got != sub {
		t.Fatalf("single nested module → %q %v", got, ok)
	}
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module y\n"), 0o644)
	if got, ok := IsGoModule(dir); !ok || got != dir {
		t.Fatalf("top-level module → %q %v", got, ok)
	}
}

func TestFindGoModules(t *testing.T) {
	dir := t.TempDir()
	mk := func(rel string) {
		p := filepath.Join(dir, rel)
		_ = os.MkdirAll(p, 0o755)
		_ = os.WriteFile(filepath.Join(p, "go.mod"), []byte("module m\n"), 0o644)
	}
	mk("backend")
	mk("docs")
	mk("tools/gen")
	mk("vendor/x")      // skipped
	mk(".hidden/y")     // skipped
	mk("a/b/c")         // too deep
	mk("backend/inner") // not descended: backend already is a module
	got := FindGoModules(dir)
	want := []string{filepath.Join(dir, "backend"), filepath.Join(dir, "docs"), filepath.Join(dir, "tools", "gen")}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestRunGovulncheckMultiModule(t *testing.T) {
	dir := t.TempDir()
	for _, m := range []string{"backend", "docs"} {
		_ = os.MkdirAll(filepath.Join(dir, m), 0o755)
		_ = os.WriteFile(filepath.Join(dir, m, "go.mod"), []byte("module x\n"), 0o644)
	}
	fixture, _ := os.ReadFile(filepath.Join("testdata", "govulncheck.json"))
	var dirs []string
	c := &Collector{Govulncheck: "govulncheck", runGovulncheck: func(_ context.Context, d string) ([]byte, error) {
		dirs = append(dirs, filepath.Base(d))
		if filepath.Base(d) == "docs" {
			return nil, errors.New("loading packages: no Go files")
		}
		return fixture, nil
	}}
	res, err := c.RunGovulncheck(context.Background(), dir)
	if err != nil || res == nil {
		t.Fatalf("one failing module must not fail the run: %v", err)
	}
	if len(dirs) != 2 || res.ScanLevel != "symbol" || len(res.Findings) == 0 {
		t.Fatalf("dirs=%v res=%+v", dirs, res)
	}
	c.runGovulncheck = func(context.Context, string) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := c.RunGovulncheck(context.Background(), dir); err == nil {
		t.Fatal("all modules failing must error")
	}
}

func TestRunGovulncheckStubbed(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644)
	fixture, _ := os.ReadFile(filepath.Join("testdata", "govulncheck.json"))

	c := &Collector{Govulncheck: "govulncheck", runGovulncheck: func(context.Context, string) ([]byte, error) { return fixture, nil }}
	res, err := c.RunGovulncheck(context.Background(), dir)
	if err != nil || res == nil || res.ScanLevel != "symbol" {
		t.Fatalf("stubbed run: %+v %v", res, err)
	}

	// a runner error (package load failure etc.) is fatal even with partial output
	c.runGovulncheck = func(context.Context, string) ([]byte, error) { return fixture, errors.New("loading packages") }
	if _, err := c.RunGovulncheck(context.Background(), dir); err == nil {
		t.Fatal("runner error must surface")
	}

	c.runGovulncheck = func(context.Context, string) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := c.RunGovulncheck(context.Background(), dir); err == nil {
		t.Fatal("expected error without output")
	}

	if res, err := (&Collector{}).RunGovulncheck(context.Background(), dir); res != nil || err != nil {
		t.Fatalf("disabled should return nil,nil: %v %v", res, err)
	}
	if res, err := c.RunGovulncheck(context.Background(), t.TempDir()); res != nil || err != nil {
		t.Fatalf("non-module should return nil,nil: %v %v", res, err)
	}
}

func TestSymbolEvidence(t *testing.T) {
	repo := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(repo, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(content), 0o644)
	}
	write("cmd/main.go", "package main\nimport \"net/http\"\nfunc main(){ http.ListenAndServe(\":80\", nil) }\n")
	write("cmd/main_test.go", "package main\nimport \"net/http\"\nfunc TestX(){ http.ServeTLS(nil,nil,\"\",\"\") }\n")
	write("vendor/x.go", "package x\nimport \"net/http\"\nvar _ = http.ServeTLS\n")

	v := &osv.Vulnerability{Affected: []osv.Affected{{EcosystemSpecific: osv.EcoSpecific{Imports: []osv.Import{{Path: "net/http", Symbols: []string{"ListenAndServe", "Server.ServeTLS", "http2serverConn.serve"}}}}}}}
	c := &Collector{}
	items := c.symbolEvidence(repo, v)
	if len(items) != 1 || items[0].Kind != KindSymbolReferenced {
		t.Fatalf("items = %+v", items)
	}
	files := items[0].Details["files"].(map[string][]string)
	if got := files["ListenAndServe"]; len(got) != 1 || got[0] != filepath.Join("cmd", "main.go") {
		t.Errorf("ListenAndServe files = %v", got)
	}
	if _, ok := files["ServeTLS"]; ok {
		t.Error("ServeTLS only in test/vendor files must be ignored")
	}

	// imported but no symbol
	write("cmd/main.go", "package main\nimport \"net/http\"\nvar _ = http.StatusOK\n")
	items = c.symbolEvidence(repo, v)
	if len(items) != 1 || items[0].Kind != KindSymbolNotReferenced {
		t.Fatalf("items = %+v", items)
	}

	// not imported at all
	write("cmd/main.go", "package main\nfunc main(){}\n")
	items = c.symbolEvidence(repo, v)
	if len(items) != 1 || items[0].Kind != KindImportNotFound {
		t.Fatalf("items = %+v", items)
	}

	if got := c.symbolEvidence(repo, &osv.Vulnerability{}); got != nil {
		t.Fatalf("no imports → nil, got %+v", got)
	}
}

func TestCollectEndToEnd(t *testing.T) {
	osvData, _ := os.ReadFile(filepath.Join("..", "osv", "testdata", "GO-2023-2102.json"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/vulns/GO-2023-2102" {
			_, _ = w.Write(osvData)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	repo := t.TempDir()
	_ = os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module x\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\nimport \"net/http\"\nfunc main(){ http.ListenAndServe(\"\", nil) }\n"), 0o644)

	c := &Collector{OSV: osv.New(srv.URL, nil)}
	gvc := loadGVC(t)
	f := source.Finding{VulnID: "GO-2023-2102", PURL: "pkg:golang/golang.org/x/net@v0.16.0", FixedVersion: "v0.17.0", DirectKnown: true, Direct: false, PackageName: "golang.org/x/net"}
	rep := c.Collect(context.Background(), f, repo, gvc)

	for _, k := range []Kind{KindVersionVulnerable, KindTransitive, KindOSVDetails, KindNotReachable, KindSymbolReferenced} {
		if !rep.Has(k) {
			t.Errorf("missing evidence %s in %+v", k, rep.Items)
		}
	}
	if rep.OSV == nil || rep.OSV.CVE() != "CVE-2023-39325" {
		t.Errorf("osv not attached")
	}
	if len(rep.StrongItems()) != 1 {
		t.Errorf("strong items = %+v", rep.StrongItems())
	}

	// no repo → repo_unavailable, no code analysis
	rep2 := c.Collect(context.Background(), source.Finding{VulnID: "UNKNOWN-1", PURL: "pkg:npm/a@1.0.0", FixedVersion: "0.9.0"}, "", nil)
	if !rep2.Has(KindRepoUnavailable) || !rep2.Has(KindVersionFixed) || rep2.OSV != nil {
		t.Errorf("rep2 = %+v", rep2.Items)
	}
}

func TestRunToolExitCodes(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	c := &Collector{}
	// exit 3 = vulnerabilities found → not an error
	out, err := c.runTool(context.Background(), t.TempDir(), "sh", "-c", "echo '{\"config\":{}}'; exit 3")
	if err != nil || !strings.Contains(string(out), "config") {
		t.Fatalf("exit 3: out=%s err=%v", out, err)
	}
	// exit 1 with stderr → error containing stderr
	_, err = c.runTool(context.Background(), t.TempDir(), "sh", "-c", "echo 'file requires newer Go version go1.26 (application built with go1.25)' >&2; exit 1")
	if err == nil || !needsNewerToolchain(err) {
		t.Fatalf("exit 1: err=%v", err)
	}
	if needsNewerToolchain(errors.New("boom")) {
		t.Fatal("unrelated error must not trigger fallback")
	}
}

func TestCollectNonGoSkipsGovulncheck(t *testing.T) {
	c := &Collector{}
	gvc := loadGVC(t)
	f := source.Finding{VulnID: "GHSA-hh8m-fm6v-7cvg", PURL: "pkg:npm/%40angular/core@22.0.8", FixedVersion: "22.0.9", DirectKnown: true, Direct: true}
	rep := c.Collect(context.Background(), f, t.TempDir(), gvc)
	if rep.Has(KindNotImported) || rep.Has(KindNotReachable) || rep.Has(KindReachable) {
		t.Fatalf("govulncheck evidence leaked into npm finding: %+v", rep.Items)
	}
	if !rep.Has(KindNoReachabilityTool) || !rep.Has(KindVersionVulnerable) || !rep.Has(KindDirectDependency) {
		t.Fatalf("expected no_reachability_analysis + version + depth evidence, got %+v", rep.Items)
	}
	if ecosystem("pkg:npm/x@1") != "npm" || ecosystem("garbage") != "this ecosystem" {
		t.Fatal("ecosystem()")
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("first\nsecond"); got != "first" {
		t.Fatalf("firstLine = %q", got)
	}
	long := strings.Repeat("x", 250)
	if got := firstLine(long); len([]rune(got)) != 201 || !strings.HasSuffix(got, "…") {
		t.Fatalf("long line not truncated: %d", len(got))
	}
	if got := firstLine("short"); got != "short" {
		t.Fatalf("firstLine = %q", got)
	}
}

// TestExecGovulncheckFallback: when the installed govulncheck was built with
// an older Go than the module requires, Collector must retry via `go run`
// (using GoBin when set).
func TestExecGovulncheckFallback(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	bin := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("govulncheck", `echo 'govulncheck: loading packages: application built with go1.25 requires newer Go version go1.26' >&2; exit 1`)
	write("go", `echo "$@" > "$0.args"; echo '{"config":{"scanner_name":"fallback"}}'; exit 0`)

	c := &Collector{Govulncheck: filepath.Join(bin, "govulncheck"), GoBin: bin}
	out, err := c.execGovulncheck(context.Background(), t.TempDir())
	if err != nil || !strings.Contains(string(out), "fallback") {
		t.Fatalf("fallback: out=%s err=%v", out, err)
	}
	args, _ := os.ReadFile(filepath.Join(bin, "go.args"))
	if !strings.Contains(string(args), "run "+GovulncheckModule+" -json ./...") {
		t.Fatalf("go run args = %q", args)
	}

	// Fallback failing too must surface both errors.
	write("go", `echo 'go: download failed' >&2; exit 1`)
	if _, err := c.execGovulncheck(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "fallback via go run also failed") {
		t.Fatalf("expected combined error, got %v", err)
	}

	// Unrelated failures are not retried.
	write("govulncheck", `echo 'boom' >&2; exit 2`)
	write("go", `echo 'must not run' >&2; exit 1`)
	if _, err := c.execGovulncheck(context.Background(), t.TempDir()); err == nil || strings.Contains(err.Error(), "fallback") {
		t.Fatalf("unexpected fallback: %v", err)
	}
}
