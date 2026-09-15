// Package evidence gathers deterministic facts about a finding that both
// the heuristic provider and the LLM prompt build on: version status,
// dependency depth, govulncheck reachability and vulnerable-symbol usage in
// the product repository.
package evidence

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/seebom-labs/vexviper/internal/osv"
	"github.com/seebom-labs/vexviper/internal/source"
)

// Kind classifies a piece of evidence.
type Kind string

// Evidence kinds.
const (
	KindVersionFixed        Kind = "version_fixed"      // installed version >= fixed
	KindVersionVulnerable   Kind = "version_vulnerable" // installed version < fixed
	KindDirectDependency    Kind = "direct_dependency"
	KindTransitive          Kind = "transitive_dependency"
	KindReachable           Kind = "govulncheck_reachable"     // symbol-level call path found
	KindNotReachable        Kind = "govulncheck_not_reachable" // module used, no call path
	KindNotImported         Kind = "govulncheck_not_imported"
	KindSymbolReferenced    Kind = "symbol_referenced" // vulnerable symbol name appears in product code
	KindSymbolNotReferenced Kind = "symbol_not_referenced"
	KindImportNotFound      Kind = "import_not_found" // vulnerable package path not imported anywhere
	KindOSVDetails          Kind = "osv_details"
	KindRepoUnavailable     Kind = "repo_unavailable"
	KindNoReachabilityTool  Kind = "no_reachability_analysis" // non-Go ecosystem: nothing like govulncheck ran
)

// Item is one fact with a short human/LLM readable description.
type Item struct {
	Kind    Kind   `json:"kind"`
	Summary string `json:"summary"`
	// Strong marks evidence that alone justifies a status (fixed, not reachable).
	Strong bool `json:"strong"`
	// Details carries optional structured data (paths, versions...).
	Details map[string]any `json:"details,omitempty"`
}

// Report is the evidence bundle for one finding.
type Report struct {
	Finding source.Finding     `json:"finding"`
	OSV     *osv.Vulnerability `json:"osv,omitempty"`
	Items   []Item             `json:"items"`
	// ProductRepo is the checkout path evidence was gathered from ("" if none).
	ProductRepo string `json:"product_repo,omitempty"`
}

// Has reports whether an item of kind k is present.
func (r *Report) Has(k Kind) bool {
	for _, it := range r.Items {
		if it.Kind == k {
			return true
		}
	}
	return false
}

// StrongItems returns the items marked Strong.
func (r *Report) StrongItems() []Item {
	var out []Item
	for _, it := range r.Items {
		if it.Strong {
			out = append(out, it)
		}
	}
	return out
}

// Collector produces Reports.
type Collector struct {
	OSV *osv.Client
	// Govulncheck is the binary to run for Go products ("" disables).
	Govulncheck string
	// GoBin is the Go toolchain govulncheck should use ("" = PATH).
	GoBin string
	// Timeout bounds one govulncheck run.
	Timeout time.Duration
	// MaxGrepFiles bounds the symbol grep (default 5000).
	MaxGrepFiles int

	// runGovulncheck is swapped in tests.
	runGovulncheck func(ctx context.Context, dir string) ([]byte, error)
}

// Collect builds a report for f. repoDir may be "" when the product
// repository could not be materialized; gvc is a cached govulncheck result
// for repoDir (nil to run it lazily via RunGovulncheck).
func (c *Collector) Collect(ctx context.Context, f source.Finding, repoDir string, gvc *GovulncheckResult) *Report {
	r := &Report{Finding: f, ProductRepo: repoDir}

	// 1. version vs fixed
	r.Items = append(r.Items, versionEvidence(f)...)

	// 2. dependency depth
	if f.DirectKnown {
		if f.Direct {
			r.Items = append(r.Items, Item{Kind: KindDirectDependency, Summary: fmt.Sprintf("%s is a direct dependency of the product", pkgName(f))})
		} else {
			r.Items = append(r.Items, Item{Kind: KindTransitive, Summary: fmt.Sprintf("%s is a transitive dependency of the product", pkgName(f))})
		}
	}

	// 3. OSV details
	if c.OSV != nil {
		if v, err := c.OSV.Get(ctx, f.VulnID); err != nil {
			slog.Debug("evidence: osv lookup failed", "vuln", f.VulnID, "err", err)
		} else {
			r.OSV = v
			r.Items = append(r.Items, osvEvidence(v, f)...)
		}
	}

	if repoDir == "" {
		r.Items = append(r.Items, Item{Kind: KindRepoUnavailable, Summary: "product source repository not available; no code-level analysis performed"})
		return r
	}

	// 4. govulncheck reachability (Go only). Attaching Go results to npm/pypi
	// findings misleads models into "govulncheck did not report it" verdicts.
	isGo := strings.HasPrefix(f.PURL, "pkg:golang/")
	switch {
	case gvc != nil && isGo:
		r.Items = append(r.Items, gvc.EvidenceFor(f.VulnID, r.OSV)...)
	case !isGo:
		r.Items = append(r.Items, Item{Kind: KindNoReachabilityTool, Summary: fmt.Sprintf("no reachability analysis available for %s; only version and dependency evidence applies", ecosystem(f.PURL))})
	}

	// 5. vulnerable symbol grep
	if r.OSV != nil && strings.HasPrefix(f.PURL, "pkg:golang/") {
		r.Items = append(r.Items, c.symbolEvidence(repoDir, r.OSV)...)
	}
	return r
}

func pkgName(f source.Finding) string {
	if f.PackageName != "" {
		return f.PackageName
	}
	return f.PURL
}

// ---- version ----

func versionEvidence(f source.Finding) []Item {
	installed := versionFromPURL(f.PURL)
	if installed == "" {
		installed = f.PackageVersion
	}
	if installed == "" || f.FixedVersion == "" {
		return nil
	}
	cmp, ok := CompareVersions(installed, f.FixedVersion)
	if !ok {
		return nil
	}
	if cmp >= 0 {
		return []Item{{Kind: KindVersionFixed, Strong: true, Summary: fmt.Sprintf("installed version %s is >= fixed version %s", installed, f.FixedVersion), Details: map[string]any{"installed": installed, "fixed": f.FixedVersion}}}
	}
	return []Item{{Kind: KindVersionVulnerable, Summary: fmt.Sprintf("installed version %s is below fixed version %s", installed, f.FixedVersion), Details: map[string]any{"installed": installed, "fixed": f.FixedVersion}}}
}

func versionFromPURL(purl string) string {
	i := strings.LastIndex(purl, "@")
	if i < 0 {
		return ""
	}
	v := purl[i+1:]
	for _, sep := range []string{"?", "#"} {
		if j := strings.Index(v, sep); j >= 0 {
			v = v[:j]
		}
	}
	return v
}

// CompareVersions compares two versions semver-style (tolerating a missing
// "v" prefix). ok is false when either is not semver.
func CompareVersions(a, b string) (int, bool) {
	na, nb := normalize(a), normalize(b)
	if !semver.IsValid(na) || !semver.IsValid(nb) {
		return 0, false
	}
	return semver.Compare(na, nb), true
}

func normalize(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && v[0] != 'v' {
		v = "v" + v
	}
	// "v1.2" → "v1.2.0" is accepted by semver.IsValid? No: it requires MAJOR.MINOR.PATCH only for canonical; IsValid accepts v1.2.
	return v
}

// ---- OSV ----

func osvEvidence(v *osv.Vulnerability, f source.Finding) []Item {
	summary := v.Summary
	if summary == "" {
		summary = firstLine(v.Details)
	}
	det := map[string]any{"aliases": v.Aliases}
	if cve := v.CVE(); cve != "" {
		det["cve"] = cve
	}
	if fixes := v.ReferenceURLs("FIX"); len(fixes) > 0 {
		det["fix_references"] = fixes
	}
	imports := v.VulnerableImports()
	if len(imports) > 0 {
		paths := make([]string, 0, len(imports))
		for _, im := range imports {
			paths = append(paths, im.Path)
		}
		det["vulnerable_packages"] = paths
	}
	return []Item{{Kind: KindOSVDetails, Summary: fmt.Sprintf("%s: %s", v.ID, summary), Details: det}}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// ---- govulncheck ----

// GovulncheckResult is the parsed JSON stream of one govulncheck run.
type GovulncheckResult struct {
	// Findings by OSV id; each entry is the list of traces.
	Findings map[string][]gvcTrace
	// Modules seen in the build list (path → version).
	Modules map[string]string
	// OSVAliases maps every alias to the GO- id reported.
	OSVAliases map[string]string
	ScanLevel  string
	// ModuleDirs lists the module directories that were scanned.
	ModuleDirs []string
}

type gvcTrace []struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
	} `json:"position"`
}

// IsGoModule reports whether dir contains a go.mod at top level or exactly
// one go.mod one level below, returning that module directory.
func IsGoModule(dir string) (string, bool) {
	mods := FindGoModules(dir)
	if len(mods) == 1 {
		return mods[0], true
	}
	if len(mods) > 1 && mods[0] == dir {
		return dir, true
	}
	return "", false
}

// FindGoModules lists directories containing a go.mod at dir, one and two
// levels below (skipping hidden dirs, vendor and testdata). Monorepos such as
// BOMHort keep the service in backend/ next to unrelated modules (docs/).
func FindGoModules(dir string) []string {
	var found []string
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		found = append(found, dir)
	}
	skip := func(name string) bool {
		return strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" || name == "node_modules"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return found
	}
	for _, e := range entries {
		if !e.IsDir() || skip(e.Name()) {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		if _, err := os.Stat(filepath.Join(sub, "go.mod")); err == nil {
			found = append(found, sub)
			continue
		}
		subEntries, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		for _, se := range subEntries {
			if se.IsDir() && !skip(se.Name()) {
				if _, err := os.Stat(filepath.Join(sub, se.Name(), "go.mod")); err == nil {
					found = append(found, filepath.Join(sub, se.Name()))
				}
			}
		}
	}
	sort.Strings(found)
	return found
}

// RunGovulncheck runs govulncheck -json ./... in every Go module found under
// dir and merges the results. It returns (nil, nil) when govulncheck is
// disabled or dir contains no Go module. A module that fails to load is
// logged and skipped; the error is returned only if every module failed.
func (c *Collector) RunGovulncheck(ctx context.Context, dir string) (*GovulncheckResult, error) {
	if c.Govulncheck == "" {
		return nil, nil
	}
	mods := FindGoModules(dir)
	if len(mods) == 0 {
		return nil, nil
	}
	run := c.runGovulncheck
	if run == nil {
		run = c.execGovulncheck
	}
	merged := &GovulncheckResult{Findings: map[string][]gvcTrace{}, Modules: map[string]string{}, OSVAliases: map[string]string{}}
	var errs []error
	ok := 0
	for _, m := range mods {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out, err := run(ctx, m)
		if err != nil {
			slog.Warn("evidence: govulncheck failed for module", "dir", m, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", m, err))
			continue
		}
		res, err := ParseGovulncheck(bytes.NewReader(out))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m, err))
			continue
		}
		ok++
		merged.merge(res)
	}
	if ok == 0 {
		return nil, fmt.Errorf("evidence: govulncheck: %w", errors.Join(errs...))
	}
	return merged, nil
}

func (g *GovulncheckResult) merge(o *GovulncheckResult) {
	for k, v := range o.Findings {
		g.Findings[k] = append(g.Findings[k], v...)
	}
	for k, v := range o.Modules {
		g.Modules[k] = v
	}
	for k, v := range o.OSVAliases {
		g.OSVAliases[k] = v
	}
	if g.ScanLevel == "" || o.ScanLevel == "symbol" {
		g.ScanLevel = o.ScanLevel
	}
	g.ModuleDirs = append(g.ModuleDirs, o.ModuleDirs...)
}

// GovulncheckModule is the module path used for the `go run` fallback.
const GovulncheckModule = "golang.org/x/vuln/cmd/govulncheck@latest"

// execGovulncheck runs the configured binary. govulncheck exits 3 when it
// finds vulnerabilities, 0 when it finds none and 1/2 on errors. When the
// installed binary was built with an older Go than the module requires, it
// cannot load the packages; in that case fall back to `go run` so the
// module's own toolchain (GOTOOLCHAIN=auto) builds a matching govulncheck.
func (c *Collector) execGovulncheck(ctx context.Context, dir string) ([]byte, error) {
	out, err := c.runTool(ctx, dir, c.Govulncheck, "-json", "./...")
	if err != nil && needsNewerToolchain(err) {
		goBin := "go"
		if c.GoBin != "" {
			goBin = filepath.Join(c.GoBin, "go")
		}
		slog.Info("evidence: installed govulncheck is too old for this module; retrying via go run", "module", GovulncheckModule)
		out2, err2 := c.runTool(ctx, dir, goBin, "run", GovulncheckModule, "-json", "./...")
		if err2 == nil {
			return out2, nil
		}
		return out, fmt.Errorf("%w (fallback via go run also failed: %v)", err, err2)
	}
	return out, err
}

func (c *Collector) runTool(ctx context.Context, dir, bin string, args ...string) ([]byte, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	env := os.Environ()
	if c.GoBin != "" {
		env = append(env, "PATH="+c.GoBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	// Let go download the toolchain the module asks for instead of failing.
	env = append(env, "GOTOOLCHAIN=auto", "GOFLAGS=-mod=mod")
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 3 {
		err = nil // vulnerabilities found: expected
	}
	if err != nil {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), err
}

func needsNewerToolchain(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "requires newer Go version") || strings.Contains(msg, "application built with") || strings.Contains(msg, "go.mod requires go >=")
}

// ecosystem returns the PURL type ("npm", "pypi", ...) for messages.
func ecosystem(purl string) string {
	rest := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i]
	}
	return "this ecosystem"
}

// ParseGovulncheck parses the govulncheck JSON stream.
func ParseGovulncheck(r io.Reader) (*GovulncheckResult, error) {
	res := &GovulncheckResult{Findings: map[string][]gvcTrace{}, Modules: map[string]string{}, OSVAliases: map[string]string{}}
	dec := json.NewDecoder(bufio.NewReader(r))
	for {
		var msg struct {
			Config *struct {
				ScanLevel string `json:"scan_level"`
			} `json:"config"`
			SBOM *struct {
				Modules []struct {
					Path    string `json:"path"`
					Version string `json:"version"`
				} `json:"modules"`
			} `json:"SBOM"`
			OSV *struct {
				ID      string   `json:"id"`
				Aliases []string `json:"aliases"`
			} `json:"osv"`
			Finding *struct {
				OSV   string   `json:"osv"`
				Trace gvcTrace `json:"trace"`
			} `json:"finding"`
		}
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return res, fmt.Errorf("evidence: parse govulncheck json: %w", err)
		}
		switch {
		case msg.Config != nil:
			res.ScanLevel = msg.Config.ScanLevel
		case msg.SBOM != nil:
			for _, m := range msg.SBOM.Modules {
				res.Modules[m.Path] = m.Version
			}
		case msg.OSV != nil:
			res.OSVAliases[msg.OSV.ID] = msg.OSV.ID
			for _, a := range msg.OSV.Aliases {
				res.OSVAliases[a] = msg.OSV.ID
			}
		case msg.Finding != nil:
			res.Findings[msg.Finding.OSV] = append(res.Findings[msg.Finding.OSV], msg.Finding.Trace)
		}
	}
	return res, nil
}

// EvidenceFor derives reachability evidence for vulnID (resolving aliases
// via the OSV record when present).
func (g *GovulncheckResult) EvidenceFor(vulnID string, v *osv.Vulnerability) []Item {
	ids := []string{vulnID}
	if v != nil {
		ids = append(ids, v.ID)
		ids = append(ids, v.Aliases...)
	}
	goID := ""
	for _, id := range ids {
		if mapped, ok := g.OSVAliases[id]; ok {
			goID = mapped
			break
		}
	}
	if goID == "" {
		// govulncheck did not report the vuln at all: either the module is not
		// in the build list or the Go vuln DB has no entry for it.
		return []Item{{Kind: KindNotImported, Strong: false, Summary: fmt.Sprintf("govulncheck (scan level %s) did not report %s for the product module", g.ScanLevel, vulnID)}}
	}
	traces := g.Findings[goID]
	var reachable []string
	for _, tr := range traces {
		if len(tr) == 0 {
			continue
		}
		if tr[0].Function != "" {
			// trace[0] is the vulnerable symbol; the last entry is the product entry point.
			last := tr[len(tr)-1]
			reachable = append(reachable, fmt.Sprintf("%s.%s ← %s.%s", tr[0].Package, tr[0].Function, last.Package, last.Function))
		}
	}
	if len(reachable) > 0 {
		sort.Strings(reachable)
		if len(reachable) > 5 {
			reachable = reachable[:5]
		}
		return []Item{{Kind: KindReachable, Strong: true, Summary: fmt.Sprintf("govulncheck found %d call path(s) from product code to vulnerable symbols of %s", len(traces), goID), Details: map[string]any{"call_paths": reachable, "govulncheck_id": goID}}}
	}
	if g.ScanLevel == "symbol" {
		return []Item{{Kind: KindNotReachable, Strong: true, Summary: fmt.Sprintf("govulncheck (symbol level) reports %s: vulnerable module is in the build list but no vulnerable symbol is reachable from product code", goID), Details: map[string]any{"govulncheck_id": goID}}}
	}
	return []Item{{Kind: KindNotReachable, Summary: fmt.Sprintf("govulncheck (%s level) reports %s as imported; symbol reachability unknown", g.ScanLevel, goID), Details: map[string]any{"govulncheck_id": goID}}}
}

// ---- symbol grep ----

var identRE = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

func (c *Collector) symbolEvidence(repoDir string, v *osv.Vulnerability) []Item {
	imports := v.VulnerableImports()
	if len(imports) == 0 {
		return nil
	}
	maxFiles := c.MaxGrepFiles
	if maxFiles <= 0 {
		maxFiles = 5000
	}
	importPaths := map[string]bool{}
	symbols := map[string]bool{}
	for _, im := range imports {
		importPaths[im.Path] = true
		for _, s := range im.Symbols {
			// "Server.ServeTLS" → method name; keep exported names only
			name := s
			if i := strings.LastIndex(s, "."); i >= 0 {
				name = s[i+1:]
			}
			if name != "" && name[0] >= 'A' && name[0] <= 'Z' {
				symbols[name] = true
			}
		}
	}

	importHits := map[string][]string{}
	symbolHits := map[string][]string{}
	files := 0
	_ = filepath.WalkDir(repoDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files++
		if files > maxFiles {
			return filepath.SkipAll
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(repoDir, path)
		imported := false
		for p := range importPaths {
			if bytes.Contains(data, []byte(`"`+p+`"`)) {
				importHits[p] = appendLimited(importHits[p], rel)
				imported = true
			}
		}
		if !imported {
			return nil
		}
		for _, m := range identRE.FindAll(data, -1) {
			if symbols[string(m)] {
				symbolHits[string(m)] = appendLimited(symbolHits[string(m)], rel)
			}
		}
		return nil
	})

	var items []Item
	if len(importHits) == 0 {
		return []Item{{Kind: KindImportNotFound, Strong: false, Summary: fmt.Sprintf("none of the vulnerable packages (%s) is imported directly by product code (transitive use still possible)", strings.Join(keys(importPaths), ", "))}}
	}
	if len(symbolHits) > 0 {
		items = append(items, Item{Kind: KindSymbolReferenced, Summary: fmt.Sprintf("product code imports %s and references vulnerable symbol name(s) %s", strings.Join(keys(importHits), ", "), strings.Join(keys(symbolHits), ", ")), Details: map[string]any{"files": symbolHits}})
	} else {
		items = append(items, Item{Kind: KindSymbolNotReferenced, Summary: fmt.Sprintf("product code imports %s but does not reference any vulnerable symbol name (%s)", strings.Join(keys(importHits), ", "), strings.Join(keys(symbols), ", ")), Details: map[string]any{"files": importHits}})
	}
	return items
}

func appendLimited(list []string, s string) []string {
	if len(list) >= 10 {
		return list
	}
	return append(list, s)
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
