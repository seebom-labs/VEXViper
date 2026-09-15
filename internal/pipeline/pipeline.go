// Package pipeline orchestrates one VEX generation run:
// BOMHort findings → product repo → evidence → assessment → OpenVEX (→ upload).
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"golang.org/x/mod/semver"

	"github.com/mfahlandt/vexviper/internal/assesscache"
	"github.com/mfahlandt/vexviper/internal/bomhort"
	"github.com/mfahlandt/vexviper/internal/config"
	"github.com/mfahlandt/vexviper/internal/evidence"
	"github.com/mfahlandt/vexviper/internal/llm"
	"github.com/mfahlandt/vexviper/internal/osv"
	"github.com/mfahlandt/vexviper/internal/repo"
	"github.com/mfahlandt/vexviper/internal/source"
	"github.com/mfahlandt/vexviper/internal/vexgen"
)

// Version is stamped by the CLI for the tooling field.
var Version = "dev"

// BOMHortAPI is what the pipeline needs from BOMHort (source.API + upload).
type BOMHortAPI interface {
	source.API
	UploadVEX(ctx context.Context, filename string, doc []byte) (bomhort.UploadResult, error)
}

// StatementLister is implemented by BOMHort clients that can enumerate the
// ingested VEX statements; it enables RunOptions.ReassessAfter.
type StatementLister interface {
	AllVEXStatements(ctx context.Context) ([]bomhort.VEXStatement, error)
}

// Cloner materializes repositories (repo.Cloner or a fake).
type Cloner interface {
	Clone(ctx context.Context, loc repo.Location) (string, error)
}

// Pipeline wires the stages together.
type Pipeline struct {
	Cfg      config.Config
	BOMHort  BOMHortAPI
	Provider llm.Provider
	Cloner   Cloner
	Evidence *evidence.Collector
	// Cache reuses verdicts across SBOMs (nil = disabled).
	Cache *assesscache.Store
	Log   *slog.Logger
}

// New builds a pipeline from config with real dependencies.
func New(cfg config.Config, log *slog.Logger) (*Pipeline, error) {
	if log == nil {
		log = slog.Default()
	}
	var opts []bomhort.Option
	if cfg.BOMHort.APIKey != "" {
		opts = append(opts, bomhort.WithAPIKey(cfg.BOMHort.APIKey))
	}
	if cfg.BOMHort.ServiceToken != "" {
		opts = append(opts, bomhort.WithServiceToken(cfg.BOMHort.ServiceToken))
	}
	p := &Pipeline{
		Cfg:     cfg,
		BOMHort: bomhort.New(cfg.BOMHort.URL, opts...),
		Log:     log,
	}
	provider, err := NewProvider(cfg.LLM, log)
	if err != nil {
		return nil, err
	}
	p.Provider = provider
	if cfg.Repo.Clone {
		p.Cloner = &repo.Cloner{CacheDir: cfg.Repo.CacheDir}
	}
	if cfg.Cache.Enabled {
		p.Cache = assesscache.New(cfg.CacheDir(), cfg.Cache.TTL)
	}
	p.Evidence = &evidence.Collector{OSV: osv.New("", nil)}
	if cfg.Repo.Govulncheck {
		p.Evidence.Govulncheck = findGovulncheck()
		if p.Evidence.Govulncheck == "" {
			log.Warn("govulncheck not found in PATH or GOPATH/bin; reachability analysis disabled")
		} else if _, err := exec.LookPath("go"); err != nil {
			// govulncheck shells out to `go`; find a toolchain when PATH lacks one.
			if goBin := findGoBin(); goBin != "" {
				p.Evidence.GoBin = goBin
				log.Info("go not in PATH; using toolchain for govulncheck", "dir", goBin)
			} else {
				log.Warn("govulncheck found but no `go` toolchain in PATH, GOROOT, ~/sdk or /usr/local/go; reachability analysis will fail")
			}
		}
	}
	return p, nil
}

// NewProvider instantiates the configured LLM provider, always wrapped with
// the heuristic fallback so a flaky LLM never aborts a run.
func NewProvider(cfg config.LLM, log *slog.Logger) (llm.Provider, error) {
	var primary llm.Provider
	switch cfg.Provider {
	case config.ProviderHeuristic:
		return llm.Heuristic{}, nil
	case config.ProviderOpenAI:
		primary = &llm.OpenAI{BaseURL: cfg.OpenAI.BaseURL, Model: cfg.OpenAI.Model, APIKey: cfg.OpenAI.APIKey, Temperature: cfg.OpenAI.Temperature, StructuredOutput: true}
		if cfg.OpenAI.Timeout > 0 {
			primary.(*llm.OpenAI).HTTP = &http.Client{Timeout: cfg.OpenAI.Timeout}
		}
	case config.ProviderGitHub:
		// GitHub Models speaks the OpenAI chat completions dialect.
		gh := &llm.OpenAI{BaseURL: cfg.GitHub.BaseURL, Model: cfg.GitHub.Model, APIKey: cfg.GitHub.Token, Temperature: cfg.GitHub.Temperature, StructuredOutput: true,
			ProviderName: config.ProviderGitHub, ExtraHeaders: map[string]string{"X-GitHub-Api-Version": config.GitHubModelsAPIVersion}}
		if cfg.GitHub.Timeout > 0 {
			gh.HTTP = &http.Client{Timeout: cfg.GitHub.Timeout}
		}
		primary = gh
	case config.ProviderCopilot:
		primary = &llm.CopilotCLI{Command: cfg.Copilot.Command, Model: cfg.Copilot.Model, Args: cfg.Copilot.Args, Timeout: cfg.Copilot.Timeout, InRepo: cfg.Copilot.InRepo}
	case config.ProviderMCPTool:
		switch cfg.MCP.Transport {
		case config.MCPTransportStdio:
			primary = llm.NewMCPToolStdio(cfg.MCP.Command, cfg.MCP.Args, cfg.MCP.Env, cfg.MCP.Tool, cfg.MCP.Timeout)
		case config.MCPTransportHTTP:
			primary = llm.NewMCPToolHTTP(cfg.MCP.URL, cfg.MCP.Headers, cfg.MCP.Tool, cfg.MCP.Timeout)
		default:
			return nil, fmt.Errorf("unknown mcp transport %q", cfg.MCP.Transport)
		}
	default:
		return nil, fmt.Errorf("unknown llm provider %q", cfg.Provider)
	}
	return llm.WithFallback{Primary: primary, Fallback: llm.Heuristic{}, OnError: func(req llm.Request, err error) {
		log.Warn("llm provider failed, using heuristic fallback", "vuln", req.Report.Finding.VulnID, "purl", req.Report.Finding.PURL, "err", err)
	}}, nil
}

func findGovulncheck() string {
	for _, c := range []string{"govulncheck", filepath.Join(os.Getenv("GOPATH"), "bin", "govulncheck"), filepath.Join(os.Getenv("HOME"), "go", "bin", "govulncheck")} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// findGoBin locates a directory containing the `go` binary outside PATH:
// $GOROOT/bin, the newest ~/sdk/go*/bin (golang.org/dl layout), /usr/local/go/bin.
func findGoBin() string {
	var dirs []string
	if r := os.Getenv("GOROOT"); r != "" {
		dirs = append(dirs, filepath.Join(r, "bin"))
	}
	if home := os.Getenv("HOME"); home != "" {
		sdks, _ := filepath.Glob(filepath.Join(home, "sdk", "go*", "bin", "go"))
		sort.Slice(sdks, func(i, j int) bool { return semver.Compare(sdkVersion(sdks[i]), sdkVersion(sdks[j])) > 0 })
		for _, g := range sdks {
			dirs = append(dirs, filepath.Dir(g))
		}
	}
	dirs = append(dirs, "/usr/local/go/bin", "/usr/lib/go/bin", "/usr/lib/golang/bin")
	for _, d := range dirs {
		if info, err := os.Stat(filepath.Join(d, "go")); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return d
		}
	}
	return ""
}

// sdkVersion turns ~/sdk/go1.25.10/bin/go into "v1.25.10" for semver.Compare.
func sdkVersion(goPath string) string {
	name := filepath.Base(filepath.Dir(filepath.Dir(goPath)))
	return "v" + strings.TrimPrefix(name, "go")
}

// RunOptions tunes a single run.
type RunOptions struct {
	// SBOMRef is the SBOM id, document name or source file in BOMHort.
	SBOMRef string
	// RepoOverride forces the product repository.
	RepoOverride string
	// OutDir receives <name>.openvex.json ("" = no file).
	OutDir string
	// Upload pushes the document to BOMHort.
	Upload bool
	// Regenerate re-assesses findings that already carry a vex_status,
	// except settled verdicts (not_affected, fixed): re-asking the provider
	// about those only burns tokens. Use Force to revisit them too.
	Regenerate bool
	// Force is a hard regenerate: every finding is re-assessed regardless of
	// its current status.
	Force bool
	// NoCache bypasses assessment-cache reads (results are still stored).
	// Regenerate and Force imply it: re-asking is the point of those runs.
	NoCache bool
	// Only restricts to specific vuln IDs (empty = all).
	Only []string
	// ReassessAfter re-includes findings whose current VEX status is
	// under_investigation or affected when BOMHort's newest statement for
	// them is older than this duration (0 = never). not_affected and fixed
	// verdicts are only revisited with Force.
	ReassessAfter time.Duration
}

// Outcome summarizes a run.
type Outcome struct {
	SBOM     bomhort.SBOM
	Product  source.Product
	RepoDir  string
	RepoHow  string
	Findings int
	Skipped  int
	// Settled counts skipped findings whose verdict is final (not_affected,
	// fixed) and was kept although Regenerate was requested.
	Settled int
	// Reassessed counts findings included because their statement expired.
	Reassessed int
	// Usage aggregates provider cost over the run (cache hits included).
	Usage       llm.Usage
	Document    []byte
	Filename    string
	Path        string
	Counts      map[vex.Status]int
	Guardrails  []vexgen.Guardrail
	Assessments []AssessmentRecord
	Upload      *bomhort.UploadResult
}

// AssessmentRecord is one finding's verdict for reporting.
type AssessmentRecord struct {
	VulnID     string
	PURL       string
	Status     vex.Status
	Confidence float64
	Provider   string
	Reasoning  string
	// Cached marks verdicts served from the assessment cache.
	Cached bool      `json:"cached,omitempty"`
	Usage  llm.Usage `json:"usage,omitempty"`
}

// Run executes the pipeline for one SBOM.
func (p *Pipeline) Run(ctx context.Context, opts RunOptions) (*Outcome, error) {
	if p.Cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.Cfg.Timeout)
		defer cancel()
	}
	log := p.Log
	if log == nil {
		log = slog.Default()
	}

	res, err := source.Load(ctx, p.BOMHort, opts.SBOMRef)
	if err != nil {
		return nil, err
	}
	out := &Outcome{Product: res.Product, SBOM: bomhort.SBOM{ID: res.Product.SBOMID, DocumentName: res.Product.DocumentName, SourceFile: res.Product.SourceFile}}
	log.Info("loaded findings", "sbom", res.Product.SBOMID, "name", res.Product.DocumentName, "findings", len(res.Findings))

	// Filter.
	stale := p.staleStatements(ctx, res.Findings, opts.ReassessAfter, log)
	var findings []source.Finding
	for _, f := range res.Findings {
		if f.VEXStatus != "" && !opts.Force {
			switch {
			case opts.Regenerate && !settled[f.VEXStatus]:
			case stale[statementKey(f.VulnID, f.PURL)]:
				out.Reassessed++
			default:
				out.Skipped++
				if opts.Regenerate && settled[f.VEXStatus] {
					out.Settled++
				}
				continue
			}
		}
		if len(opts.Only) > 0 && !contains(opts.Only, f.VulnID) {
			out.Skipped++
			continue
		}
		findings = append(findings, f)
	}
	out.Findings = len(findings)

	// Product repository.
	repoDir, how := p.MaterializeRepo(ctx, res.Product, opts.RepoOverride)
	out.RepoDir, out.RepoHow = repoDir, how

	var gvc *evidence.GovulncheckResult
	if repoDir != "" && p.Evidence != nil {
		gvc, err = p.Evidence.RunGovulncheck(ctx, repoDir)
		if err != nil {
			log.Warn("govulncheck failed; continuing without reachability", "err", err)
		} else if gvc != nil {
			log.Info("govulncheck completed", "scan_level", gvc.ScanLevel, "reported", len(gvc.Findings))
		}
	}

	// Assess.
	commit := ""
	if repoDir != "" {
		commit = repo.HeadCommit(repoDir)
	}
	readCache := p.Cache.Enabled() && !opts.NoCache && !opts.Regenerate && !opts.Force
	var entries []vexgen.Entry
	records := map[string]*AssessmentRecord{}
	for i, f := range findings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rep := p.Evidence.Collect(ctx, f, repoDir, gvc)
		req := llm.Request{ProductName: productName(res.Product), Report: rep, RepoDir: repoDir}
		if repoDir != "" {
			req.ProductRepo = how
		}
		key := assesscache.KeyFor(p.Provider.Name(), commit, how, rep)
		var (
			a      llm.Assessment
			cached bool
		)
		if readCache {
			a, cached = p.Cache.Get(key)
		}
		if cached {
			a.Usage = llm.Usage{CacheHits: 1}
		} else {
			var err error
			a, err = p.Provider.Assess(ctx, req)
			if err != nil {
				log.Error("assessment failed; marking under_investigation", "vuln", f.VulnID, "purl", f.PURL, "err", err)
				a = llm.Assessment{Status: vex.StatusUnderInvestigation, Reasoning: "assessment error: " + err.Error(), Provider: p.Provider.Name()}
			} else if err := p.Cache.Put(key, a, productName(res.Product)); err != nil {
				log.Warn("assessment cache write failed", "err", err)
			}
		}
		out.Usage.Add(a.Usage)
		log.Info("assessed", "n", fmt.Sprintf("%d/%d", i+1, len(findings)), "vuln", f.VulnID, "purl", f.PURL, "status", a.Status, "confidence", a.Confidence, "provider", a.Provider, "cached", cached, "usage", a.Usage.String())
		entries = append(entries, vexgen.Entry{Report: rep, Assessment: a})
		records[statementKey(f.VulnID, f.PURL)] = &AssessmentRecord{Confidence: a.Confidence, Provider: a.Provider, Cached: cached, Usage: a.Usage}
	}

	// Build.
	built, err := vexgen.Build(res.Product.SBOMID, entries, p.VEXOptions(p.Provider.Name()))
	if err != nil {
		return nil, err
	}
	out.Counts, out.Guardrails = built.Counts, built.Guardrails
	for _, s := range built.Document.Statements {
		rec := AssessmentRecord{VulnID: string(s.Vulnerability.Name), PURL: s.Products[0].ID, Status: s.Status, Reasoning: s.StatusNotes}
		if r := records[statementKey(rec.VulnID, rec.PURL)]; r != nil {
			rec.Confidence, rec.Provider, rec.Cached, rec.Usage = r.Confidence, r.Provider, r.Cached, r.Usage
		}
		out.Assessments = append(out.Assessments, rec)
	}
	if !out.Usage.IsZero() {
		log.Info("provider usage", "sbom", res.Product.SBOMID, "usage", out.Usage.String())
	}
	for _, g := range built.Guardrails {
		log.Warn("guardrail applied", "vuln", g.VulnID, "purl", g.PURL, "reason", g.Reason)
	}
	doc, err := vexgen.Marshal(built.Document)
	if err != nil {
		return nil, err
	}
	out.Document = doc
	out.Filename = Filename(res.Product)

	if opts.OutDir != "" {
		if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
			return nil, err
		}
		out.Path = filepath.Join(opts.OutDir, out.Filename)
		if err := os.WriteFile(out.Path, doc, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", out.Path, err)
		}
		log.Info("wrote VEX document", "path", out.Path, "statements", len(built.Document.Statements))
	}

	if opts.Upload {
		if len(built.Document.Statements) == 0 {
			log.Info("nothing to upload: no statements")
		} else {
			r, err := p.BOMHort.UploadVEX(ctx, out.Filename, doc)
			if err != nil {
				return out, fmt.Errorf("upload: %w", err)
			}
			out.Upload = &r
			log.Info("uploaded VEX document to BOMHort", "status", r.Status, "job_id", r.JobID, "sha256", r.SHA256Hash)
		}
	}
	return out, nil
}

// VEXOptions returns the document options derived from config.
func (p *Pipeline) VEXOptions(provider string) vexgen.Options {
	return vexgen.Options{
		Author:                      p.Cfg.VEX.Author,
		AuthorRole:                  p.Cfg.VEX.AuthorRole,
		Supplier:                    p.Cfg.VEX.Supplier,
		Tooling:                     "vexviper/" + Version + " provider=" + provider,
		Namespace:                   p.Cfg.VEX.Namespace,
		MinConfidence:               p.Cfg.LLM.MinConfidence,
		AllowUnsupportedNotAffected: p.Cfg.LLM.AllowUnsupportedNotAffected,
	}
}

// MaterializeRepo resolves and clones the product repository. Order:
// override → config override → SBOM hints → root PURLs. It returns the
// checkout dir ("" if unavailable) and the repository URL it settled on.
func (p *Pipeline) MaterializeRepo(ctx context.Context, prod source.Product, override string) (string, string) {
	log := p.Log
	if log == nil {
		log = slog.Default()
	}
	var candidates []repo.Location
	fallbackRef := VersionFromName(prod.SourceFile, prod.DocumentName)
	how := "flag"
	if override == "" {
		override = p.Cfg.Repo.Override
		how = "config"
	}
	if override == "" {
		override = p.Cfg.Repo.RepoFor(prod.SBOMID, prod.DocumentName, prod.SourceFile)
		how = "config-sbom"
	}
	override = strings.ReplaceAll(override, "{version}", fallbackRef)
	if loc, ok := repo.FromOverride(override); ok {
		loc.How = how
		if loc.Ref == "" {
			loc.Ref = fallbackRef
		}
		candidates = append(candidates, loc)
	} else if override != "" {
		log.Warn("repo override not understood", "override", override)
	}
	for _, h := range prod.RepoHints {
		if loc, ok := repo.FromOverride(h); ok {
			loc.How = "sbom"
			if loc.Ref == "" {
				loc.Ref = fallbackRef
			}
			candidates = append(candidates, loc)
		}
	}
	for _, purl := range prod.RootPURLs {
		if loc, ok := repo.FromPURL(purl); ok {
			loc.How = "root-purl"
			if loc.Ref == "" {
				loc.Ref = fallbackRef
			}
			candidates = append(candidates, loc)
		}
	}
	if len(candidates) == 0 {
		log.Info("no product repository could be determined; pass --repo to enable code analysis", "sbom", prod.SBOMID)
		return "", ""
	}
	if p.Cloner == nil {
		return "", candidates[0].URL
	}
	var errs []error
	for _, c := range candidates {
		dir, err := p.Cloner.Clone(ctx, c)
		if err == nil {
			log.Info("product repository ready", "url", c.URL, "ref", c.Ref, "via", c.How, "dir", dir)
			return dir, c.URL
		}
		errs = append(errs, err)
	}
	log.Warn("could not clone any product repository candidate", "err", errors.Join(errs...))
	return "", ""
}

var versionRE = regexp.MustCompile(`[-_@ ]v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?:[._-]|$)`)

// VersionFromName extracts a semantic version from SBOM file/document names
// such as "bomhort-0.6.1.spdx.json" or "kubermatic_kubelb_1.4.2.spdx.json"
// and returns it as a "v"-prefixed git ref candidate ("" if none).
func VersionFromName(names ...string) string {
	for _, n := range names {
		n = filepath.Base(n)
		for _, suf := range []string{".spdx.json", ".cdx.json", ".json", ".spdx", ".cdx"} {
			n = strings.TrimSuffix(n, suf)
		}
		if m := versionRE.FindStringSubmatch(n); m != nil {
			return "v" + m[1]
		}
	}
	return ""
}

// Filename derives the companion OpenVEX file name for an SBOM.
func Filename(prod source.Product) string {
	base := filepath.Base(prod.SourceFile)
	if base == "" || base == "." {
		base = prod.DocumentName
	}
	if base == "" || base == "." {
		base = prod.SBOMID
	}
	for _, suf := range []string{".spdx.json", ".cdx.json", ".json", ".spdx", ".cdx"} {
		base = strings.TrimSuffix(base, suf)
	}
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			return r
		}
		return '-'
	}, base)
	if base == "" || base == "." {
		base = "vex"
	}
	return base + ".vexviper.openvex.json"
}

func productName(p source.Product) string {
	switch {
	case p.DocumentName != "" && p.DocumentName != ".":
		return p.DocumentName
	case p.SourceFile != "":
		return p.SourceFile
	}
	return p.SBOMID
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func statementKey(vulnID, purl string) string { return vulnID + "\x00" + purl }

// reassessable lists statuses that are worth revisiting automatically.
var reassessable = map[string]bool{
	string(vex.StatusUnderInvestigation): true,
	string(vex.StatusAffected):           true,
}

// settled lists final verdicts that Regenerate leaves alone; only Force
// re-assesses them.
var settled = map[string]bool{
	string(vex.StatusNotAffected): true,
	string(vex.StatusFixed):       true,
}

// staleStatements returns the (vuln_id, purl) keys of findings whose newest
// BOMHort statement is older than ttl and whose status is reassessable.
func (p *Pipeline) staleStatements(ctx context.Context, findings []source.Finding, ttl time.Duration, log *slog.Logger) map[string]bool {
	stale := map[string]bool{}
	if ttl <= 0 {
		return stale
	}
	lister, ok := p.BOMHort.(StatementLister)
	if !ok {
		log.Warn("reassess_after set but BOMHort client cannot list VEX statements")
		return stale
	}
	stmts, err := lister.AllVEXStatements(ctx)
	if err != nil {
		log.Warn("reassess_after: listing VEX statements failed; keeping existing statuses", "err", err)
		return stale
	}
	newest := map[string]time.Time{}
	for _, s := range stmts {
		ts := parseTime(s.VEXTimestamp)
		if ts.IsZero() {
			ts = parseTime(s.IngestedAt)
		}
		k := statementKey(s.VulnID, s.ProductPURL)
		if ts.After(newest[k]) {
			newest[k] = ts
		}
	}
	cutoff := time.Now().Add(-ttl)
	for _, f := range findings {
		if !reassessable[f.VEXStatus] {
			continue
		}
		ts, known := newest[statementKey(f.VulnID, f.PURL)]
		if known && ts.Before(cutoff) {
			stale[statementKey(f.VulnID, f.PURL)] = true
		}
	}
	return stale
}

func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Wait polls BOMHort until statements from the uploaded document are
// visible or the timeout expires. It is used by the CLI (--wait) and E2E.
func (p *Pipeline) Wait(ctx context.Context, docID string, timeout time.Duration, statements func(ctx context.Context) ([]bomhort.VEXStatement, error)) error {
	deadline := time.Now().Add(timeout)
	for {
		list, err := statements(ctx)
		if err == nil {
			for _, s := range list {
				if s.DocumentID == docID {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for VEX document %s to be ingested", docID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
