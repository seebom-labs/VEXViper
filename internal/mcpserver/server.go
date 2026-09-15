// Package mcpserver exposes VEXViper as an MCP server so an LLM host
// (Claude Desktop, Copilot, an agent framework) can drive VEX generation
// interactively: browse BOMHort findings, gather code evidence, submit its
// own assessments and publish the resulting OpenVEX document.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/mfahlandt/vexviper/internal/bomhort"
	"github.com/mfahlandt/vexviper/internal/evidence"
	"github.com/mfahlandt/vexviper/internal/llm"
	"github.com/mfahlandt/vexviper/internal/pipeline"
	"github.com/mfahlandt/vexviper/internal/source"
	"github.com/mfahlandt/vexviper/internal/vexgen"
)

// SBOMLister is the extra BOMHort capability the server needs beyond the pipeline.
type SBOMLister interface {
	AllSBOMs(ctx context.Context) ([]bomhort.SBOM, error)
	VEXStatements(ctx context.Context, page, pageSize int) (bomhort.Paginated[bomhort.VEXStatement], error)
}

// Server holds the dependencies for the tool handlers.
type Server struct {
	Pipeline *pipeline.Pipeline
	Lister   SBOMLister
	Log      *slog.Logger
	Version  string
}

// New builds the MCP server with all tools registered.
func (s *Server) New() *mcp.Server {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Version == "" {
		s.Version = pipeline.Version
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "vexviper", Version: s.Version}, &mcp.ServerOptions{
		Instructions: "VEXViper generates OpenVEX documents for SBOMs stored in BOMHort. " +
			"Typical flow: list_sboms → list_findings → get_repo_context (deterministic evidence) → " +
			"draft_vex with your own per-finding assessments (or generate_vex to let the configured provider assess) → upload_vex.",
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "list_sboms", Description: "List SBOMs known to BOMHort with their vulnerability counts."}, s.listSBOMs)
	mcp.AddTool(srv, &mcp.Tool{Name: "list_findings", Description: "List the vulnerability findings BOMHort reports for one SBOM (by id, document name or source file). Findings that already carry a vex_status are included with that status."}, s.listFindings)
	mcp.AddTool(srv, &mcp.Tool{Name: "get_repo_context", Description: "Resolve and clone the product's source repository, run govulncheck when it is a Go module and collect deterministic evidence (version comparison, dependency depth, reachability, symbol references, OSV details) for each finding of the SBOM."}, s.getRepoContext)
	mcp.AddTool(srv, &mcp.Tool{Name: "draft_vex", Description: "Build a validated OpenVEX document from assessments you provide (one per vuln_id+purl). Guardrails downgrade unsupported not_affected/fixed claims to under_investigation. Writes <name>.vexviper.openvex.json to the configured out_dir and returns the document."}, s.draftVEX)
	mcp.AddTool(srv, &mcp.Tool{Name: "generate_vex", Description: "Run the full VEXViper pipeline for an SBOM with the configured assessment provider (heuristic/openai/github/copilot/mcptool) and optionally upload to BOMHort. By default findings that already carry a vex_status are skipped; regenerate=true re-assesses them except settled verdicts (not_affected/fixed); force=true re-assesses everything."}, s.generateVEX)
	mcp.AddTool(srv, &mcp.Tool{Name: "upload_vex", Description: "Upload an OpenVEX document (inline JSON or a path returned by draft_vex/generate_vex) to BOMHort's /api/v1/sboms/upload endpoint."}, s.uploadVEX)
	mcp.AddTool(srv, &mcp.Tool{Name: "list_vex_statements", Description: "List the VEX statements BOMHort has ingested (to verify an upload was applied)."}, s.listVEXStatements)
	return srv
}

// Handler returns a streamable-HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s.New() }, &mcp.StreamableHTTPOptions{})
}

type listSBOMsIn struct {
	// Search filters by document name/source file substring (optional).
	Search string `json:"search,omitempty"`
}

type sbomOut struct {
	ID           string `json:"sbom_id"`
	DocumentName string `json:"document_name"`
	SourceFile   string `json:"source_file"`
	PackageCount uint64 `json:"package_count"`
	VulnCount    uint64 `json:"vuln_count"`
	IngestedAt   string `json:"ingested_at"`
	// ConfiguredRepo is the repository pinned for this SBOM in repo.sboms (if any).
	ConfiguredRepo string `json:"configured_repo,omitempty"`
}

type listSBOMsOut struct {
	SBOMs []sbomOut `json:"sboms"`
}

func (s *Server) listSBOMs(ctx context.Context, _ *mcp.CallToolRequest, in listSBOMsIn) (*mcp.CallToolResult, listSBOMsOut, error) {
	list, err := s.Lister.AllSBOMs(ctx)
	if err != nil {
		return nil, listSBOMsOut{}, err
	}
	out := listSBOMsOut{SBOMs: []sbomOut{}}
	for _, b := range list {
		if in.Search != "" && !strings.Contains(strings.ToLower(b.DocumentName+" "+b.SourceFile), strings.ToLower(in.Search)) {
			continue
		}
		out.SBOMs = append(out.SBOMs, sbomOut{ID: b.ID, DocumentName: b.DocumentName, SourceFile: b.SourceFile, PackageCount: b.PackageCount, VulnCount: b.VulnCount, IngestedAt: b.IngestedAt,
			ConfiguredRepo: s.Pipeline.Cfg.Repo.RepoFor(b.ID, b.DocumentName, b.SourceFile)})
	}
	return nil, out, nil
}

type sbomRefIn struct {
	// SBOM is the BOMHort sbom_id, document name or source file.
	SBOM string `json:"sbom"`
}

type findingsOut struct {
	Product  source.Product   `json:"product"`
	Findings []source.Finding `json:"findings"`
}

func (s *Server) listFindings(ctx context.Context, _ *mcp.CallToolRequest, in sbomRefIn) (*mcp.CallToolResult, findingsOut, error) {
	res, err := source.Load(ctx, s.Pipeline.BOMHort, in.SBOM)
	if err != nil {
		return nil, findingsOut{}, err
	}
	if res.Findings == nil {
		res.Findings = []source.Finding{}
	}
	return nil, findingsOut{Product: res.Product, Findings: res.Findings}, nil
}

type repoContextIn struct {
	SBOM string `json:"sbom"`
	// Repo overrides repository resolution (URL or owner/name[@ref]).
	Repo string `json:"repo,omitempty"`
	// IncludeAssessed also collects evidence for findings that already have a vex_status.
	IncludeAssessed bool `json:"include_assessed,omitempty"`
}

type findingContext struct {
	Finding  source.Finding  `json:"finding"`
	Evidence []evidence.Item `json:"evidence"`
	OSV      *osvSummary     `json:"osv,omitempty"`
	// Prompt is the exact evidence prompt VEXViper would send to an LLM.
	Prompt string `json:"prompt"`
}

type osvSummary struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	Summary string   `json:"summary,omitempty"`
	Fixed   []string `json:"fixed_versions,omitempty"`
}

type repoContextOut struct {
	Product      source.Product   `json:"product"`
	RepoDir      string           `json:"repo_dir,omitempty"`
	RepoURL      string           `json:"repo_url,omitempty"`
	Govulncheck  string           `json:"govulncheck,omitempty"`
	Findings     []findingContext `json:"findings"`
	SystemPrompt string           `json:"system_prompt"`
	Schema       map[string]any   `json:"assessment_schema"`
}

func (s *Server) getRepoContext(ctx context.Context, _ *mcp.CallToolRequest, in repoContextIn) (*mcp.CallToolResult, repoContextOut, error) {
	res, err := source.Load(ctx, s.Pipeline.BOMHort, in.SBOM)
	if err != nil {
		return nil, repoContextOut{}, err
	}
	var findings []source.Finding
	for _, f := range res.Findings {
		if f.VEXStatus != "" && !in.IncludeAssessed {
			continue
		}
		findings = append(findings, f)
	}
	dir, how := s.Pipeline.MaterializeRepo(ctx, res.Product, in.Repo)
	out := repoContextOut{Product: res.Product, RepoDir: dir, RepoURL: how, Findings: []findingContext{}, SystemPrompt: llm.SystemPrompt, Schema: llm.JSONSchema}
	var gvc *evidence.GovulncheckResult
	if dir != "" && s.Pipeline.Evidence != nil {
		gvc, err = s.Pipeline.Evidence.RunGovulncheck(ctx, dir)
		switch {
		case err != nil:
			out.Govulncheck = "failed: " + err.Error()
		case gvc == nil:
			out.Govulncheck = "skipped (not a Go module or govulncheck unavailable)"
		default:
			out.Govulncheck = fmt.Sprintf("ok (%s, %d findings reported)", gvc.ScanLevel, len(gvc.Findings))
		}
	}
	for _, f := range findings {
		rep := s.Pipeline.Evidence.Collect(ctx, f, dir, gvc)
		fc := findingContext{Finding: f, Evidence: rep.Items, Prompt: llm.BuildUserPrompt(llm.Request{ProductName: res.Product.DocumentName, ProductRepo: how, Report: rep})}
		if fc.Evidence == nil {
			fc.Evidence = []evidence.Item{}
		}
		if rep.OSV != nil {
			fc.OSV = &osvSummary{ID: rep.OSV.ID, Aliases: rep.OSV.Aliases, Summary: rep.OSV.Summary, Fixed: rep.OSV.FixedVersions("")}
		}
		out.Findings = append(out.Findings, fc)
	}
	return nil, out, nil
}

// AssessmentIn is one host-provided verdict.
type AssessmentIn struct {
	VulnID          string  `json:"vuln_id"`
	PURL            string  `json:"purl"`
	Status          string  `json:"status"`
	Justification   string  `json:"justification,omitempty"`
	ImpactStatement string  `json:"impact_statement,omitempty"`
	ActionStatement string  `json:"action_statement,omitempty"`
	Confidence      float64 `json:"confidence"`
	Reasoning       string  `json:"reasoning"`
}

type draftIn struct {
	SBOM        string         `json:"sbom"`
	Repo        string         `json:"repo,omitempty"`
	Assessments []AssessmentIn `json:"assessments"`
	// Author overrides the configured document author (e.g. the reviewing human).
	Author string `json:"author,omitempty"`
	// Upload pushes the document to BOMHort immediately.
	Upload bool `json:"upload,omitempty"`
}

type docOut struct {
	Filename   string             `json:"filename"`
	Path       string             `json:"path,omitempty"`
	DocumentID string             `json:"document_id"`
	Counts     map[string]int     `json:"counts"`
	Guardrails []vexgen.Guardrail `json:"guardrails"`
	Document   map[string]any     `json:"document"`
	Upload     *uploadOut         `json:"upload,omitempty"`
}

type uploadOut struct {
	Status string `json:"status"`
	JobID  string `json:"job_id,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

func (s *Server) draftVEX(ctx context.Context, _ *mcp.CallToolRequest, in draftIn) (*mcp.CallToolResult, docOut, error) {
	if len(in.Assessments) == 0 {
		return nil, docOut{}, fmt.Errorf("no assessments provided")
	}
	res, err := source.Load(ctx, s.Pipeline.BOMHort, in.SBOM)
	if err != nil {
		return nil, docOut{}, err
	}
	byKey := map[string]source.Finding{}
	for _, f := range res.Findings {
		byKey[f.VulnID+"|"+f.PURL] = f
	}
	dir, _ := s.Pipeline.MaterializeRepo(ctx, res.Product, in.Repo)
	var gvc *evidence.GovulncheckResult
	if dir != "" && s.Pipeline.Evidence != nil {
		gvc, _ = s.Pipeline.Evidence.RunGovulncheck(ctx, dir)
	}
	var entries []vexgen.Entry
	var unknown []string
	for _, a := range in.Assessments {
		f, ok := byKey[a.VulnID+"|"+a.PURL]
		if !ok {
			unknown = append(unknown, a.VulnID+" "+a.PURL)
			continue
		}
		rep := s.Pipeline.Evidence.Collect(ctx, f, dir, gvc)
		as := llm.Assessment{Status: vex.Status(a.Status), Justification: vex.Justification(a.Justification), ImpactStatement: a.ImpactStatement, ActionStatement: a.ActionStatement, Confidence: a.Confidence, Reasoning: a.Reasoning, Provider: "mcp-host"}
		as.Normalize()
		entries = append(entries, vexgen.Entry{Report: rep, Assessment: as})
	}
	if len(unknown) > 0 {
		return nil, docOut{}, fmt.Errorf("assessments reference findings BOMHort does not report for this SBOM (vuln_id+purl must match exactly): %s", strings.Join(unknown, "; "))
	}
	opts := s.Pipeline.VEXOptions("mcp-host")
	if in.Author != "" {
		opts.Author = in.Author
	}
	built, err := vexgen.Build(res.Product.SBOMID, entries, opts)
	if err != nil {
		return nil, docOut{}, err
	}
	data, err := vexgen.Marshal(built.Document)
	if err != nil {
		return nil, docOut{}, err
	}
	out := docOut{Filename: pipeline.Filename(res.Product), DocumentID: built.Document.ID, Counts: map[string]int{}, Guardrails: built.Guardrails, Document: toMap(data)}
	if out.Guardrails == nil {
		out.Guardrails = []vexgen.Guardrail{}
	}
	for k, v := range built.Counts {
		out.Counts[string(k)] = v
	}
	if od := s.Pipeline.Cfg.VEX.OutDir; od != "" {
		if err := os.MkdirAll(od, 0o755); err != nil {
			return nil, docOut{}, err
		}
		out.Path = filepath.Join(od, out.Filename)
		if err := os.WriteFile(out.Path, data, 0o644); err != nil {
			return nil, docOut{}, err
		}
	}
	if in.Upload {
		r, err := s.Pipeline.BOMHort.UploadVEX(ctx, out.Filename, data)
		if err != nil {
			return nil, docOut{}, fmt.Errorf("document built but upload failed: %w", err)
		}
		out.Upload = &uploadOut{Status: r.Status, JobID: r.JobID, SHA256: r.SHA256Hash}
	}
	return nil, out, nil
}

type generateIn struct {
	SBOM       string `json:"sbom"`
	Repo       string `json:"repo,omitempty"`
	Upload     bool   `json:"upload,omitempty"`
	Regenerate bool   `json:"regenerate,omitempty"`
	Force      bool   `json:"force,omitempty"`
	NoCache    bool   `json:"no_cache,omitempty"`
}

type generateOut struct {
	docOut
	Findings    int                         `json:"findings"`
	Skipped     int                         `json:"skipped"`
	Settled     int                         `json:"settled,omitempty"`
	Usage       llm.Usage                   `json:"usage"`
	RepoURL     string                      `json:"repo_url,omitempty"`
	Assessments []pipeline.AssessmentRecord `json:"assessments"`
}

func (s *Server) generateVEX(ctx context.Context, _ *mcp.CallToolRequest, in generateIn) (*mcp.CallToolResult, generateOut, error) {
	o, err := s.Pipeline.Run(ctx, pipeline.RunOptions{SBOMRef: in.SBOM, RepoOverride: in.Repo, OutDir: s.Pipeline.Cfg.VEX.OutDir, Upload: in.Upload, Regenerate: in.Regenerate || in.Force, Force: in.Force, NoCache: in.NoCache})
	if err != nil {
		return nil, generateOut{}, err
	}
	out := generateOut{Findings: o.Findings, Skipped: o.Skipped, Settled: o.Settled, Usage: o.Usage, RepoURL: o.RepoHow, Assessments: o.Assessments}
	out.Filename, out.Path, out.Document, out.Guardrails = o.Filename, o.Path, toMap(o.Document), o.Guardrails
	out.Counts = map[string]int{}
	for k, v := range o.Counts {
		out.Counts[string(k)] = v
	}
	if out.Assessments == nil {
		out.Assessments = []pipeline.AssessmentRecord{}
	}
	if out.Guardrails == nil {
		out.Guardrails = []vexgen.Guardrail{}
	}
	out.DocumentID, _ = out.Document["@id"].(string)
	if o.Upload != nil {
		out.Upload = &uploadOut{Status: o.Upload.Status, JobID: o.Upload.JobID, SHA256: o.Upload.SHA256Hash}
	}
	return nil, out, nil
}

type uploadIn struct {
	// Filename must end with .openvex.json so BOMHort treats it as VEX (defaults to base of path).
	Filename string `json:"filename,omitempty"`
	// Document is the OpenVEX JSON (object); alternatively give Path.
	Document map[string]any `json:"document,omitempty"`
	Path     string         `json:"path,omitempty"`
}

func (s *Server) uploadVEX(ctx context.Context, _ *mcp.CallToolRequest, in uploadIn) (*mcp.CallToolResult, uploadOut, error) {
	var data []byte
	var err error
	switch {
	case in.Path != "":
		data, err = os.ReadFile(in.Path)
		if err != nil {
			return nil, uploadOut{}, err
		}
	case len(in.Document) > 0:
		data, err = json.Marshal(in.Document)
		if err != nil {
			return nil, uploadOut{}, err
		}
	default:
		return nil, uploadOut{}, fmt.Errorf("either document or path is required")
	}
	name := in.Filename
	if name == "" {
		name = filepath.Base(in.Path)
	}
	if !strings.HasSuffix(name, ".openvex.json") {
		return nil, uploadOut{}, fmt.Errorf("filename %q must end with .openvex.json", name)
	}
	var doc vex.VEX
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, uploadOut{}, fmt.Errorf("not an OpenVEX document: %w", err)
	}
	for i := range doc.Statements {
		if err := doc.Statements[i].Validate(); err != nil {
			return nil, uploadOut{}, fmt.Errorf("statement %d invalid: %w", i, err)
		}
	}
	r, err := s.Pipeline.BOMHort.UploadVEX(ctx, name, data)
	if err != nil {
		return nil, uploadOut{}, err
	}
	return nil, uploadOut{Status: r.Status, JobID: r.JobID, SHA256: r.SHA256Hash}, nil
}

type statementsIn struct {
	// DocumentID filters to one VEX document (optional).
	DocumentID string `json:"document_id,omitempty"`
	// VulnID filters to one vulnerability (optional).
	VulnID string `json:"vuln_id,omitempty"`
}

type statementsOut struct {
	Total      uint64                 `json:"total"`
	Statements []bomhort.VEXStatement `json:"statements"`
}

func (s *Server) listVEXStatements(ctx context.Context, _ *mcp.CallToolRequest, in statementsIn) (*mcp.CallToolResult, statementsOut, error) {
	out := statementsOut{Statements: []bomhort.VEXStatement{}}
	for page := 1; ; page++ {
		pg, err := s.Lister.VEXStatements(ctx, page, 100)
		if err != nil {
			return nil, statementsOut{}, err
		}
		out.Total = pg.Total
		for _, st := range pg.Data {
			if in.DocumentID != "" && st.DocumentID != in.DocumentID {
				continue
			}
			if in.VulnID != "" && st.VulnID != in.VulnID {
				continue
			}
			out.Statements = append(out.Statements, st)
		}
		if len(pg.Data) < 100 || uint64(page*100) >= pg.Total {
			break
		}
	}
	return nil, out, nil
}

// toMap converts marshalled JSON into a generic object (the MCP SDK derives
// output schemas from Go types and cannot describe json.RawMessage).
func toMap(data []byte) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(data, &m)
	return m
}
