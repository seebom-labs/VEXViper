// Package source turns BOMHort API data for one SBOM into the Finding list
// the rest of the pipeline works on. BOMHort is the single source of truth
// for vulnerabilities; the raw SBOM is only consulted for repository hints
// and to distinguish direct from transitive dependencies.
package source

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/seebom-labs/vexviper/internal/bomhort"
	"github.com/seebom-labs/vexviper/internal/sbom"
)

// Finding is one (vulnerability, package) pair as BOMHort reports it. VulnID
// and PURL are kept verbatim because BOMHort matches VEX statements on exact
// string equality of both.
type Finding struct {
	VulnID       string
	PURL         string
	Severity     string
	Summary      string
	FixedVersion string
	// VEXStatus is the status BOMHort already applies from ingested VEX (empty if none).
	VEXStatus string
	// Direct is true when the package is a direct dependency of the product.
	Direct bool
	// DirectKnown is false when the SBOM carries no relationship data at all.
	DirectKnown bool
	// PackageName and PackageVersion are taken from the dependency tree when available.
	PackageName    string
	PackageVersion string
}

// Product describes the SBOM under analysis.
type Product struct {
	SBOMID       string
	DocumentName string
	SourceFile   string
	// RepoHints are candidate source repositories for the product, best first.
	RepoHints []string
	// RootPURLs are the PURLs of the components the SBOM describes, if any.
	RootPURLs []string
}

// Result bundles the product with its findings.
type Result struct {
	Product  Product
	Findings []Finding
}

// API is the subset of bomhort.Client the source needs (for tests).
type API interface {
	FindSBOM(ctx context.Context, ref string) (bomhort.SBOM, error)
	Vulnerabilities(ctx context.Context, sbomID string) ([]bomhort.Vulnerability, error)
	Dependencies(ctx context.Context, sbomID string) ([]bomhort.DependencyNode, error)
	DownloadSBOM(ctx context.Context, sbomID string) ([]byte, error)
}

// Load resolves ref (SBOM id, document name or source file) and collects findings.
func Load(ctx context.Context, api API, ref string) (*Result, error) {
	s, err := api.FindSBOM(ctx, ref)
	if err != nil {
		return nil, err
	}
	return LoadSBOM(ctx, api, s)
}

// LoadSBOM collects findings for an already-resolved SBOM.
func LoadSBOM(ctx context.Context, api API, s bomhort.SBOM) (*Result, error) {
	vulns, err := api.Vulnerabilities(ctx, s.ID)
	if err != nil {
		return nil, fmt.Errorf("source: vulnerabilities of %s: %w", s.ID, err)
	}
	res := &Result{Product: Product{SBOMID: s.ID, DocumentName: s.DocumentName, SourceFile: s.SourceFile}}

	// Dependency tree: best effort.
	direct := map[string]bool{}
	names := map[string]bomhort.DependencyNode{}
	directKnown := false
	if deps, err := api.Dependencies(ctx, s.ID); err != nil {
		slog.Warn("source: dependency tree unavailable", "sbom", s.ID, "err", err)
	} else {
		directKnown = markDirect(deps, direct, names)
	}

	// Raw SBOM: repo hints and a second opinion on direct deps.
	var doc *sbom.Document
	if raw, err := api.DownloadSBOM(ctx, s.ID); err != nil {
		slog.Warn("source: raw SBOM unavailable", "sbom", s.ID, "err", err)
	} else if doc, err = sbom.Parse(raw); err != nil {
		slog.Warn("source: raw SBOM unparsable", "sbom", s.ID, "err", err)
		doc = nil
	}
	if doc != nil {
		res.Product.RepoHints = doc.RepoHints
		for _, c := range doc.Components {
			if c.Root && c.PURL != "" {
				res.Product.RootPURLs = append(res.Product.RootPURLs, c.PURL)
			}
			if !directKnown && c.Direct {
				direct[c.PURL] = true
				directKnown = true
			}
		}
	}

	// BOMHort may return one row per (finding, source_file/statement); VEX is
	// keyed on (vuln_id, purl) so collapse duplicates, preferring a row that
	// already carries a vex_status.
	seen := map[string]int{}
	for _, v := range vulns {
		f := Finding{
			VulnID:       strings.TrimSpace(v.VulnID),
			PURL:         strings.TrimSpace(v.PURL),
			Severity:     v.Severity,
			Summary:      v.Summary,
			FixedVersion: v.FixedVersion,
			VEXStatus:    v.VEXStatus,
			Direct:       direct[v.PURL],
			DirectKnown:  directKnown,
		}
		if n, ok := names[v.PURL]; ok {
			f.PackageName, f.PackageVersion = n.Name, n.Version
		} else if doc != nil {
			if c, ok := doc.ByPURL()[v.PURL]; ok {
				f.PackageName, f.PackageVersion = c.Name, c.Version
			}
		}
		if f.VulnID == "" || f.PURL == "" {
			slog.Warn("source: skipping finding without vuln_id or purl", "sbom", s.ID, "vuln", v.VulnID, "purl", v.PURL)
			continue
		}
		key := f.VulnID + "\x00" + f.PURL
		if i, dup := seen[key]; dup {
			// BOMHort emits one row per matching VEX statement, so several
			// documents for the same (vuln, purl) surface as duplicates with
			// possibly different statuses. Any non-empty status means "already
			// VEXed"; the newest statement is resolved via /vex/statements.
			if res.Findings[i].VEXStatus == "" && f.VEXStatus != "" {
				res.Findings[i].VEXStatus = f.VEXStatus
			} else if f.VEXStatus != "" && f.VEXStatus != res.Findings[i].VEXStatus {
				slog.Debug("source: conflicting vex_status rows", "sbom", s.ID, "vuln", f.VulnID, "purl", f.PURL, "kept", res.Findings[i].VEXStatus, "other", f.VEXStatus)
			}
			continue
		}
		seen[key] = len(res.Findings)
		res.Findings = append(res.Findings, f)
	}
	return res, nil
}

// markDirect flags children of root nodes (nodes nobody points to) as direct.
// It returns false when the tree carries no edges at all.
func markDirect(nodes []bomhort.DependencyNode, direct map[string]bool, names map[string]bomhort.DependencyNode) bool {
	byIndex := make(map[uint32]bomhort.DependencyNode, len(nodes))
	hasParent := map[uint32]bool{}
	edges := 0
	for _, n := range nodes {
		byIndex[n.Index] = n
		if n.PURL != "" {
			names[n.PURL] = n
		}
		for _, c := range n.Children {
			hasParent[c] = true
			edges++
		}
	}
	if edges == 0 {
		return false
	}
	for _, n := range nodes {
		if hasParent[n.Index] {
			continue
		}
		for _, c := range n.Children {
			if child, ok := byIndex[c]; ok && child.PURL != "" {
				direct[child.PURL] = true
			}
		}
	}
	return true
}
