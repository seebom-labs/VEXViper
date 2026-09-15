// Package vexgen turns assessments into an OpenVEX document that BOMHort can
// ingest, applying safety guardrails on the way.
package vexgen

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/seebom-labs/vexviper/internal/evidence"
	"github.com/seebom-labs/vexviper/internal/llm"
)

// Options controls document metadata and guardrails.
type Options struct {
	Author     string
	AuthorRole string
	Supplier   string
	Tooling    string
	// Namespace is the IRI prefix for document and statement IDs.
	Namespace string
	// MinConfidence: assessments below it become under_investigation.
	MinConfidence float64
	// AllowUnsupportedNotAffected permits not_affected without strong evidence.
	AllowUnsupportedNotAffected bool
	// Now overrides the timestamp (tests).
	Now func() time.Time
}

// Entry pairs an assessment with the evidence it was made from.
type Entry struct {
	Report     *evidence.Report
	Assessment llm.Assessment
}

// Guardrail records a modification the generator applied.
type Guardrail struct {
	VulnID string
	PURL   string
	Reason string
}

// Result is the generated document plus bookkeeping.
type Result struct {
	Document   *vex.VEX
	Guardrails []Guardrail
	// Counts by final status.
	Counts map[vex.Status]int
}

// Build assembles the document. Entries with invalid assessments (after
// guardrails) are downgraded rather than dropped so every finding gets a
// statement.
// buildMu serializes Build: go-vex keeps the namespace in the package-level
// vex.DefaultNamespace, which GenerateCanonicalID reads.
var buildMu sync.Mutex

func Build(productID string, entries []Entry, opts Options) (*Result, error) {
	buildMu.Lock()
	defer buildMu.Unlock()
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	if opts.Namespace != "" {
		vex.DefaultNamespace = strings.TrimRight(opts.Namespace, "/")
	}
	doc := vex.New()
	doc.Timestamp = &now
	doc.Author = opts.Author
	if doc.Author == "" {
		doc.Author = "VEXViper"
	}
	doc.AuthorRole = opts.AuthorRole
	doc.Supplier = opts.Supplier
	doc.Tooling = opts.Tooling
	if doc.Tooling == "" {
		doc.Tooling = "vexviper"
	}

	res := &Result{Document: &doc, Counts: map[vex.Status]int{}}

	sorted := append([]Entry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i].Report.Finding, sorted[j].Report.Finding
		if a.VulnID != b.VulnID {
			return a.VulnID < b.VulnID
		}
		return a.PURL < b.PURL
	})

	for _, e := range sorted {
		f := e.Report.Finding
		a := e.Assessment
		a.Normalize()
		a, gr := applyGuardrails(a, e.Report, opts)
		for _, g := range gr {
			res.Guardrails = append(res.Guardrails, Guardrail{VulnID: f.VulnID, PURL: f.PURL, Reason: g})
		}
		if err := a.Validate(); err != nil {
			res.Guardrails = append(res.Guardrails, Guardrail{VulnID: f.VulnID, PURL: f.PURL, Reason: "invalid assessment downgraded: " + err.Error()})
			a = llm.Assessment{Status: vex.StatusUnderInvestigation, Confidence: 0, Reasoning: "assessment failed validation: " + err.Error(), Provider: a.Provider}
		}

		ts := now
		stmt := vex.Statement{
			ID:        fmt.Sprintf("%s/statements/%s/%s", strings.TrimRight(vex.DefaultNamespace, "/"), sanitize(f.VulnID), sanitize(f.PURL)),
			Timestamp: &ts,
			// BOMHort resolves the ID from name → @id → aliases[0]; keep the
			// exact BOMHort vuln_id in Name so the join matches.
			Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(f.VulnID), Description: f.Summary},
			Products: []vex.Product{{Component: vex.Component{
				ID:          f.PURL,
				Identifiers: map[vex.IdentifierType]string{vex.PURL: f.PURL},
			}}},
			Status:          a.Status,
			StatusNotes:     statusNotes(a, e.Report),
			Justification:   a.Justification,
			ImpactStatement: a.ImpactStatement,
			ActionStatement: a.ActionStatement,
		}
		if e.Report.OSV != nil {
			if cve := e.Report.OSV.CVE(); cve != "" && cve != f.VulnID {
				stmt.Vulnerability.Aliases = append(stmt.Vulnerability.Aliases, vex.VulnerabilityID(cve))
			}
			if stmt.Vulnerability.Description == "" {
				stmt.Vulnerability.Description = e.Report.OSV.Summary
			}
		}
		if a.Status == vex.StatusAffected {
			stmt.ActionStatementTimestamp = &ts
		}
		if err := stmt.Validate(); err != nil {
			return nil, fmt.Errorf("vexgen: statement for %s/%s invalid after guardrails: %w", f.VulnID, f.PURL, err)
		}
		doc.Statements = append(doc.Statements, stmt)
		res.Counts[a.Status]++
	}

	id, err := doc.GenerateCanonicalID()
	if err != nil {
		return nil, fmt.Errorf("vexgen: canonical id: %w", err)
	}
	// Make the document ID specific to the product so re-runs for different
	// SBOMs never collide even with identical statements.
	doc.ID = id + "-" + sanitize(productID)
	return res, nil
}

func applyGuardrails(a llm.Assessment, r *evidence.Report, opts Options) (llm.Assessment, []string) {
	var notes []string
	downgrade := func(reason string) {
		notes = append(notes, reason)
		a.Reasoning = strings.TrimSpace(reason + ". Original verdict: " + string(a.Status) + " (confidence " + fmtConf(a.Confidence) + "). " + a.Reasoning)
		a.Status = vex.StatusUnderInvestigation
		a.Justification, a.ImpactStatement, a.ActionStatement = "", "", ""
	}
	if a.Status == vex.StatusNotAffected || a.Status == vex.StatusFixed {
		if a.Confidence < opts.MinConfidence {
			downgrade(fmt.Sprintf("confidence %s below minimum %s", fmtConf(a.Confidence), fmtConf(opts.MinConfidence)))
			return a, notes
		}
	}
	if a.Status == vex.StatusNotAffected && !opts.AllowUnsupportedNotAffected && len(r.StrongItems()) == 0 {
		downgrade("not_affected requires strong deterministic evidence (none collected)")
		return a, notes
	}
	if a.Status == vex.StatusFixed && !r.Has(evidence.KindVersionFixed) && !opts.AllowUnsupportedNotAffected {
		downgrade("fixed claimed but installed version is not at or above the fixed version")
		return a, notes
	}
	return a, notes
}

func statusNotes(a llm.Assessment, r *evidence.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "provider=%s confidence=%s", orUnknown(a.Provider), fmtConf(a.Confidence))
	if len(a.EvidenceRefs) > 0 {
		fmt.Fprintf(&b, " evidence=%s", strings.Join(a.EvidenceRefs, ","))
	} else if strong := r.StrongItems(); len(strong) > 0 {
		kinds := make([]string, 0, len(strong))
		for _, s := range strong {
			kinds = append(kinds, string(s.Kind))
		}
		fmt.Fprintf(&b, " evidence=%s", strings.Join(kinds, ","))
	}
	if a.Reasoning != "" {
		b.WriteString(" | " + a.Reasoning)
	}
	return b.String()
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func fmtConf(c float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", c), "0"), ".")
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Marshal renders the document as indented JSON.
func Marshal(doc *vex.VEX) ([]byte, error) {
	var buf bytes.Buffer
	if err := doc.ToJSON(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
