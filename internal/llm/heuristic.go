package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/seebom-labs/vexviper/internal/evidence"
)

// Heuristic is a rules-only provider. It never needs network access or
// credentials and doubles as the safety net when an LLM is unavailable.
//
// Rules, first match wins:
//  1. version_fixed                              → fixed (0.95)
//  2. govulncheck_reachable                      → affected (0.9)
//  3. govulncheck_not_reachable [strong]         → not_affected / vulnerable_code_not_in_execute_path (0.85)
//  4. import_not_found + transitive dependency   → under_investigation (0.5)  (too weak alone)
//  5. symbol_not_referenced + direct dependency  → under_investigation (0.55)
//  6. everything else                            → under_investigation (0.3)
type Heuristic struct{}

// Name implements Provider.
func (Heuristic) Name() string { return "heuristic" }

// Assess implements Provider.
func (h Heuristic) Assess(_ context.Context, req Request) (Assessment, error) {
	r := req.Report
	if r == nil {
		return Assessment{}, fmt.Errorf("heuristic: nil report")
	}
	a := Assessment{Provider: h.Name()}
	switch {
	case r.Has(evidence.KindVersionFixed):
		a.Status = vex.StatusFixed
		a.Confidence = 0.95
		a.Reasoning = "The installed version is at or above the version that fixes the vulnerability."
		a.EvidenceRefs = []string{string(evidence.KindVersionFixed)}
	case r.Has(evidence.KindReachable):
		a.Status = vex.StatusAffected
		a.Confidence = 0.9
		a.Reasoning = "govulncheck found a call path from product code to a vulnerable symbol."
		a.ActionStatement = actionFor(r)
		a.EvidenceRefs = []string{string(evidence.KindReachable)}
	case hasStrong(r, evidence.KindNotReachable):
		a.Status = vex.StatusNotAffected
		a.Justification = vex.VulnerableCodeNotInExecutePath
		a.ImpactStatement = "govulncheck symbol-level analysis shows the vulnerable module is present but no vulnerable symbol is reachable from the product's code."
		a.Confidence = 0.85
		a.Reasoning = "Static call-graph analysis found no path to the vulnerable code."
		a.EvidenceRefs = []string{string(evidence.KindNotReachable)}
	case r.Has(evidence.KindImportNotFound) && r.Has(evidence.KindTransitive):
		a.Status = vex.StatusUnderInvestigation
		a.Confidence = 0.5
		a.Reasoning = "The vulnerable package is only a transitive dependency and is not imported by product code, but reachability through intermediaries was not proven."
		a.EvidenceRefs = []string{string(evidence.KindImportNotFound), string(evidence.KindTransitive)}
	case r.Has(evidence.KindSymbolNotReferenced):
		a.Status = vex.StatusUnderInvestigation
		a.Confidence = 0.55
		a.Reasoning = "Product code imports the vulnerable package but does not reference the vulnerable symbols by name; a manual review is required."
		a.EvidenceRefs = []string{string(evidence.KindSymbolNotReferenced)}
	default:
		a.Status = vex.StatusUnderInvestigation
		a.Confidence = 0.3
		a.Reasoning = "Insufficient deterministic evidence to decide exploitability."
	}
	return a, nil
}

func hasStrong(r *evidence.Report, k evidence.Kind) bool {
	for _, it := range r.Items {
		if it.Kind == k && it.Strong {
			return true
		}
	}
	return false
}

func actionFor(r *evidence.Report) string {
	name := r.Finding.PackageName
	if name == "" {
		name = r.Finding.PURL
	}
	if fv := strings.TrimSpace(r.Finding.FixedVersion); fv != "" {
		return fmt.Sprintf("Upgrade %s to %s or later.", name, fv)
	}
	return fmt.Sprintf("Upgrade %s to a version that fixes %s.", name, r.Finding.VulnID)
}
