package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openvex/go-vex/pkg/vex"
)

// SystemPrompt frames the model as a conservative VEX analyst.
const SystemPrompt = `You are a senior application security engineer producing OpenVEX (Vulnerability Exploitability eXchange) statements.
You receive one vulnerability finding for one package in a software product together with deterministic evidence gathered from the product's SBOM, OSV and source repository.

Decide the OpenVEX status for this (vulnerability, product) pair:
- "not_affected": the product is NOT exploitable. REQUIRES a justification from: component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist. Only choose this when the evidence supports it (e.g. govulncheck reports no reachable vulnerable symbol, or the vulnerable package/symbol is not used).
- "fixed": the installed version already contains the fix.
- "affected": the product is (likely) exploitable. Provide an action_statement (how to remediate, e.g. upgrade to the fixed version).
- "under_investigation": evidence is insufficient to decide. Prefer this over guessing.

Rules:
- Be conservative. False "not_affected" claims are dangerous; when in doubt use "under_investigation" with a lower confidence.
- Never invent evidence. Reference the evidence kinds you relied on in evidence_refs.
- For non-Go ecosystems (npm, pypi, cargo, gem, composer, maven, nuget, pub) there is no call-graph analysis: "package_imported", "import_not_found", "dev_dependency", "dependency_path" and "manifest_not_found" describe how the package is declared, resolved and imported, not whether the vulnerable code executes — unless marked [strong]. A [strong] "dev_dependency" means the lockfile resolves the package outside the runtime closure (not_affected / vulnerable_code_not_present). A [strong] "import_not_found" or "symbol_not_referenced" means the lockfile graph proves product code is the package's only possible caller and it never imports it / never references the advisory's vulnerable functions (not_affected / vulnerable_code_not_in_execute_path). Without [strong], these items alone never justify not_affected.
- confidence is your calibrated probability (0..1) that the status is correct.
- reasoning: 1-3 sentences, plain text, no markdown.
- Respond with a single JSON object matching the schema. No prose before or after.`

// BuildUserPrompt renders the request as a compact, deterministic prompt.
func BuildUserPrompt(req Request) string {
	var b strings.Builder
	r := req.Report
	f := r.Finding
	fmt.Fprintf(&b, "PRODUCT: %s", req.ProductName)
	if req.ProductRepo != "" {
		fmt.Fprintf(&b, " (repository: %s)", req.ProductRepo)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "VULNERABILITY: %s\n", f.VulnID)
	fmt.Fprintf(&b, "PACKAGE (PURL): %s\n", f.PURL)
	if f.Severity != "" {
		fmt.Fprintf(&b, "SEVERITY: %s\n", f.Severity)
	}
	if f.Summary != "" {
		fmt.Fprintf(&b, "SUMMARY: %s\n", f.Summary)
	}
	if f.FixedVersion != "" {
		fmt.Fprintf(&b, "FIXED VERSION: %s\n", f.FixedVersion)
	}
	if r.OSV != nil {
		if r.OSV.Details != "" {
			fmt.Fprintf(&b, "\nOSV DETAILS:\n%s\n", truncate(r.OSV.Details, 2000))
		}
		if imports := r.OSV.VulnerableImports(); len(imports) > 0 {
			b.WriteString("\nVULNERABLE PACKAGES/SYMBOLS:\n")
			for _, im := range imports {
				fmt.Fprintf(&b, "- %s: %s\n", im.Path, truncate(strings.Join(im.Symbols, ", "), 400))
			}
		}
	}
	b.WriteString("\nEVIDENCE:\n")
	if len(r.Items) == 0 {
		b.WriteString("- (none)\n")
	}
	for _, it := range r.Items {
		strong := ""
		if it.Strong {
			strong = " [strong]"
		}
		fmt.Fprintf(&b, "- %s%s: %s\n", it.Kind, strong, it.Summary)
		if len(it.Details) > 0 {
			if d, err := json.Marshal(it.Details); err == nil {
				fmt.Fprintf(&b, "  details: %s\n", truncate(string(d), 600))
			}
		}
	}
	b.WriteString("\nRESPONSE JSON SCHEMA:\n")
	schema, _ := json.Marshal(JSONSchema)
	b.Write(schema)
	b.WriteString("\n\nValid status values: " + strings.Join(vex.Statuses(), ", "))
	b.WriteString("\nValid justification values: " + strings.Join(vex.Justifications(), ", "))
	b.WriteString("\n\nReturn only the JSON object.")
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
