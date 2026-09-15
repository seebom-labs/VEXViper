package vexgen

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/seebom-labs/vexviper/internal/evidence"
	"github.com/seebom-labs/vexviper/internal/llm"
	"github.com/seebom-labs/vexviper/internal/osv"
	"github.com/seebom-labs/vexviper/internal/source"
)

var update = flag.Bool("update", false, "update golden files")

func fixedTime() time.Time { return time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC) }

func entry(vuln, purl string, a llm.Assessment, items ...evidence.Item) Entry {
	return Entry{
		Report: &evidence.Report{
			Finding: source.Finding{VulnID: vuln, PURL: purl, FixedVersion: "v0.17.0", Summary: "summary of " + vuln, PackageName: "pkg"},
			Items:   items,
		},
		Assessment: a,
	}
}

func strong(k evidence.Kind) evidence.Item {
	return evidence.Item{Kind: k, Strong: true, Summary: string(k)}
}
func weak(k evidence.Kind) evidence.Item { return evidence.Item{Kind: k, Summary: string(k)} }

func TestBuildGolden(t *testing.T) {
	entries := []Entry{
		entry("GO-2023-2102", "pkg:golang/golang.org/x/net@v0.16.0",
			llm.Assessment{Status: vex.StatusNotAffected, Justification: vex.VulnerableCodeNotInExecutePath, ImpactStatement: "not reachable", Confidence: 0.85, Reasoning: "no call path", EvidenceRefs: []string{"govulncheck_not_reachable"}, Provider: "heuristic"},
			strong(evidence.KindNotReachable)),
		entry("GHSA-aaaa", "pkg:npm/%40angular/cdk@22.0.6",
			llm.Assessment{Status: vex.StatusFixed, Confidence: 0.95, Reasoning: "version ok", Provider: "heuristic"},
			strong(evidence.KindVersionFixed)),
		entry("CVE-2026-0001", "pkg:golang/github.com/foo/bar@v1.0.0",
			llm.Assessment{Status: vex.StatusAffected, ActionStatement: "Upgrade pkg to v0.17.0 or later.", Confidence: 0.9, Reasoning: "reachable", Provider: "openai:gpt"},
			strong(evidence.KindReachable)),
		entry("CVE-2026-0002", "pkg:golang/github.com/foo/baz@v1.0.0",
			llm.Assessment{Status: vex.StatusUnderInvestigation, Confidence: 0.3, Reasoning: "unclear", Provider: "heuristic"}),
	}
	entries[0].Report.OSV = &osv.Vulnerability{ID: "GO-2023-2102", Aliases: []string{"CVE-2023-39325"}}

	res, err := Build("sbom-123", entries, Options{
		Author: "ACME Security", AuthorRole: "automated triage", Supplier: "ACME", Tooling: "vexviper/test",
		Namespace: "https://vex.example.com/docs", MinConfidence: 0.6, Now: fixedTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Guardrails) != 0 {
		t.Fatalf("unexpected guardrails: %+v", res.Guardrails)
	}
	if res.Counts[vex.StatusNotAffected] != 1 || res.Counts[vex.StatusFixed] != 1 || res.Counts[vex.StatusAffected] != 1 || res.Counts[vex.StatusUnderInvestigation] != 1 {
		t.Fatalf("counts = %v", res.Counts)
	}
	got, err := Marshal(res.Document)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "golden.openvex.json")
	if *update {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("golden mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// Check BOMHort-relevant invariants on the parsed output.
	var parsed struct {
		Context    string `json:"@context"`
		ID         string `json:"@id"`
		Statements []struct {
			Vulnerability struct {
				Name    string   `json:"name"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerability"`
			Products []struct {
				ID          string            `json:"@id"`
				Identifiers map[string]string `json:"identifiers"`
			} `json:"products"`
			Status string `json:"status"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(parsed.Context, "https://openvex.dev/ns") || !strings.HasPrefix(parsed.ID, "https://vex.example.com/docs/") || !strings.HasSuffix(parsed.ID, "-sbom-123") {
		t.Errorf("context/id = %q %q", parsed.Context, parsed.ID)
	}
	if len(parsed.Statements) != 4 || parsed.Statements[0].Vulnerability.Name != "CVE-2026-0001" {
		t.Fatalf("statements not sorted by vuln id: %+v", parsed.Statements)
	}
	for _, s := range parsed.Statements {
		p := s.Products[0]
		if p.ID != p.Identifiers["purl"] || !strings.HasPrefix(p.ID, "pkg:") {
			t.Errorf("product id/purl mismatch: %+v", p)
		}
	}
	if a := parsed.Statements[3].Vulnerability.Aliases; len(a) != 1 || a[0] != "CVE-2023-39325" {
		t.Errorf("aliases = %v", a)
	}
}

func TestGuardrails(t *testing.T) {
	opts := Options{MinConfidence: 0.6, Now: fixedTime}
	cases := []struct {
		name   string
		e      Entry
		want   vex.Status
		reason string
	}{
		{"low confidence not_affected", entry("V1", "pkg:npm/a@1", llm.Assessment{Status: vex.StatusNotAffected, Justification: vex.ComponentNotPresent, Confidence: 0.4}, strong(evidence.KindNotReachable)), vex.StatusUnderInvestigation, "below minimum"},
		{"low confidence fixed", entry("V2", "pkg:npm/a@1", llm.Assessment{Status: vex.StatusFixed, Confidence: 0.1}, strong(evidence.KindVersionFixed)), vex.StatusUnderInvestigation, "below minimum"},
		{"not_affected without strong evidence", entry("V3", "pkg:npm/a@1", llm.Assessment{Status: vex.StatusNotAffected, Justification: vex.ComponentNotPresent, Confidence: 0.99}, weak(evidence.KindImportNotFound)), vex.StatusUnderInvestigation, "strong deterministic evidence"},
		{"fixed without version evidence", entry("V4", "pkg:npm/a@1", llm.Assessment{Status: vex.StatusFixed, Confidence: 0.99}), vex.StatusUnderInvestigation, "fixed claimed"},
		{"invalid assessment", entry("V5", "pkg:npm/a@1", llm.Assessment{Status: "bogus", Confidence: 0.5}), vex.StatusUnderInvestigation, "invalid assessment"},
		{"low confidence affected stays", entry("V6", "pkg:npm/a@1", llm.Assessment{Status: vex.StatusAffected, Confidence: 0.2}), vex.StatusAffected, ""},
		{"llm normalization", entry("V7", "pkg:npm/a@1", llm.Assessment{Status: "Not-Affected", Justification: "Vulnerable_Code_Not_In_Execute_Path", ActionStatement: "junk", Confidence: 0.9}, strong(evidence.KindNotReachable)), vex.StatusNotAffected, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Build("p", []Entry{tc.e}, opts)
			if err != nil {
				t.Fatal(err)
			}
			st := res.Document.Statements[0]
			if st.Status != tc.want {
				t.Fatalf("status = %s want %s (guardrails %+v)", st.Status, tc.want, res.Guardrails)
			}
			if tc.reason == "" {
				if len(res.Guardrails) != 0 {
					t.Fatalf("unexpected guardrails %+v", res.Guardrails)
				}
				return
			}
			if len(res.Guardrails) == 0 || !strings.Contains(res.Guardrails[0].Reason, tc.reason) {
				t.Fatalf("guardrails = %+v, want reason containing %q", res.Guardrails, tc.reason)
			}
			if !strings.Contains(st.StatusNotes, "Original verdict") && tc.name != "invalid assessment" {
				t.Fatalf("status notes should mention original verdict: %q", st.StatusNotes)
			}
			if err := st.Validate(); err != nil {
				t.Fatalf("downgraded statement invalid: %v", err)
			}
		})
	}

	// AllowUnsupportedNotAffected disables the evidence guardrail.
	res, err := Build("p", []Entry{entry("V3", "pkg:npm/a@1", llm.Assessment{Status: vex.StatusNotAffected, Justification: vex.ComponentNotPresent, Confidence: 0.99})}, Options{MinConfidence: 0.6, AllowUnsupportedNotAffected: true, Now: fixedTime})
	if err != nil || res.Document.Statements[0].Status != vex.StatusNotAffected {
		t.Fatalf("allow flag ignored: %+v %v", res.Guardrails, err)
	}
}

func TestBuildEmptyAndDefaults(t *testing.T) {
	res, err := Build("p", nil, Options{Now: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if res.Document.Author != "VEXViper" || res.Document.Tooling != "vexviper" || len(res.Document.Statements) != 0 {
		t.Fatalf("defaults = %+v", res.Document.Metadata)
	}
	if !strings.HasPrefix(res.Document.ID, "https://") {
		t.Fatalf("id = %q", res.Document.ID)
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("pkg:npm/%40angular/cdk@22.0.6"); got != "pkg_npm__40angular_cdk_22.0.6" {
		t.Fatalf("sanitize = %q", got)
	}
	if fmtConf(0.5) != "0.5" || fmtConf(1) != "1" || fmtConf(0.85) != "0.85" || fmtConf(0) != "0" {
		t.Fatal("fmtConf")
	}
}
