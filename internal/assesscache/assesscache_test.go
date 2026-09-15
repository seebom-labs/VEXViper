package assesscache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/seebom-labs/vexviper/internal/evidence"
	"github.com/seebom-labs/vexviper/internal/llm"
	"github.com/seebom-labs/vexviper/internal/osv"
	"github.com/seebom-labs/vexviper/internal/source"
)

func report(items ...evidence.Item) *evidence.Report {
	return &evidence.Report{
		Finding: source.Finding{VulnID: "GO-2025-0001", PURL: "pkg:golang/x@v1", PackageVersion: "v1", FixedVersion: "v2"},
		Items:   items,
		OSV:     &osv.Vulnerability{ID: "GO-2025-0001", Modified: "2026-01-01T00:00:00Z"},
	}
}

func TestFingerprintStableAcrossPathsAndOrder(t *testing.T) {
	a := report(
		evidence.Item{Kind: evidence.KindNotReachable, Strong: true, Summary: "/tmp/clone-a: not reachable", Details: map[string]any{"path": "/tmp/a"}},
		evidence.Item{Kind: evidence.KindTransitive, Summary: "direct"},
	)
	b := report(
		evidence.Item{Kind: evidence.KindTransitive, Summary: "transitive"},
		evidence.Item{Kind: evidence.KindNotReachable, Strong: true, Summary: "/var/clone-b: not reachable"},
	)
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("fingerprint must ignore summaries, details and order")
	}
	c := report(evidence.Item{Kind: evidence.KindNotReachable, Strong: false})
	if Fingerprint(a) == Fingerprint(c) {
		t.Fatal("strength change must alter the fingerprint")
	}
	d := report(a.Items...)
	d.OSV.Modified = "2026-02-01T00:00:00Z"
	if Fingerprint(a) == Fingerprint(d) {
		t.Fatal("OSV modification must alter the fingerprint")
	}
	if Fingerprint(nil) != "" {
		t.Fatal("nil report")
	}
}

func TestKeyFor(t *testing.T) {
	rep := report()
	k := KeyFor("copilot:gpt-5", "abc", "github.com/x/y@v1", rep)
	if k.Commit != "abc" || k.Repo != "" || k.VulnID != "GO-2025-0001" || k.PURL != "pkg:golang/x@v1" || k.Version != Version || k.Evidence == "" {
		t.Fatalf("key = %+v", k)
	}
	k2 := KeyFor("copilot:gpt-5", "", "github.com/x/y@v1", rep)
	if k2.Repo != "github.com/x/y@v1" || k2.hash() == k.hash() {
		t.Fatalf("repo fallback key = %+v", k2)
	}
	if KeyFor("p", "c", "r", nil).VulnID != "" {
		t.Fatal("nil report key")
	}
}

func TestStoreRoundTripTTLAndDisabled(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := New(filepath.Join(t.TempDir(), "assessments"), time.Hour)
	s.Now = func() time.Time { return now }
	k := KeyFor("p", "c", "", report())

	if _, ok := s.Get(k); ok {
		t.Fatal("empty store must miss")
	}
	a := llm.Assessment{Status: vex.StatusNotAffected, Justification: vex.VulnerableCodeNotInExecutePath, Confidence: 0.9, Reasoning: "r", Provider: "p",
		Usage: llm.Usage{Calls: 1, PromptTokens: 100}}
	if err := s.Put(k, a, "product"); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get(k)
	if !ok || got.Status != vex.StatusNotAffected || got.Confidence != 0.9 || got.Provider != "p" {
		t.Fatalf("get = %+v %v", got, ok)
	}
	if !got.Usage.IsZero() {
		t.Fatalf("cached usage must be reset, got %+v", got.Usage)
	}
	// Different provider → different key.
	if _, ok := s.Get(KeyFor("other", "c", "", report())); ok {
		t.Fatal("provider must be part of the key")
	}
	// Expired.
	now = now.Add(2 * time.Hour)
	if _, ok := s.Get(k); ok {
		t.Fatal("expired entry must miss")
	}
	s.TTL = 0
	if _, ok := s.Get(k); !ok {
		t.Fatal("ttl 0 never expires")
	}
	st, err := s.Stats()
	if err != nil || st.Entries != 1 || st.Bytes == 0 {
		t.Fatalf("stats = %+v %v", st, err)
	}
	// Corrupt file → miss.
	os.WriteFile(s.path(k), []byte("{nope"), 0o644)
	if _, ok := s.Get(k); ok {
		t.Fatal("corrupt entry must miss")
	}

	var nilStore *Store
	if nilStore.Enabled() || (&Store{}).Enabled() {
		t.Fatal("nil/zero store must be disabled")
	}
	if err := nilStore.Put(k, a, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := nilStore.Get(k); ok {
		t.Fatal("disabled store must miss")
	}
	if st, err := nilStore.Stats(); err != nil || st.Entries != 0 {
		t.Fatal("disabled stats")
	}
	if st, err := New(filepath.Join(t.TempDir(), "missing"), 0).Stats(); err != nil || st.Entries != 0 {
		t.Fatal("missing dir stats must be empty, not an error")
	}
}
