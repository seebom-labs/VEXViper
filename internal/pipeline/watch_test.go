package pipeline

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mfahlandt/vexviper/internal/assesscache"
	"github.com/mfahlandt/vexviper/internal/bomhort"
	"github.com/mfahlandt/vexviper/internal/llm"
)

type fakeLister struct {
	sboms []bomhort.SBOM
	err   error
	calls int
}

func (l *fakeLister) AllSBOMs(context.Context) ([]bomhort.SBOM, error) {
	l.calls++
	return l.sboms, l.err
}

func TestWatchOnceAndState(t *testing.T) {
	bh := bomhortFixture(t)
	bh.sbom.VulnCount = 3
	bh.sbom.IngestedAt = "2025-01-01T00:00:00Z"
	mock := &llm.Mock{Default: &llm.Assessment{Status: "under_investigation", Confidence: 0.4}}
	p := newTestPipeline(t, bh, mock, nil)
	lister := &fakeLister{sboms: []bomhort.SBOM{bh.sbom, {ID: "empty", VulnCount: 0}}}
	stateFile := filepath.Join(t.TempDir(), "state", "watch.json")
	out := t.TempDir()

	opts := WatchOptions{StateFile: stateFile, OutDir: out, Upload: true, Once: true, SkipZero: true}
	if err := p.Watch(context.Background(), lister, opts); err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 2 || len(bh.uploads) != 1 {
		t.Fatalf("calls=%d uploads=%d", len(mock.Calls), len(bh.uploads))
	}
	st, err := LoadWatchState(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Processed["sbom-1"] != "3@2025-01-01T00:00:00Z" || st.Processed["empty"] != "0@" || st.LastRun.IsZero() {
		t.Fatalf("state = %+v", st)
	}

	// Second pass: nothing changed → nothing processed.
	if err := p.Watch(context.Background(), lister, opts); err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 2 {
		t.Fatalf("re-processed unchanged sbom: calls=%d", len(mock.Calls))
	}

	// Vuln count changed → processed again.
	lister.sboms[0].VulnCount = 4
	if err := p.Watch(context.Background(), lister, opts); err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 4 {
		t.Fatalf("changed sbom not re-processed: calls=%d", len(mock.Calls))
	}

	// ReassessAfter: unchanged fingerprint but last run is older than the TTL → re-run.
	st, _ = LoadWatchState(stateFile)
	if st.ProcessedAt["sbom-1"].IsZero() {
		t.Fatalf("ProcessedAt not recorded: %+v", st)
	}
	st.ProcessedAt["sbom-1"] = time.Now().Add(-48 * time.Hour)
	if err := st.Save(stateFile); err != nil {
		t.Fatal(err)
	}
	opts.ReassessAfter = 24 * time.Hour
	if err := p.Watch(context.Background(), lister, opts); err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 6 {
		t.Fatalf("due sbom not re-processed: calls=%d", len(mock.Calls))
	}
	// Immediately again: not due anymore.
	if err := p.Watch(context.Background(), lister, opts); err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 6 {
		t.Fatalf("re-processed sbom that was not due: calls=%d", len(mock.Calls))
	}
}

func TestWatchLoopStopsOnCancel(t *testing.T) {
	bh := bomhortFixture(t)
	p := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	lister := &fakeLister{err: errors.New("bomhort down")}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := p.Watch(ctx, lister, WatchOptions{Interval: 20 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if lister.calls < 2 {
		t.Fatalf("expected multiple passes, got %d", lister.calls)
	}
}

func TestWatchOnceReportsRunErrors(t *testing.T) {
	bh := bomhortFixture(t)
	p := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	lister := &fakeLister{sboms: []bomhort.SBOM{{ID: "ghost", VulnCount: 1}}}
	err := p.Watch(context.Background(), lister, WatchOptions{Once: true})
	if err == nil {
		t.Fatal("expected error for unknown sbom")
	}
}

func TestLoadWatchStateBad(t *testing.T) {
	f := filepath.Join(t.TempDir(), "s.json")
	if err := (&WatchState{}).Save(f); err != nil {
		t.Fatal(err)
	}
	st, err := LoadWatchState(f)
	if err != nil || st.Processed == nil {
		t.Fatalf("st=%+v err=%v", st, err)
	}
	if st, err := LoadWatchState(""); err != nil || st == nil {
		t.Fatal("empty path must yield empty state")
	}
}

func TestWatchBudgetResetsPerPassAndRetriesDeferred(t *testing.T) {
	bh := bomhortFixture(t)
	mock := &llm.Mock{Default: &llm.Assessment{Status: "affected", ActionStatement: "upgrade", Confidence: 0.9, Reasoning: "r", Usage: llm.Usage{Calls: 1}}}
	p := newTestPipeline(t, bh, mock, nil)
	p.Budget = llm.NewBudget(llm.BudgetLimits{MaxCalls: 1})
	p.Cache = assesscache.New(filepath.Join(t.TempDir(), "assessments"), 0)
	lister := &fakeLister{sboms: []bomhort.SBOM{bh.sbom}}
	stateFile := filepath.Join(t.TempDir(), "watch.json")
	opts := WatchOptions{StateFile: stateFile, Once: true}

	if err := p.Watch(context.Background(), lister, opts); err != nil {
		t.Fatal(err)
	}
	st, _ := LoadWatchState(stateFile)
	if _, ok := st.Processed["sbom-1"]; ok {
		t.Fatalf("partially processed sbom must not be marked processed: %+v", st.Processed)
	}
	if len(mock.Calls) != 1 || st.LastPassUsage.Calls != 1 {
		t.Fatalf("calls=%d usage=%+v", len(mock.Calls), st.LastPassUsage)
	}

	// Next pass: budget reset, first verdict from cache, the remaining finding gets assessed.
	if err := p.Watch(context.Background(), lister, opts); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadWatchState(stateFile)
	if len(mock.Calls) != 2 || st.Processed["sbom-1"] == "" || st.Usage.Calls != 2 {
		t.Fatalf("second pass calls=%d state=%+v", len(mock.Calls), st)
	}
}

// multiBOMHort serves several SBOM ids from one fixture and is safe for
// concurrent uploads.
type multiBOMHort struct {
	*fakeBOMHort
	ids map[string]bool
	mu  sync.Mutex
}

func (m *multiBOMHort) FindSBOM(_ context.Context, ref string) (bomhort.SBOM, error) {
	if !m.ids[ref] {
		return bomhort.SBOM{}, errors.New("not found")
	}
	s := m.sbom
	s.ID = ref
	return s, nil
}

func (m *multiBOMHort) UploadVEX(ctx context.Context, name string, doc []byte) (bomhort.UploadResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fakeBOMHort.UploadVEX(ctx, name, doc)
}

// gauge counts concurrent Assess calls.
type gauge struct {
	llm.Provider
	mu       sync.Mutex
	inflight int
	peak     int
}

func (g *gauge) Assess(ctx context.Context, req llm.Request) (llm.Assessment, error) {
	g.mu.Lock()
	g.inflight++
	if g.inflight > g.peak {
		g.peak = g.inflight
	}
	g.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	defer func() { g.mu.Lock(); g.inflight--; g.mu.Unlock() }()
	return g.Provider.Assess(ctx, req)
}

func TestWatchConcurrency(t *testing.T) {
	bh := bomhortFixture(t)
	multi := &multiBOMHort{fakeBOMHort: bh, ids: map[string]bool{}}
	var sboms []bomhort.SBOM
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("sbom-%d", i)
		multi.ids[id] = true
		s := bh.sbom
		s.ID = id
		sboms = append(sboms, s)
	}
	mock := &llm.Mock{Default: &llm.Assessment{Status: "affected", ActionStatement: "upgrade", Confidence: 0.9, Reasoning: "r", Usage: llm.Usage{Calls: 1}}}
	g := &gauge{Provider: mock}
	p := newTestPipeline(t, bh, g, nil)
	p.BOMHort = multi
	p.Budget = llm.NewBudget(llm.BudgetLimits{MaxCalls: 100})
	lister := &fakeLister{sboms: sboms}
	stateFile := filepath.Join(t.TempDir(), "watch.json")

	if err := p.Watch(context.Background(), lister, WatchOptions{StateFile: stateFile, Once: true, Upload: true, Concurrency: 4}); err != nil {
		t.Fatal(err)
	}
	if g.peak < 2 {
		t.Fatalf("expected parallel assessments, peak = %d", g.peak)
	}
	st, _ := LoadWatchState(stateFile)
	if len(st.Processed) != 6 || len(bh.uploads) != 6 || st.LastPassUsage.Calls != 12 || p.Budget.Spent().Calls != 12 {
		t.Fatalf("processed=%d uploads=%d usage=%+v budget=%+v", len(st.Processed), len(bh.uploads), st.LastPassUsage, p.Budget.Spent())
	}

	// Cancellation stops feeding the queue; workers drain and Watch returns.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lister2 := &fakeLister{sboms: sboms}
	err := p.Watch(ctx, lister2, WatchOptions{StateFile: filepath.Join(t.TempDir(), "w.json"), Once: true, Concurrency: 2})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
