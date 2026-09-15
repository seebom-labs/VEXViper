package pipeline

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/seebom-labs/vexviper/internal/bomhort"
	"github.com/seebom-labs/vexviper/internal/llm"
)

func TestMetricsNilIsNoop(t *testing.T) {
	var m *Metrics
	m.RecordRun(nil, nil)
	m.RecordPass(time.Second, nil)
	if !m.LastPass().IsZero() {
		t.Fatal("nil LastPass")
	}
	if n, err := m.WriteTo(&strings.Builder{}); n != 0 || err != nil {
		t.Fatalf("WriteTo = %d %v", n, err)
	}
}

func TestMetricsExpositionAndHandler(t *testing.T) {
	m := NewMetrics()
	m.RecordRun(&Outcome{
		Findings: 3, Skipped: 1, Settled: 1, Deferred: 1,
		Counts: map[vex.Status]int{vex.StatusAffected: 1, vex.StatusNotAffected: 1},
		Upload: &bomhort.UploadResult{Status: "accepted"},
		Usage:  llm.Usage{Calls: 2, PromptTokens: 100, CompletionTokens: 20, PremiumRequests: 0.66, CacheHits: 1, Duration: 1500 * time.Millisecond},
	}, nil)
	m.RecordRun(nil, errors.New("boom"))
	m.RecordPass(2*time.Second, nil)

	var sb strings.Builder
	if _, err := m.WriteTo(&sb); err != nil {
		t.Fatal(err)
	}
	body := sb.String()
	for _, want := range []string{
		"vexviper_runs_total 2\n",
		"vexviper_run_errors_total 1\n",
		"vexviper_findings_assessed_total 3\n",
		"vexviper_findings_deferred_total 1\n",
		"vexviper_uploads_total 1\n",
		"vexviper_statements_total{status=\"affected\"} 1\n",
		"vexviper_statements_total{status=\"not_affected\"} 1\n",
		"vexviper_provider_calls_total 2\n",
		"vexviper_provider_tokens_total{kind=\"prompt\"} 100\n",
		"vexviper_provider_premium_requests_total 0.66\n",
		"vexviper_provider_seconds_total 1.500\n",
		"vexviper_cache_hits_total 1\n",
		"vexviper_watch_passes_total 1\n",
		"vexviper_watch_last_pass_duration_seconds 2.000\n",
		"# TYPE vexviper_watch_last_pass_timestamp_seconds gauge\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}

	h := m.Handler(time.Hour)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != 200 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") || !strings.Contains(rr.Body.String(), "vexviper_runs_total") {
		t.Fatalf("/metrics: %d %s", rr.Code, rr.Header().Get("Content-Type"))
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != 200 {
		t.Fatalf("/healthz: %d %s", rr.Code, rr.Body.String())
	}

	// Stale pass → 503; no pass yet → still healthy (starting up).
	m.mu.Lock()
	m.lastPass = time.Now().Add(-2 * time.Hour)
	m.mu.Unlock()
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("stale /healthz: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	NewMetrics().Handler(time.Minute).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != 200 {
		t.Fatalf("fresh /healthz: %d", rr.Code)
	}
}
