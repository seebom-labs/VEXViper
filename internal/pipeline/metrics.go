package pipeline

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/seebom-labs/vexviper/internal/llm"
)

// Metrics collects process-wide counters and renders them in the Prometheus
// text exposition format (no client library: the set is small and static).
// A nil *Metrics is a no-op sink.
type Metrics struct {
	mu sync.Mutex

	runs, runErrors    int
	findings, skipped  int
	settled, deferred  int
	statements         map[vex.Status]int
	guardrails         int
	uploads            int
	usage              llm.Usage
	passes, passErrors int
	lastPass           time.Time
	lastPassDuration   time.Duration
	started            time.Time
}

// NewMetrics returns an empty collector.
func NewMetrics() *Metrics {
	return &Metrics{statements: map[vex.Status]int{}, started: time.Now()}
}

// RecordRun accounts one pipeline run (err != nil counts as a failed run).
func (m *Metrics) RecordRun(out *Outcome, err error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs++
	if err != nil {
		m.runErrors++
	}
	if out == nil {
		return
	}
	m.findings += out.Findings
	m.skipped += out.Skipped
	m.settled += out.Settled
	m.deferred += out.Deferred
	m.guardrails += len(out.Guardrails)
	for s, n := range out.Counts {
		m.statements[s] += n
	}
	if out.Upload != nil {
		m.uploads++
	}
	m.usage.Add(out.Usage)
}

// RecordPass accounts one watch pass.
func (m *Metrics) RecordPass(d time.Duration, err error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.passes++
	if err != nil {
		m.passErrors++
	}
	m.lastPass = time.Now()
	m.lastPassDuration = d
}

// LastPass returns when the most recent watch pass finished (zero = none yet).
func (m *Metrics) LastPass() time.Time {
	if m == nil {
		return time.Time{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastPass
}

// WriteTo renders the metrics in Prometheus text format.
func (m *Metrics) WriteTo(w io.Writer) (int64, error) {
	if m == nil {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cw := &countingWriter{w: w}
	p := func(name, typ, help string, v any, labels ...string) {
		fmt.Fprintf(cw, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		lbl := ""
		if len(labels) > 0 {
			lbl = "{" + labels[0] + "}"
		}
		fmt.Fprintf(cw, "%s%s %v\n", name, lbl, v)
	}
	p("vexviper_runs_total", "counter", "Pipeline runs (one per SBOM).", m.runs)
	p("vexviper_run_errors_total", "counter", "Pipeline runs that failed.", m.runErrors)
	p("vexviper_findings_assessed_total", "counter", "Findings that went through assessment.", m.findings)
	p("vexviper_findings_skipped_total", "counter", "Findings skipped because they already had a VEX status.", m.skipped)
	p("vexviper_findings_settled_kept_total", "counter", "Settled verdicts kept on --regenerate.", m.settled)
	p("vexviper_findings_deferred_total", "counter", "Findings left without statement because the provider budget was exhausted.", m.deferred)
	p("vexviper_guardrails_applied_total", "counter", "Assessments downgraded by a guardrail.", m.guardrails)
	p("vexviper_uploads_total", "counter", "VEX documents uploaded to BOMHort.", m.uploads)
	fmt.Fprint(cw, "# HELP vexviper_statements_total VEX statements emitted by status.\n# TYPE vexviper_statements_total counter\n")
	statuses := make([]string, 0, len(m.statements))
	for s := range m.statements {
		statuses = append(statuses, string(s))
	}
	sort.Strings(statuses)
	for _, s := range statuses {
		fmt.Fprintf(cw, "vexviper_statements_total{status=%q} %d\n", s, m.statements[vex.Status(s)])
	}
	p("vexviper_provider_calls_total", "counter", "Provider invocations.", m.usage.Calls)
	fmt.Fprint(cw, "# HELP vexviper_provider_tokens_total Tokens reported by the provider.\n# TYPE vexviper_provider_tokens_total counter\n")
	fmt.Fprintf(cw, "vexviper_provider_tokens_total{kind=\"prompt\"} %d\nvexviper_provider_tokens_total{kind=\"completion\"} %d\n", m.usage.PromptTokens, m.usage.CompletionTokens)
	p("vexviper_provider_premium_requests_total", "counter", "GitHub Copilot premium requests consumed.", fmt.Sprintf("%.2f", m.usage.PremiumRequests))
	p("vexviper_provider_seconds_total", "counter", "Wall time spent waiting on the provider.", fmt.Sprintf("%.3f", m.usage.Duration.Seconds()))
	p("vexviper_cache_hits_total", "counter", "Assessments served from the assessment cache.", m.usage.CacheHits)
	p("vexviper_watch_passes_total", "counter", "Watch passes completed.", m.passes)
	p("vexviper_watch_pass_errors_total", "counter", "Watch passes that reported errors.", m.passErrors)
	last := 0.0
	if !m.lastPass.IsZero() {
		last = float64(m.lastPass.Unix())
	}
	p("vexviper_watch_last_pass_timestamp_seconds", "gauge", "Unix time the last watch pass finished (0 = none yet).", fmt.Sprintf("%.0f", last))
	p("vexviper_watch_last_pass_duration_seconds", "gauge", "Duration of the last watch pass.", fmt.Sprintf("%.3f", m.lastPassDuration.Seconds()))
	p("vexviper_process_start_time_seconds", "gauge", "Unix time the process started.", m.started.Unix())
	return cw.n, cw.err
}

type countingWriter struct {
	w   io.Writer
	n   int64
	err error
}

func (c *countingWriter) Write(b []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.w.Write(b)
	c.n += int64(n)
	c.err = err
	return n, err
}

// Handler serves /metrics and /healthz. The health check fails when no
// watch pass finished within maxAge (0 = only check that the process is up).
func (m *Metrics) Handler(maxAge time.Duration) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = m.WriteTo(w)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		last := m.LastPass()
		if maxAge > 0 && !last.IsZero() && time.Since(last) > maxAge {
			http.Error(w, fmt.Sprintf("last watch pass finished %s ago (max %s)", time.Since(last).Round(time.Second), maxAge), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	return mux
}
