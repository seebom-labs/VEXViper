package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/seebom-labs/vexviper/internal/evidence"
	"github.com/seebom-labs/vexviper/internal/source"
)

func report(items ...evidence.Item) *evidence.Report {
	return &evidence.Report{
		Finding: source.Finding{VulnID: "GO-2023-2102", PURL: "pkg:golang/golang.org/x/net@v0.16.0", FixedVersion: "v0.17.0", PackageName: "golang.org/x/net", Severity: "HIGH", Summary: "rapid reset"},
		Items:   items,
	}
}

func item(k evidence.Kind, strong bool) evidence.Item {
	return evidence.Item{Kind: k, Strong: strong, Summary: string(k), Details: map[string]any{"x": 1}}
}

func TestAssessmentNormalizeAndValidate(t *testing.T) {
	cases := []struct {
		name string
		in   Assessment
		want vex.Status
		ok   bool
	}{
		{"affected fills action", Assessment{Status: "Affected", Justification: "component_not_present", Confidence: 0.7}, vex.StatusAffected, true},
		{"not affected dash", Assessment{Status: "not-affected", Justification: "Vulnerable-Code-Not-In-Execute-Path", ActionStatement: "x", Confidence: 0.9}, vex.StatusNotAffected, true},
		{"not affected without justification", Assessment{Status: "not_affected", Confidence: 0.9}, vex.StatusNotAffected, false},
		{"fixed strips", Assessment{Status: "fixed", Justification: "component_not_present", ActionStatement: "x", ImpactStatement: "y", Confidence: 1}, vex.StatusFixed, true},
		{"under investigation", Assessment{Status: "under_investigation", Confidence: 0}, vex.StatusUnderInvestigation, true},
		{"bad status", Assessment{Status: "maybe", Confidence: 0.5}, "maybe", false},
		{"bad confidence", Assessment{Status: "fixed", Confidence: 1.5}, vex.StatusFixed, false},
		{"bad justification", Assessment{Status: "not_affected", Justification: "because", Confidence: 0.5}, vex.StatusNotAffected, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.in
			a.Normalize()
			if a.Status != tc.want {
				t.Fatalf("status = %q want %q", a.Status, tc.want)
			}
			err := a.Validate()
			if (err == nil) != tc.ok {
				t.Fatalf("validate err = %v, want ok=%v", err, tc.ok)
			}
			if a.Status == vex.StatusAffected && a.ActionStatement == "" {
				t.Fatal("affected must have action statement")
			}
			if (a.Status == vex.StatusFixed || a.Status == vex.StatusUnderInvestigation) && (a.Justification != "" || a.ActionStatement != "" || a.ImpactStatement != "") {
				t.Fatal("fixed/under_investigation must strip fields")
			}
		})
	}
}

func TestParseAssessment(t *testing.T) {
	inputs := []string{
		`{"status":"fixed","confidence":0.9,"reasoning":"ok"}`,
		"Here you go:\n```json\n{\"status\":\"fixed\",\"confidence\":0.9,\"reasoning\":\"ok\"}\n```\nThanks!",
		"Sure. {\"status\": \"FIXED\", \"confidence\": 0.9, \"reasoning\": \"ok\", \"extra\": {\"nested\": \"}\"}}",
	}
	for _, in := range inputs {
		a, err := ParseAssessment(in)
		if err != nil || a.Status != vex.StatusFixed || a.Confidence != 0.9 {
			t.Errorf("ParseAssessment(%q) = %+v, %v", in, a, err)
		}
	}
	for _, bad := range []string{"", "no json here", "{not json}"} {
		if _, err := ParseAssessment(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestBuildUserPrompt(t *testing.T) {
	r := report(item(evidence.KindVersionVulnerable, false), item(evidence.KindNotReachable, true))
	p := BuildUserPrompt(Request{ProductName: "bomhort", ProductRepo: "https://github.com/seebom-labs/bomhort", Report: r})
	for _, want := range []string{"PRODUCT: bomhort", "GO-2023-2102", "pkg:golang/golang.org/x/net@v0.16.0", "FIXED VERSION: v0.17.0", "govulncheck_not_reachable [strong]", `"x":1`, "under_investigation", "vulnerable_code_not_in_execute_path"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	if !strings.Contains(BuildUserPrompt(Request{Report: report()}), "(none)") {
		t.Error("empty evidence should say none")
	}
}

func TestHeuristic(t *testing.T) {
	h := Heuristic{}
	cases := []struct {
		name  string
		items []evidence.Item
		want  vex.Status
		just  vex.Justification
	}{
		{"fixed", []evidence.Item{item(evidence.KindVersionFixed, true), item(evidence.KindReachable, true)}, vex.StatusFixed, ""},
		{"reachable", []evidence.Item{item(evidence.KindVersionVulnerable, false), item(evidence.KindReachable, true)}, vex.StatusAffected, ""},
		{"not reachable strong", []evidence.Item{item(evidence.KindNotReachable, true)}, vex.StatusNotAffected, vex.VulnerableCodeNotInExecutePath},
		{"not reachable weak", []evidence.Item{item(evidence.KindNotReachable, false)}, vex.StatusUnderInvestigation, ""},
		{"transitive not imported", []evidence.Item{item(evidence.KindImportNotFound, false), item(evidence.KindTransitive, false)}, vex.StatusUnderInvestigation, ""},
		{"symbol not referenced", []evidence.Item{item(evidence.KindSymbolNotReferenced, false)}, vex.StatusUnderInvestigation, ""},
		{"nothing", nil, vex.StatusUnderInvestigation, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := h.Assess(context.Background(), Request{Report: report(tc.items...)})
			if err != nil {
				t.Fatal(err)
			}
			if a.Status != tc.want || a.Justification != tc.just {
				t.Fatalf("got %s/%s want %s/%s", a.Status, a.Justification, tc.want, tc.just)
			}
			if err := a.Validate(); err != nil {
				t.Fatalf("heuristic produced invalid assessment: %v", err)
			}
			if a.Status == vex.StatusAffected && !strings.Contains(a.ActionStatement, "v0.17.0") {
				t.Fatalf("action = %q", a.ActionStatement)
			}
			if a.Provider != "heuristic" || a.Reasoning == "" {
				t.Fatalf("meta = %+v", a)
			}
		})
	}
	if _, err := h.Assess(context.Background(), Request{}); err == nil {
		t.Fatal("nil report must error")
	}
}

func TestOpenAI(t *testing.T) {
	var calls atomic.Int32
	var lastBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer sk-test" || r.Header.Get("X-Extra") != "1" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"message":"bad auth"}}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &lastBody)
		rf, _ := lastBody["response_format"].(map[string]any)
		if rf != nil && rf["type"] == "json_schema" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"message":"response_format json_schema is not supported"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"model":"test-model-2026","usage":{"prompt_tokens":1200,"completion_tokens":80},"choices":[{"message":{"content":"{\"status\":\"not_affected\",\"justification\":\"vulnerable_code_not_in_execute_path\",\"confidence\":0.8,\"reasoning\":\"no path\",\"evidence_refs\":[\"govulncheck_not_reachable\"]}"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()

	o := &OpenAI{BaseURL: srv.URL + "/v1/", Model: "test-model", APIKey: "sk-test", StructuredOutput: true, ExtraHeaders: map[string]string{"X-Extra": "1"}}
	a, err := o.Assess(context.Background(), Request{ProductName: "p", Report: report(item(evidence.KindNotReachable, true))})
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != vex.StatusNotAffected || a.Confidence != 0.8 || a.Provider != "openai:test-model" {
		t.Fatalf("assessment = %+v", a)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected fallback from json_schema to json_object (2 calls), got %d", calls.Load())
	}
	// Both attempts count; tokens come from the successful response only.
	if a.Usage.Calls != 2 || a.Usage.PromptTokens != 1200 || a.Usage.CompletionTokens != 80 || a.Usage.Model != "test-model-2026" || a.Usage.Duration <= 0 {
		t.Fatalf("usage = %+v", a.Usage)
	}
	msgs := lastBody["messages"].([]any)
	if len(msgs) != 2 || msgs[0].(map[string]any)["role"] != "system" {
		t.Fatalf("messages = %v", msgs)
	}
	if lastBody["model"] != "test-model" {
		t.Fatalf("model = %v", lastBody["model"])
	}

	bad := &OpenAI{BaseURL: srv.URL + "/v1", Model: "m", APIKey: "wrong"}
	if _, err := bad.Assess(context.Background(), Request{Report: report()}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got %v", err)
	}
	if _, err := o.Assess(context.Background(), Request{}); err == nil {
		t.Fatal("nil report must error")
	}
}

func TestOpenAIBadModelOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"I cannot decide."}}]}`)
	}))
	defer srv.Close()
	o := &OpenAI{BaseURL: srv.URL, Model: "m"}
	if _, err := o.Assess(context.Background(), Request{Report: report()}); err == nil || !strings.Contains(err.Error(), "no JSON object") {
		t.Fatalf("got %v", err)
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"choices":[]}`) }))
	defer empty.Close()
	if _, err := (&OpenAI{BaseURL: empty.URL, Model: "m"}).Assess(context.Background(), Request{Report: report()}); err == nil {
		t.Fatal("empty choices must error")
	}
}

// fakeTriageServer is an in-process MCP server exposing an assessment tool.
func fakeTriageServer(t *testing.T, structured bool) *mcp.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake-triage", Version: "0"}, nil)
	type in struct {
		SystemPrompt string         `json:"system_prompt"`
		Prompt       string         `json:"prompt"`
		Request      map[string]any `json:"request"`
		Schema       map[string]any `json:"schema"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "assess_vulnerability", Description: "triage"}, func(_ context.Context, _ *mcp.CallToolRequest, input in) (*mcp.CallToolResult, any, error) {
		if !strings.Contains(input.Prompt, "GO-2023-2102") || input.SystemPrompt == "" || len(input.Request) == 0 || input.Schema["type"] != "object" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "bad arguments"}}}, nil, nil
		}
		out := map[string]any{"status": "affected", "action_statement": "upgrade", "confidence": 0.75, "reasoning": "reachable"}
		if structured {
			return &mcp.CallToolResult{StructuredContent: out}, nil, nil
		}
		data, _ := json.Marshal(out)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "```json\n" + string(data) + "\n```"}}}, nil, nil
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "broken"}, func(context.Context, *mcp.CallToolRequest, in) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "model overloaded"}}}, nil, nil
	})
	return srv
}

func connectInMemory(t *testing.T, server *mcp.Server) mcp.Transport {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	return ct
}

func TestMCPTool(t *testing.T) {
	for _, structured := range []bool{true, false} {
		server := fakeTriageServer(t, structured)
		m := &MCPTool{Transport: connectInMemory(t, server), Tool: "assess_vulnerability"}
		a, err := m.Assess(context.Background(), Request{ProductName: "p", Report: report(item(evidence.KindReachable, true))})
		if err != nil {
			t.Fatalf("structured=%v: %v", structured, err)
		}
		if a.Status != vex.StatusAffected || a.Confidence != 0.75 || a.Provider != "mcptool:assess_vulnerability" || a.ActionStatement != "upgrade" {
			t.Fatalf("assessment = %+v", a)
		}
		// second call reuses session
		if _, err := m.Assess(context.Background(), Request{ProductName: "p", Report: report()}); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(); err != nil {
			t.Fatal("double close should be nil")
		}
	}
}

func TestMCPToolErrors(t *testing.T) {
	server := fakeTriageServer(t, true)
	m := &MCPTool{Transport: connectInMemory(t, server), Tool: "broken"}
	defer m.Close()
	if _, err := m.Assess(context.Background(), Request{Report: report()}); err == nil || !strings.Contains(err.Error(), "model overloaded") {
		t.Fatalf("expected tool error, got %v", err)
	}
	missing := &MCPTool{Transport: connectInMemory(t, server), Tool: "does_not_exist"}
	defer missing.Close()
	if _, err := missing.Assess(context.Background(), Request{Report: report()}); err == nil {
		t.Fatal("unknown tool must error")
	}
	if _, err := (&MCPTool{Tool: "x"}).Assess(context.Background(), Request{Report: report()}); err == nil {
		t.Fatal("missing transport must error")
	}
	if _, err := m.Assess(context.Background(), Request{}); err == nil {
		t.Fatal("nil report must error")
	}
}

func TestMCPToolConstructors(t *testing.T) {
	s := NewMCPToolStdio("true", []string{"-x"}, map[string]string{"A": "b"}, "t", 0)
	if s.Tool != "t" || s.Transport == nil {
		t.Fatal("stdio ctor")
	}
	h := NewMCPToolHTTP("http://localhost:1/mcp", map[string]string{"Authorization": "Bearer x"}, "t", 0)
	if h.Tool != "t" || h.Transport == nil {
		t.Fatal("http ctor")
	}
	rt := &headerRoundTripper{headers: map[string]string{"X-A": "1"}, next: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-A") != "1" {
			t.Fatal("header not set")
		}
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMockAndFallback(t *testing.T) {
	m := &Mock{ByVulnID: map[string]Assessment{"GO-2023-2102": {Status: vex.StatusFixed, Confidence: 1}}}
	a, err := m.Assess(context.Background(), Request{Report: report()})
	if err != nil || a.Status != vex.StatusFixed || a.Provider != "mock" || len(m.Calls) != 1 {
		t.Fatalf("mock = %+v %v", a, err)
	}
	other := report()
	other.Finding.VulnID = "X"
	if _, err := m.Assess(context.Background(), Request{Report: other}); err == nil {
		t.Fatal("unconfigured vuln must error")
	}
	m.Default = &Assessment{Status: vex.StatusUnderInvestigation}
	if a, err := m.Assess(context.Background(), Request{Report: other}); err != nil || a.Status != vex.StatusUnderInvestigation {
		t.Fatal("default not used")
	}
	if _, err := (&Mock{}).Assess(context.Background(), Request{}); err == nil {
		t.Fatal("nil report must error")
	}

	var logged error
	fb := WithFallback{Primary: &Mock{Err: errors.New("llm down")}, Fallback: Heuristic{}, OnError: func(_ Request, err error) { logged = err }}
	a, err = fb.Assess(context.Background(), Request{Report: report(item(evidence.KindVersionFixed, true))})
	if err != nil || a.Status != vex.StatusFixed || a.Provider != "heuristic" || !strings.Contains(a.Reasoning, "llm down") || logged == nil {
		t.Fatalf("fallback = %+v %v", a, err)
	}
	if fb.Name() != "mock+heuristic" {
		t.Fatalf("name = %q", fb.Name())
	}
	both := WithFallback{Primary: &Mock{Err: errors.New("a")}, Fallback: &Mock{Err: errors.New("b")}}
	if _, err := both.Assess(context.Background(), Request{Report: report()}); err == nil || !strings.Contains(err.Error(), "a") || !strings.Contains(err.Error(), "b") {
		t.Fatalf("joined error = %v", err)
	}
}

func TestOpenAIProviderNameGitHubModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/inference/chat/completions" || r.Header.Get("Authorization") != "Bearer ghp_x" || r.Header.Get("X-GitHub-Api-Version") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{\"status\":\"under_investigation\",\"confidence\":0.5,\"reasoning\":\"x\"}"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()
	o := &OpenAI{BaseURL: srv.URL + "/inference", Model: "openai/gpt-4.1-mini", APIKey: "ghp_x", ProviderName: "github",
		ExtraHeaders: map[string]string{"X-GitHub-Api-Version": "2022-11-28"}}
	a, err := o.Assess(context.Background(), Request{ProductName: "p", Report: report()})
	if err != nil {
		t.Fatal(err)
	}
	if a.Provider != "github:openai/gpt-4.1-mini" || o.Name() != "github:openai/gpt-4.1-mini" {
		t.Fatalf("provider = %q", a.Provider)
	}
}

func TestCopilotCLI(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "copilot")
	// Fake CLI: verifies flags, echoes an assessment; "--model fail" exits with the auth hint.
	if err := os.WriteFile(script, []byte(`#!/bin/sh
prompt=""
while [ $# -gt 0 ]; do
  case "$1" in
    -p) prompt="$2"; shift;;
    --model) model="$2"; shift;;
    --output-format) fmt="$2"; shift;;
    -s|--no-ask-user|--no-auto-update|--no-custom-instructions|--deny-tool=shell|--deny-tool=write|--deny-tool=edit) ;;
    --extra) extra=1;;
    *) echo "unexpected arg $1" >&2; exit 2;;
  esac
  shift
done
case "$prompt" in *"OpenVEX"*) ;; *) echo "system prompt missing" >&2; exit 2;; esac
case "$prompt" in *"GO-2023-2102"*) ;; *) echo "finding missing" >&2; exit 2;; esac
if [ "$model" = "fail" ]; then echo "To authenticate, run /login" >&2; exit 1; fi
[ "$extra" = 1 ] || { echo "extra arg missing" >&2; exit 2; }
[ "$fmt" = json ] || { echo "json output format missing" >&2; exit 2; }
if [ "$model" = "legacy" ]; then
  # Older CLI: plain text with a fenced answer.
  echo 'Here you go:'
  printf '%s\n' '`+"```"+`json'
  echo '{"status":"affected","confidence":0.7,"reasoning":"reachable","action_statement":"upgrade"}'
  printf '%s\n' '`+"```"+`'
  exit 0
fi
# JSONL events as emitted by copilot --output-format json.
echo '{"type":"session.tools_updated","data":{"model":"claude-sonnet-4.5"}}'
echo '{"type":"assistant.reasoning","data":{"content":"thinking","outputTokens":40}}'
echo '{"type":"assistant.message","data":{"content":"","toolRequests":[{"name":"view"}],"outputTokens":10}}'
cwd=$(pwd)
cat <<EOF
{"type":"assistant.message","data":{"content":"Result:\\n\\u0060\\u0060\\u0060json\\n{\\"status\\":\\"affected\\",\\"confidence\\":0.7,\\"reasoning\\":\\"cwd=$cwd\\",\\"action_statement\\":\\"upgrade\\"}\\n\\u0060\\u0060\\u0060","outputTokens":62}}
EOF
echo '{"type":"result","exitCode":0,"usage":{"premiumRequests":0.33,"totalApiDurationMs":1500}}'
`), 0o755); err != nil {
		t.Fatal(err)
	}
	repoDir := t.TempDir()
	c := &CopilotCLI{Command: script, Model: "gpt-5", Args: []string{"--extra"}, InRepo: true}
	a, err := c.Assess(context.Background(), Request{ProductName: "p", RepoDir: repoDir, Report: report(item(evidence.KindReachable, true))})
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != vex.StatusAffected || a.Provider != "copilot:gpt-5" || a.ActionStatement != "upgrade" {
		t.Fatalf("assessment = %+v", a)
	}
	if !strings.Contains(a.Reasoning, repoDir) {
		t.Fatalf("InRepo: cwd not the repo: %q", a.Reasoning)
	}
	if a.Usage.Calls != 1 || a.Usage.PremiumRequests != 0.33 || a.Usage.CompletionTokens != 112 || a.Usage.Model != "claude-sonnet-4.5" || a.Usage.Duration <= 0 {
		t.Fatalf("usage = %+v", a.Usage)
	}

	// Older CLI without JSONL output still works; the model falls back to the configured one.
	legacy := &CopilotCLI{Command: script, Model: "legacy", Args: []string{"--extra"}}
	a, err = legacy.Assess(context.Background(), Request{ProductName: "p", Report: report(item(evidence.KindReachable, true))})
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != vex.StatusAffected || a.Usage.Calls != 1 || a.Usage.Model != "legacy" || a.Usage.PremiumRequests != 0 {
		t.Fatalf("legacy = %+v usage=%+v", a, a.Usage)
	}

	bad := &CopilotCLI{Command: script, Model: "fail", Args: []string{"--extra"}}
	if _, err := bad.Assess(context.Background(), Request{Report: report()}); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("expected auth error, got %v", err)
	}
	if _, err := c.Assess(context.Background(), Request{}); err == nil {
		t.Fatal("nil report must error")
	}
	if (&CopilotCLI{}).Name() != "copilot" || (&CopilotCLI{}).command() != "copilot" {
		t.Fatal("defaults")
	}
}

func TestUsageAddAndString(t *testing.T) {
	var u Usage
	if !u.IsZero() || u.String() != "none" {
		t.Fatalf("zero usage: %q", u.String())
	}
	u.Add(Usage{Calls: 1, PromptTokens: 11900, CompletionTokens: 512, Model: "gpt-4.1"})
	u.Add(Usage{Calls: 2, PremiumRequests: 1, CacheHits: 2, Model: "gpt-4.1"})
	if u.Calls != 3 || u.TotalTokens() != 12412 || u.PremiumRequests != 1 || u.CacheHits != 2 || u.Model != "gpt-4.1" {
		t.Fatalf("u = %+v", u)
	}
	s := u.String()
	for _, want := range []string{"3 calls", "12.4k tokens", "11.9k prompt", "512 completion", "1.00 premium requests", "2 cache hits", "model=gpt-4.1"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
	u.Add(Usage{Model: "claude"})
	if u.Model != "mixed" {
		t.Fatalf("model = %q, want mixed", u.Model)
	}
	if got := (Usage{CompletionTokens: 5}).String(); got != "5 output tokens" {
		t.Fatalf("output-only usage = %q", got)
	}
}

func TestParseCopilotOutputNonJSON(t *testing.T) {
	text, u := parseCopilotOutput([]byte("plain {\"status\":\"fixed\"} answer"))
	if text != "plain {\"status\":\"fixed\"} answer" || !u.IsZero() {
		t.Fatalf("text=%q usage=%+v", text, u)
	}
	// A JSON line without "type" is not an event stream.
	text, _ = parseCopilotOutput([]byte("{\"status\":\"fixed\",\"confidence\":1,\"reasoning\":\"x\"}"))
	if !strings.Contains(text, "fixed") {
		t.Fatalf("bare JSON must be passed through: %q", text)
	}
}
