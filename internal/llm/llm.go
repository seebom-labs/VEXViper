// Package llm defines the assessment provider abstraction and the shared
// request/response schema exchanged with language models.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/seebom-labs/vexviper/internal/evidence"
)

// Request is everything a provider gets about one finding.
type Request struct {
	ProductName string           `json:"product_name"`
	ProductRepo string           `json:"product_repo,omitempty"`
	Report      *evidence.Report `json:"report"`
	// RepoDir is the local checkout of the product (if any); providers that
	// can inspect code (CopilotCLI with InRepo) use it as working directory.
	RepoDir string `json:"-"`
}

// Assessment is the provider's verdict. It intentionally mirrors OpenVEX
// statement fields so it can be validated with go-vex before use.
type Assessment struct {
	Status          vex.Status        `json:"status"`
	Justification   vex.Justification `json:"justification,omitempty"`
	ImpactStatement string            `json:"impact_statement,omitempty"`
	ActionStatement string            `json:"action_statement,omitempty"`
	// Confidence in [0,1].
	Confidence float64 `json:"confidence"`
	// Reasoning is a short explanation kept in status_notes.
	Reasoning string `json:"reasoning"`
	// EvidenceRefs lists evidence kinds the verdict relies on.
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	// Provider names the provider that produced the assessment.
	Provider string `json:"provider,omitempty"`
	// Usage reports what the assessment cost (zero for offline providers).
	Usage Usage `json:"usage,omitempty"`
}

// Usage is the cost of one or more provider calls. Fields are additive so
// callers can aggregate per SBOM/run. Not every provider fills every field:
// OpenAI-compatible APIs report tokens; the Copilot CLI reports premium
// requests (its billing unit) and output tokens only.
type Usage struct {
	// Calls counts provider invocations (0 for cache hits / offline verdicts).
	Calls int `json:"calls,omitempty"`
	// PromptTokens and CompletionTokens as reported by the API.
	PromptTokens     int `json:"prompt_tokens,omitempty"`
	CompletionTokens int `json:"completion_tokens,omitempty"`
	// PremiumRequests is the GitHub Copilot billing unit consumed.
	PremiumRequests float64 `json:"premium_requests,omitempty"`
	// Model is the model that actually answered, when the provider reports it.
	Model string `json:"model,omitempty"`
	// Duration is wall time spent waiting on the provider.
	Duration time.Duration `json:"duration_ns,omitempty"`
	// CacheHits counts assessments served from the assessment cache.
	CacheHits int `json:"cache_hits,omitempty"`
}

// Add accumulates o into u. Model is kept when all contributions agree and
// becomes "mixed" otherwise.
func (u *Usage) Add(o Usage) {
	u.Calls += o.Calls
	u.PromptTokens += o.PromptTokens
	u.CompletionTokens += o.CompletionTokens
	u.PremiumRequests += o.PremiumRequests
	u.Duration += o.Duration
	u.CacheHits += o.CacheHits
	switch {
	case o.Model == "":
	case u.Model == "":
		u.Model = o.Model
	case u.Model != o.Model:
		u.Model = "mixed"
	}
}

// TotalTokens is prompt + completion tokens.
func (u Usage) TotalTokens() int { return u.PromptTokens + u.CompletionTokens }

// IsZero reports whether nothing was consumed or cached.
func (u Usage) IsZero() bool {
	return u.Calls == 0 && u.PromptTokens == 0 && u.CompletionTokens == 0 && u.PremiumRequests == 0 && u.CacheHits == 0
}

// String renders a compact human-readable summary, e.g.
// "3 calls, 12.4k tokens (11.9k prompt / 512 completion), 1.0 premium requests, 2 cache hits".
func (u Usage) String() string {
	var parts []string
	if u.Calls > 0 {
		parts = append(parts, fmt.Sprintf("%d calls", u.Calls))
	}
	switch {
	case u.PromptTokens > 0:
		parts = append(parts, fmt.Sprintf("%s tokens (%s prompt / %s completion)", kilo(u.TotalTokens()), kilo(u.PromptTokens), kilo(u.CompletionTokens)))
	case u.CompletionTokens > 0:
		// Copilot CLI only reports output tokens.
		parts = append(parts, fmt.Sprintf("%s output tokens", kilo(u.CompletionTokens)))
	}
	if u.PremiumRequests > 0 {
		parts = append(parts, fmt.Sprintf("%.2f premium requests", u.PremiumRequests))
	}
	if u.CacheHits > 0 {
		parts = append(parts, fmt.Sprintf("%d cache hits", u.CacheHits))
	}
	if u.Model != "" {
		parts = append(parts, "model="+u.Model)
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func kilo(n int) string {
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

// Provider assesses one finding.
type Provider interface {
	Name() string
	Assess(ctx context.Context, req Request) (Assessment, error)
}

// Validate checks the assessment against OpenVEX rules and value ranges.
func (a *Assessment) Validate() error {
	if a.Confidence < 0 || a.Confidence > 1 {
		return fmt.Errorf("confidence %v out of range [0,1]", a.Confidence)
	}
	s := vex.Statement{
		Status:          a.Status,
		Justification:   a.Justification,
		ImpactStatement: a.ImpactStatement,
		ActionStatement: a.ActionStatement,
	}
	return s.Validate()
}

// Normalize coerces common LLM sloppiness (case, dashes, empty strings) into
// valid OpenVEX enum values before validation.
func (a *Assessment) Normalize() {
	a.Status = vex.Status(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(string(a.Status)), "-", "_")))
	a.Justification = vex.Justification(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(string(a.Justification)), "-", "_")))
	a.ImpactStatement = strings.TrimSpace(a.ImpactStatement)
	a.ActionStatement = strings.TrimSpace(a.ActionStatement)
	a.Reasoning = strings.TrimSpace(a.Reasoning)
	// Drop fields that are forbidden for the status; LLMs love to fill them in.
	switch a.Status {
	case vex.StatusAffected:
		a.Justification, a.ImpactStatement = "", ""
		if a.ActionStatement == "" {
			a.ActionStatement = "Upgrade the affected component to a fixed version."
		}
	case vex.StatusFixed, vex.StatusUnderInvestigation:
		a.Justification, a.ImpactStatement, a.ActionStatement = "", "", ""
	case vex.StatusNotAffected:
		a.ActionStatement = ""
	}
}

// ParseAssessment decodes JSON (optionally wrapped in markdown fences or
// surrounded by prose) into an Assessment and normalizes it.
func ParseAssessment(text string) (Assessment, error) {
	raw := extractJSON(text)
	if raw == "" {
		return Assessment{}, fmt.Errorf("no JSON object found in model output: %.200q", text)
	}
	var a Assessment
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return Assessment{}, fmt.Errorf("decode assessment: %w (input %.200q)", err, raw)
	}
	a.Normalize()
	return a, nil
}

func extractJSON(text string) string {
	text = strings.TrimSpace(text)
	if i := strings.Index(text, "```"); i >= 0 {
		rest := text[i+3:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:]
		}
		if j := strings.Index(rest, "```"); j >= 0 {
			text = rest[:j]
		}
	}
	start := strings.IndexByte(text, '{')
	end := strings.LastIndexByte(text, '}')
	if start < 0 || end <= start {
		return ""
	}
	return text[start : end+1]
}

// JSONSchema is the response schema handed to structured-output capable
// providers and included in the prompt for the others.
var JSONSchema = map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"status", "confidence", "reasoning"},
	"properties": map[string]any{
		"status":           map[string]any{"type": "string", "enum": vex.Statuses()},
		"justification":    map[string]any{"type": "string", "enum": append([]string{""}, vex.Justifications()...)},
		"impact_statement": map[string]any{"type": "string"},
		"action_statement": map[string]any{"type": "string"},
		"confidence":       map[string]any{"type": "number", "minimum": 0, "maximum": 1},
		"reasoning":        map[string]any{"type": "string"},
		"evidence_refs":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	},
}
