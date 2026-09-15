package llm

import (
	"fmt"
	"strings"
	"sync"
)

// BudgetLimits caps provider spend. Zero values mean "unlimited".
type BudgetLimits struct {
	MaxCalls           int     `yaml:"max_calls"`
	MaxTokens          int     `yaml:"max_tokens"`
	MaxPremiumRequests float64 `yaml:"max_premium_requests"`
}

// IsZero reports whether no limit is set.
func (l BudgetLimits) IsZero() bool {
	return l.MaxCalls == 0 && l.MaxTokens == 0 && l.MaxPremiumRequests == 0
}

// Budget is a concurrency-safe spend meter. Callers check Exceeded before
// asking a provider and Spend afterwards; once a limit is hit the pipeline
// falls back to offline (heuristic) verdicts so a runaway watch pass cannot
// drain a subscription.
type Budget struct {
	Limits BudgetLimits

	mu    sync.Mutex
	spent Usage
}

// NewBudget returns a meter for limits; a nil *Budget is valid and unlimited.
func NewBudget(l BudgetLimits) *Budget {
	if l.IsZero() {
		return nil
	}
	return &Budget{Limits: l}
}

// Spend records usage.
func (b *Budget) Spend(u Usage) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.spent.Add(u)
	b.mu.Unlock()
}

// Spent returns a snapshot of what has been consumed.
func (b *Budget) Spent() Usage {
	if b == nil {
		return Usage{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.spent
}

// Exceeded reports whether any limit has been reached.
func (b *Budget) Exceeded() bool {
	_, over := b.Check()
	return over
}

// Check returns the first exhausted limit (human readable) and whether one
// has been reached.
func (b *Budget) Check() (string, bool) {
	if b == nil {
		return "", false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	l, s := b.Limits, b.spent
	switch {
	case l.MaxCalls > 0 && s.Calls >= l.MaxCalls:
		return fmt.Sprintf("max_calls %d reached", l.MaxCalls), true
	case l.MaxTokens > 0 && s.TotalTokens() >= l.MaxTokens:
		return fmt.Sprintf("max_tokens %d reached (%d used)", l.MaxTokens, s.TotalTokens()), true
	case l.MaxPremiumRequests > 0 && s.PremiumRequests >= l.MaxPremiumRequests:
		return fmt.Sprintf("max_premium_requests %.2f reached (%.2f used)", l.MaxPremiumRequests, s.PremiumRequests), true
	}
	return "", false
}

// Reset clears the spend (watch mode does this per pass).
func (b *Budget) Reset() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.spent = Usage{}
	b.mu.Unlock()
}

// String renders the limits, e.g. "max_calls=50 max_premium_requests=20.00".
func (l BudgetLimits) String() string {
	var parts []string
	if l.MaxCalls > 0 {
		parts = append(parts, fmt.Sprintf("max_calls=%d", l.MaxCalls))
	}
	if l.MaxTokens > 0 {
		parts = append(parts, fmt.Sprintf("max_tokens=%d", l.MaxTokens))
	}
	if l.MaxPremiumRequests > 0 {
		parts = append(parts, fmt.Sprintf("max_premium_requests=%.2f", l.MaxPremiumRequests))
	}
	if len(parts) == 0 {
		return "unlimited"
	}
	return strings.Join(parts, " ")
}
