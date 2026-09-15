package llm

import (
	"sync"
	"testing"
)

func TestBudgetNilIsUnlimited(t *testing.T) {
	var b *Budget
	if b.Exceeded() {
		t.Fatal("nil budget must never be exceeded")
	}
	b.Spend(Usage{Calls: 100})
	b.Reset()
	if !b.Spent().IsZero() {
		t.Fatal("nil budget spent must be zero")
	}
	if NewBudget(BudgetLimits{}) != nil {
		t.Fatal("zero limits must yield nil budget")
	}
	if got := (BudgetLimits{}).String(); got != "unlimited" {
		t.Fatalf("String() = %q", got)
	}
}

func TestBudgetLimits(t *testing.T) {
	b := NewBudget(BudgetLimits{MaxCalls: 2})
	b.Spend(Usage{Calls: 1})
	if b.Exceeded() {
		t.Fatal("1/2 calls must not be exceeded")
	}
	b.Spend(Usage{Calls: 1, CacheHits: 5})
	if reason, over := b.Check(); !over || reason != "max_calls 2 reached" {
		t.Fatalf("Check() = %q, %v", reason, over)
	}
	b.Reset()
	if b.Exceeded() {
		t.Fatal("reset must clear spend")
	}

	tok := NewBudget(BudgetLimits{MaxTokens: 100})
	tok.Spend(Usage{PromptTokens: 60, CompletionTokens: 40})
	if r, over := tok.Check(); !over || r != "max_tokens 100 reached (100 used)" {
		t.Fatalf("tokens: %q %v", r, over)
	}

	prem := NewBudget(BudgetLimits{MaxPremiumRequests: 1})
	prem.Spend(Usage{PremiumRequests: 0.33})
	prem.Spend(Usage{PremiumRequests: 0.33})
	if prem.Exceeded() {
		t.Fatal("0.66 < 1 premium requests")
	}
	prem.Spend(Usage{PremiumRequests: 0.34})
	if !prem.Exceeded() {
		t.Fatal("1.00 premium requests must exceed")
	}
	if got := prem.Limits.String(); got != "max_premium_requests=1.00" {
		t.Fatalf("String() = %q", got)
	}
	if got := (BudgetLimits{MaxCalls: 3, MaxTokens: 9}).String(); got != "max_calls=3 max_tokens=9" {
		t.Fatalf("String() = %q", got)
	}
}

func TestBudgetConcurrentSpend(t *testing.T) {
	b := NewBudget(BudgetLimits{MaxCalls: 1000})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				b.Spend(Usage{Calls: 1})
			}
		}()
	}
	wg.Wait()
	if b.Spent().Calls != 500 {
		t.Fatalf("Calls = %d, want 500", b.Spent().Calls)
	}
}
