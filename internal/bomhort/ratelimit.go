package bomhort

import (
	"context"
	"sync"
	"time"
)

// RateLimiter admits at most limit requests per window (sliding). BOMHort's
// gateway allows 100 requests / 10 s per client IP by default; staying below
// that avoids 429 back-off storms when watch runs several SBOMs in parallel.
type RateLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu    sync.Mutex
	slots []time.Time // admission times of the last `limit` requests
}

// NewRateLimiter returns nil (no limiting) when limit <= 0.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		return nil
	}
	if window <= 0 {
		window = 10 * time.Second
	}
	return &RateLimiter{limit: limit, window: window, now: time.Now}
}

// Wait blocks until a request may be sent or ctx is done. A nil limiter
// never blocks.
func (r *RateLimiter) Wait(ctx context.Context) error {
	if r == nil {
		return nil
	}
	d := r.reserve()
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// reserve books the next admission slot and returns how long to wait for it.
func (r *RateLimiter) reserve() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	// Drop slots outside the window.
	cut := now.Add(-r.window)
	i := 0
	for i < len(r.slots) && !r.slots[i].After(cut) {
		i++
	}
	r.slots = r.slots[i:]
	at := now
	if len(r.slots) >= r.limit {
		at = r.slots[len(r.slots)-r.limit].Add(r.window)
	}
	r.slots = append(r.slots, at)
	return at.Sub(now)
}
