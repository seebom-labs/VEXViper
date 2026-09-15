package bomhort

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterNilAndReserve(t *testing.T) {
	var nl *RateLimiter
	if err := nl.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if NewRateLimiter(0, time.Second) != nil {
		t.Fatal("limit 0 must disable")
	}

	now := time.Unix(1000, 0)
	r := NewRateLimiter(2, 10*time.Second)
	r.now = func() time.Time { return now }
	if d := r.reserve(); d != 0 {
		t.Fatalf("1st: %v", d)
	}
	if d := r.reserve(); d != 0 {
		t.Fatalf("2nd: %v", d)
	}
	if d := r.reserve(); d != 10*time.Second {
		t.Fatalf("3rd must wait a full window, got %v", d)
	}
	// Fourth request queues behind the third: 2 per window → +10s again.
	if d := r.reserve(); d != 10*time.Second {
		t.Fatalf("4th: %v", d)
	}
	// Time moves past the window: the first two slots expire, but the
	// reserved ones (at +10s) still count.
	now = now.Add(11 * time.Second)
	if d := r.reserve(); d != 9*time.Second {
		t.Fatalf("after window: %v", d)
	}
	// Default window when none given.
	if NewRateLimiter(1, 0).window != 10*time.Second {
		t.Fatal("default window")
	}
}

func TestRateLimiterWaitHonoursContext(t *testing.T) {
	r := NewRateLimiter(1, time.Hour)
	if err := r.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.Wait(ctx); err != context.DeadlineExceeded {
		t.Fatalf("err = %v", err)
	}
}
