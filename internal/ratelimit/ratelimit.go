// Package ratelimit provides a small, dependency-free, per-process token-bucket
// limiter keyed by an arbitrary string (typically the requesting IP). It guards
// the OIDC plugin's attacker-reachable endpoints — ExchangeCode and the admin
// diagnostic handlers (decode-id-token, discovery, simulate-claims) — all of
// which run verification or outbound network calls on attacker-influenced
// input.
//
// The limiter is intentionally in-process: the plugin runs as a single process
// behind the host, so a process-local bucket is the correct enforcement point
// and avoids a shared-store round-trip on the hot auth path. Stale buckets are
// swept lazily so an attacker churning keys can't grow the map without bound.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a keyed token-bucket rate limiter. Each key gets its own bucket
// that refills at Rate tokens/second up to Burst tokens. It is safe for
// concurrent use.
type Limiter struct {
	rate  float64       // tokens added per second
	burst float64       // bucket capacity
	ttl   time.Duration // idle buckets older than this are swept
	now   func() time.Time

	mu       sync.Mutex
	buckets  map[string]*bucket
	lastSwip time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a Limiter allowing burst requests immediately and refilling at
// ratePerSec tokens/second. A non-positive burst is clamped to 1.
func New(ratePerSec, burst float64) *Limiter {
	if burst < 1 {
		burst = 1
	}
	if ratePerSec <= 0 {
		ratePerSec = 1
	}
	return &Limiter{
		rate:    ratePerSec,
		burst:   burst,
		ttl:     10 * time.Minute,
		now:     time.Now,
		buckets: make(map[string]*bucket),
	}
}

// Allow consumes one token for key. It returns ok=true when a token was
// available. When ok=false, retryAfter is the time until the next token is
// available, rounded up to whole seconds (suitable for a Retry-After header).
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * l.rate
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
			b.last = now
		}
	}

	if b.tokens >= 1 {
		b.tokens -= 1
		return true, 0
	}
	// Tokens needed to reach 1, converted to wait time, rounded up to a second.
	need := 1 - b.tokens
	wait := time.Duration(need / l.rate * float64(time.Second))
	if rem := wait % time.Second; rem != 0 {
		wait += time.Second - rem
	}
	if wait <= 0 {
		wait = time.Second
	}
	return false, wait
}

// sweepLocked drops buckets idle longer than ttl. Runs at most once per ttl to
// keep Allow cheap; the caller holds l.mu.
func (l *Limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSwip) < l.ttl {
		return
	}
	l.lastSwip = now
	for k, b := range l.buckets {
		if now.Sub(b.last) > l.ttl {
			delete(l.buckets, k)
		}
	}
}
