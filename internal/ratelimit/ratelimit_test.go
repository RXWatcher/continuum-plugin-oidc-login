package ratelimit

import (
	"testing"
	"time"
)

func TestAllow_BurstThenThrottle(t *testing.T) {
	l := New(1, 3) // 1 token/sec, burst 3
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("k"); !ok {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
	ok, retry := l.Allow("k")
	if ok {
		t.Fatal("4th request should be throttled")
	}
	if retry <= 0 {
		t.Errorf("retryAfter = %v, want > 0", retry)
	}
}

func TestAllow_RefillsOverTime(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 1)
	l.now = func() time.Time { return now }

	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("first allowed")
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("second should be throttled (burst=1)")
	}
	now = now.Add(2 * time.Second) // refill
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("should be allowed after refill")
	}
}

func TestAllow_KeysAreIndependent(t *testing.T) {
	l := New(1, 1)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("a first allowed")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("b should have its own bucket")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("a second should throttle")
	}
}

func TestAllow_RetryAfterRoundsUpToSecond(t *testing.T) {
	l := New(1, 1)
	_, _ = l.Allow("k")
	_, retry := l.Allow("k")
	if retry%time.Second != 0 {
		t.Errorf("retryAfter = %v, want whole seconds", retry)
	}
	if retry < time.Second {
		t.Errorf("retryAfter = %v, want >= 1s", retry)
	}
}

func TestSweep_DropsIdleBuckets(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 1)
	l.now = func() time.Time { return now }
	_, _ = l.Allow("old")
	if len(l.buckets) != 1 {
		t.Fatalf("buckets = %d", len(l.buckets))
	}
	now = now.Add(l.ttl + time.Minute)
	_, _ = l.Allow("new") // triggers sweep of "old"
	if _, ok := l.buckets["old"]; ok {
		t.Error("idle bucket should have been swept")
	}
}

func TestNew_ClampsInvalidParams(t *testing.T) {
	l := New(0, 0)
	if l.burst < 1 || l.rate <= 0 {
		t.Errorf("clamp failed: burst=%v rate=%v", l.burst, l.rate)
	}
}
