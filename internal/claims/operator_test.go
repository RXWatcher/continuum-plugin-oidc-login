package claims_test

import (
	"testing"

	"github.com/ContinuumApp/continuum-plugin-oidc-login/internal/claims"
)

func TestEquals(t *testing.T) {
	cases := []struct {
		claim, value any
		want         bool
	}{
		{"abc", "abc", true},
		{"abc", "abd", false},
		{true, true, true},
		{true, false, false},
		{float64(1), float64(1), true},
		{float64(1), float64(2), false},
		{[]any{"a"}, "a", false}, // arrays don't equal strings — use contains
	}
	for i, c := range cases {
		if got := claims.Eval("equals", c.claim, c.value); got != c.want {
			t.Errorf("case %d: equals(%v, %v) = %v, want %v", i, c.claim, c.value, got, c.want)
		}
	}
}

func TestContains(t *testing.T) {
	cases := []struct {
		claim, value any
		want         bool
	}{
		{[]any{"a", "b"}, "a", true},
		{[]any{"a", "b"}, "c", false},
		{"abcdef", "cd", true},
		{"abcdef", "xy", false},
		{nil, "x", false},
		{float64(1), "1", false},
	}
	for i, c := range cases {
		if got := claims.Eval("contains", c.claim, c.value); got != c.want {
			t.Errorf("case %d: contains(%v, %v) = %v, want %v", i, c.claim, c.value, got, c.want)
		}
	}
}

func TestStartsWith(t *testing.T) {
	if !claims.Eval("starts_with", "hello world", "hello") {
		t.Error("starts_with positive")
	}
	if claims.Eval("starts_with", "hello", "world") {
		t.Error("starts_with negative")
	}
	if claims.Eval("starts_with", float64(1), "1") {
		t.Error("starts_with non-string should be false")
	}
}

func TestRegex(t *testing.T) {
	if !claims.Eval("regex", "abc123", "^abc[0-9]+$") {
		t.Error("regex positive")
	}
	if claims.Eval("regex", "abc", "^[0-9]+$") {
		t.Error("regex negative")
	}
	// Array: passes if any element matches.
	if !claims.Eval("regex", []any{"x", "abc123"}, "^abc[0-9]+$") {
		t.Error("regex over array")
	}
	// Bad regex pattern → false.
	if claims.Eval("regex", "abc", "[unclosed") {
		t.Error("invalid regex should be false")
	}
}

func TestEval_UnknownOperatorReturnsFalse(t *testing.T) {
	if claims.Eval("unknown", "x", "x") {
		t.Error("unknown operator should be false (defensive)")
	}
}
