package claims_test

import (
	"testing"

	"github.com/RXWatcher/continuum-plugin-oidc-login/internal/claims"
)

func TestResolvePath_TopLevel(t *testing.T) {
	m := map[string]any{"sub": "abc", "groups": []any{"a", "b"}}
	if v, ok := claims.ResolvePath(m, "sub"); !ok || v != "abc" {
		t.Errorf("sub = %v ok=%v", v, ok)
	}
	if v, ok := claims.ResolvePath(m, "groups"); !ok {
		t.Errorf("groups missing")
	} else if got, ok2 := v.([]any); !ok2 || len(got) != 2 {
		t.Errorf("groups = %v", v)
	}
}

func TestResolvePath_Nested(t *testing.T) {
	m := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"r1", "r2"},
		},
	}
	v, ok := claims.ResolvePath(m, "realm_access.roles")
	if !ok {
		t.Fatalf("nested missing")
	}
	got, ok2 := v.([]any)
	if !ok2 || got[0] != "r1" {
		t.Errorf("nested = %v", v)
	}
}

func TestResolvePath_DeepNested(t *testing.T) {
	m := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": "deep",
			},
		},
	}
	v, ok := claims.ResolvePath(m, "a.b.c")
	if !ok || v != "deep" {
		t.Errorf("deep = %v ok=%v", v, ok)
	}
}

func TestResolvePath_Missing(t *testing.T) {
	m := map[string]any{"sub": "abc"}
	if _, ok := claims.ResolvePath(m, "groups"); ok {
		t.Errorf("groups should be missing")
	}
	if _, ok := claims.ResolvePath(m, "extra.role"); ok {
		t.Errorf("extra.role should be missing")
	}
}

func TestResolvePath_NonObjectMid(t *testing.T) {
	m := map[string]any{"sub": "abc"}
	// sub is a string — can't traverse into it.
	if _, ok := claims.ResolvePath(m, "sub.x"); ok {
		t.Errorf("sub.x should be missing")
	}
}

func TestResolvePath_EmptyPath(t *testing.T) {
	m := map[string]any{"sub": "x"}
	if _, ok := claims.ResolvePath(m, ""); ok {
		t.Errorf("empty path should be missing")
	}
}
