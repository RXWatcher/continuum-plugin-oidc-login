package claims_test

import (
	"testing"

	"github.com/RXWatcher/silo-plugin-oidc-login/internal/claims"
	pluginrt "github.com/RXWatcher/silo-plugin-oidc-login/internal/runtime"
)

func TestEvaluateFilters_AllPass_AcceptsUser(t *testing.T) {
	c := map[string]any{
		"groups":         []any{"silo-users", "engineering"},
		"email_verified": true,
	}
	filters := []pluginrt.ClaimFilter{
		{ClaimPath: "groups", Operator: "contains", Value: "silo-users"},
		{ClaimPath: "email_verified", Operator: "equals", Value: true},
	}
	if err := claims.EvaluateFilters(c, filters); err != nil {
		t.Errorf("expected pass, got err = %v", err)
	}
}

func TestEvaluateFilters_OneFails_RejectsUser(t *testing.T) {
	c := map[string]any{"groups": []any{"other"}}
	filters := []pluginrt.ClaimFilter{
		{ClaimPath: "groups", Operator: "contains", Value: "silo-users"},
	}
	if err := claims.EvaluateFilters(c, filters); err == nil {
		t.Error("expected rejection")
	}
}

func TestEvaluateFilters_MissingClaim_RejectsUser(t *testing.T) {
	c := map[string]any{"sub": "u-1"}
	filters := []pluginrt.ClaimFilter{
		{ClaimPath: "groups", Operator: "contains", Value: "silo-users"},
	}
	if err := claims.EvaluateFilters(c, filters); err == nil {
		t.Error("missing claim should reject")
	}
}

func TestEvaluateFilters_EmptyList_NoGating(t *testing.T) {
	if err := claims.EvaluateFilters(map[string]any{}, nil); err != nil {
		t.Errorf("empty filters should always pass: %v", err)
	}
}

func TestResolveRole_FirstMatchWins(t *testing.T) {
	c := map[string]any{"groups": []any{"silo-admins", "silo-users"}}
	rules := []pluginrt.RoleMappingRule{
		{ClaimPath: "groups", Operator: "contains", Value: "silo-admins", Role: "admin"},
		{ClaimPath: "groups", Operator: "contains", Value: "silo-users", Role: "user"},
	}
	if got := claims.ResolveRole(c, rules); got != "admin" {
		t.Errorf("ResolveRole = %q, want admin", got)
	}
}

func TestResolveRole_NoMatch_DefaultsToUser(t *testing.T) {
	c := map[string]any{"groups": []any{"other"}}
	rules := []pluginrt.RoleMappingRule{
		{ClaimPath: "groups", Operator: "contains", Value: "admins", Role: "admin"},
	}
	if got := claims.ResolveRole(c, rules); got != "user" {
		t.Errorf("ResolveRole = %q, want user", got)
	}
}

func TestResolveRole_EmptyRules_DefaultsToUser(t *testing.T) {
	if got := claims.ResolveRole(map[string]any{}, nil); got != "user" {
		t.Errorf("default = %q", got)
	}
}

func TestTraceFilters_RunsAllFilters_AndReportsPerFilterMatch(t *testing.T) {
	c := map[string]any{
		"groups":         []any{"silo-users"},
		"email_verified": true,
	}
	filters := []pluginrt.ClaimFilter{
		{ClaimPath: "groups", Operator: "contains", Value: "silo-users"},
		{ClaimPath: "groups", Operator: "contains", Value: "missing-group"},
		{ClaimPath: "email_verified", Operator: "equals", Value: true},
	}
	trace, allPass := claims.TraceFilters(c, filters)
	if allPass {
		t.Error("expected overall fail because second filter doesn't match")
	}
	if len(trace) != 3 {
		t.Fatalf("trace length = %d, want 3", len(trace))
	}
	if !trace[0].Match || !trace[0].ClaimFound {
		t.Errorf("filter 0: expected match+found, got %+v", trace[0])
	}
	if trace[1].Match {
		t.Errorf("filter 1: expected no match, got %+v", trace[1])
	}
	if !trace[2].Match {
		t.Errorf("filter 2: expected match, got %+v", trace[2])
	}
}

func TestTraceFilters_MissingClaim_RecordsFoundFalse(t *testing.T) {
	trace, allPass := claims.TraceFilters(map[string]any{"sub": "u"}, []pluginrt.ClaimFilter{
		{ClaimPath: "groups", Operator: "contains", Value: "x"},
	})
	if allPass {
		t.Error("missing claim should fail overall")
	}
	if trace[0].ClaimFound {
		t.Error("ClaimFound should be false for missing claim")
	}
	if trace[0].Match {
		t.Error("Match should be false when claim is missing")
	}
}

func TestTraceFilters_EmptyList_PassesWithEmptyTrace(t *testing.T) {
	trace, allPass := claims.TraceFilters(map[string]any{}, nil)
	if !allPass {
		t.Error("empty filters should pass")
	}
	if len(trace) != 0 {
		t.Errorf("expected empty trace, got %d entries", len(trace))
	}
}

func TestTraceRole_ReturnsMatchedIndex(t *testing.T) {
	c := map[string]any{"groups": []any{"silo-admins"}}
	rules := []pluginrt.RoleMappingRule{
		{ClaimPath: "groups", Operator: "contains", Value: "engineering", Role: "user"},
		{ClaimPath: "groups", Operator: "contains", Value: "silo-admins", Role: "admin"},
	}
	role, idx := claims.TraceRole(c, rules)
	if role != "admin" || idx != 1 {
		t.Errorf("TraceRole = (%q, %d), want (admin, 1)", role, idx)
	}
}

func TestTraceRole_NoMatch_ReturnsMinusOne(t *testing.T) {
	role, idx := claims.TraceRole(map[string]any{}, []pluginrt.RoleMappingRule{
		{ClaimPath: "groups", Operator: "contains", Value: "admins", Role: "admin"},
	})
	if role != "user" || idx != -1 {
		t.Errorf("TraceRole = (%q, %d), want (user, -1)", role, idx)
	}
}

func TestResolveRole_NestedPath(t *testing.T) {
	c := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"silo-admin"},
		},
	}
	rules := []pluginrt.RoleMappingRule{
		{ClaimPath: "realm_access.roles", Operator: "contains", Value: "silo-admin", Role: "admin"},
	}
	if got := claims.ResolveRole(c, rules); got != "admin" {
		t.Errorf("nested = %q", got)
	}
}
