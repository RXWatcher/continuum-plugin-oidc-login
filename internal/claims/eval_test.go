package claims_test

import (
	"testing"

	"github.com/ContinuumApp/continuum-plugin-oidc-login/internal/claims"
	pluginrt "github.com/ContinuumApp/continuum-plugin-oidc-login/internal/runtime"
)

func TestEvaluateFilters_AllPass_AcceptsUser(t *testing.T) {
	c := map[string]any{
		"groups":         []any{"continuum-users", "engineering"},
		"email_verified": true,
	}
	filters := []pluginrt.ClaimFilter{
		{ClaimPath: "groups", Operator: "contains", Value: "continuum-users"},
		{ClaimPath: "email_verified", Operator: "equals", Value: true},
	}
	if err := claims.EvaluateFilters(c, filters); err != nil {
		t.Errorf("expected pass, got err = %v", err)
	}
}

func TestEvaluateFilters_OneFails_RejectsUser(t *testing.T) {
	c := map[string]any{"groups": []any{"other"}}
	filters := []pluginrt.ClaimFilter{
		{ClaimPath: "groups", Operator: "contains", Value: "continuum-users"},
	}
	if err := claims.EvaluateFilters(c, filters); err == nil {
		t.Error("expected rejection")
	}
}

func TestEvaluateFilters_MissingClaim_RejectsUser(t *testing.T) {
	c := map[string]any{"sub": "u-1"}
	filters := []pluginrt.ClaimFilter{
		{ClaimPath: "groups", Operator: "contains", Value: "continuum-users"},
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
	c := map[string]any{"groups": []any{"continuum-admins", "continuum-users"}}
	rules := []pluginrt.RoleMappingRule{
		{ClaimPath: "groups", Operator: "contains", Value: "continuum-admins", Role: "admin"},
		{ClaimPath: "groups", Operator: "contains", Value: "continuum-users", Role: "user"},
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

func TestResolveRole_NestedPath(t *testing.T) {
	c := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"continuum-admin"},
		},
	}
	rules := []pluginrt.RoleMappingRule{
		{ClaimPath: "realm_access.roles", Operator: "contains", Value: "continuum-admin", Role: "admin"},
	}
	if got := claims.ResolveRole(c, rules); got != "admin" {
		t.Errorf("nested = %q", got)
	}
}
