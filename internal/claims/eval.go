package claims

import (
	"errors"

	pluginrt "github.com/RXWatcher/silo-plugin-oidc-login/internal/runtime"
)

// ErrFilterRejected is returned by EvaluateFilters when at least one filter
// fails. Callers translate this into a gRPC PermissionDenied error.
var ErrFilterRejected = errors.New("claim filter rejected")

// EvaluateFilters returns nil if all filters pass (AND semantics). A missing
// claim path is treated as filter failure (no match). Empty filter list means
// no gating and always passes.
func EvaluateFilters(c map[string]any, filters []pluginrt.ClaimFilter) error {
	for _, f := range filters {
		v, ok := ResolvePath(c, f.ClaimPath)
		if !ok {
			return ErrFilterRejected
		}
		if !Eval(f.Operator, v, f.Value) {
			return ErrFilterRejected
		}
	}
	return nil
}

// ResolveRole walks rules in order; first match wins. Default: "user".
// Silo host applies this role on every login (via its existing
// role-mapping pass, fed by the merged claims this plugin returns).
func ResolveRole(c map[string]any, rules []pluginrt.RoleMappingRule) string {
	role, _ := TraceRole(c, rules)
	return role
}

// FilterTrace records the per-filter evaluation result for the admin
// simulator. Unlike EvaluateFilters (which short-circuits), TraceFilters runs
// every filter so the SPA can show admins which rule rejected the user.
type FilterTrace struct {
	Index      int    `json:"index"`
	ClaimPath  string `json:"claim_path"`
	Operator   string `json:"operator"`
	Value      any    `json:"value"`
	ClaimValue any    `json:"claim_value"`
	ClaimFound bool   `json:"claim_found"`
	Match      bool   `json:"match"`
}

// TraceFilters runs every filter against c and returns a per-filter trace plus
// the overall pass flag. Empty filter list passes.
func TraceFilters(c map[string]any, filters []pluginrt.ClaimFilter) ([]FilterTrace, bool) {
	out := make([]FilterTrace, 0, len(filters))
	allPass := true
	for i, f := range filters {
		v, found := ResolvePath(c, f.ClaimPath)
		match := found && Eval(f.Operator, v, f.Value)
		if !match {
			allPass = false
		}
		out = append(out, FilterTrace{
			Index:      i,
			ClaimPath:  f.ClaimPath,
			Operator:   f.Operator,
			Value:      f.Value,
			ClaimValue: v,
			ClaimFound: found,
			Match:      match,
		})
	}
	return out, allPass
}

// TraceRole returns the assigned role plus the index of the rule that matched
// (or -1 for the default fallback).
func TraceRole(c map[string]any, rules []pluginrt.RoleMappingRule) (string, int) {
	for i, r := range rules {
		v, ok := ResolvePath(c, r.ClaimPath)
		if !ok {
			continue
		}
		if Eval(r.Operator, v, r.Value) {
			return r.Role, i
		}
	}
	return "user", -1
}
