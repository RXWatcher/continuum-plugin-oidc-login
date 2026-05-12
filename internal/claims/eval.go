package claims

import (
	"errors"

	pluginrt "github.com/ContinuumApp/continuum-plugin-oidc-login/internal/runtime"
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
// Continuum host applies this role on every login (via its existing
// role-mapping pass, fed by the merged claims this plugin returns).
func ResolveRole(c map[string]any, rules []pluginrt.RoleMappingRule) string {
	for _, r := range rules {
		v, ok := ResolvePath(c, r.ClaimPath)
		if !ok {
			continue
		}
		if Eval(r.Operator, v, r.Value) {
			return r.Role
		}
	}
	return "user"
}
