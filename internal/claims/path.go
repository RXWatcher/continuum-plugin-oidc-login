// Package claims evaluates claim_filter and claim_role_mapping rules
// against a merged claims object (id_token + userinfo).
package claims

import "strings"

// ResolvePath walks dot-separated keys into m. Returns (value, true) on hit,
// (nil, false) when the path doesn't fully resolve to a value (missing key
// or an intermediate that isn't a JSON object).
func ResolvePath(m map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	parts := strings.Split(path, ".")
	var cur any = m
	for _, p := range parts {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := obj[p]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}
