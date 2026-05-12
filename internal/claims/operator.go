package claims

import (
	"fmt"
	"regexp"
	"strings"
)

// Eval returns true if the given operator over (claimValue, ruleValue) holds.
// Returns false for unknown operators (defensive: the operator name should
// already have been validated at Configure time).
func Eval(operator string, claimValue, ruleValue any) bool {
	switch operator {
	case "equals":
		return equals(claimValue, ruleValue)
	case "contains":
		return contains(claimValue, ruleValue)
	case "starts_with":
		return startsWith(claimValue, ruleValue)
	case "regex":
		return regexMatch(claimValue, ruleValue)
	}
	return false
}

// equals does deep JSON-typed equality. Arrays don't equal non-arrays — use
// contains instead.
func equals(a, b any) bool {
	if _, ok := a.([]any); ok {
		return false
	}
	return a == b
}

// contains has two modes:
//   - array claim: element membership (any element equals the rule value)
//   - string claim: substring match (rule value must also be a string)
//
// Anything else (numbers, bools, nil) returns false.
func contains(claim, value any) bool {
	switch v := claim.(type) {
	case []any:
		for _, e := range v {
			if e == value {
				return true
			}
		}
		return false
	case string:
		s, ok := value.(string)
		if !ok {
			return false
		}
		return strings.Contains(v, s)
	}
	return false
}

// startsWith is a string prefix check; false for non-strings on either side.
func startsWith(claim, value any) bool {
	c, okC := claim.(string)
	v, okV := value.(string)
	if !okC || !okV {
		return false
	}
	return strings.HasPrefix(c, v)
}

// regexMatch compiles `value` as an RE2 regex and matches against claim. For
// array claims, passes if any element (stringified) matches. Invalid patterns
// return false (Configure validation should have caught these already).
func regexMatch(claim, value any) bool {
	pattern, ok := value.(string)
	if !ok {
		return false
	}
	rx, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	switch v := claim.(type) {
	case string:
		return rx.MatchString(v)
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && rx.MatchString(s) {
				return true
			}
		}
		return false
	default:
		return rx.MatchString(fmt.Sprint(claim))
	}
}
