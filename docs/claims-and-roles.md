# Claims, Filters, And Role Mapping

Deep semantics. The [README](../README.md) gives the one-paragraph version; this is the file to read when a rule isn't matching and you need to know why.

## The merged claims object

Every filter and role rule evaluates against a single `map[string]any` produced by `internal/auth.ExchangeCode`:

1. Start with the verified `id_token` claims.
2. Overlay userinfo claims; userinfo wins on collisions.
3. Plugin-generated claims are added last by the gate/map pass:
   - `silo_role` — the resolved role string.
   - `silo_link_by_email` — present only when `link_by_email=true`.

Filters and role mapping run against this combined object, so you can match on values that exist only in userinfo (`groups` on Authentik, for instance) and on id_token-only claims interchangeably.

## Claim paths

Dot-separated. Walks JSON objects only — there is no bracket indexing, no wildcards, no array-element addressing.

```
groups
realm_access.roles
custom.org.tier
```

Each segment must match `[A-Za-z_][A-Za-z0-9_-]*`. Empty segments, whitespace, quotes, and leading digits are rejected at Configure time, so a bad claim path fails validation before any login attempt sees it.

Resolution rules (`internal/claims.ResolvePath`):

- Walks objects step by step.
- A missing key at any depth returns `(nil, false)`.
- Encountering a non-object intermediate returns `(nil, false)` — you cannot dot into an array or a scalar.

`(nil, false)` is **"claim not found"**, which is distinct from "claim found but value is null". The simulator's `claim_found` flag exposes this.

## The four operators

Defined in `internal/claims/operator.go`. Behaviour is intentionally JSON-typed; values are compared with `reflect.DeepEqual` rather than string coercion.

### `equals`

JSON deep equality. Both sides must be the same type and value.

- `equals` against an array claim **always returns false**. Use `contains` for array membership.
- `null == null` is true.
- Numbers and booleans match on type and value (`equals 1` will not match the string `"1"`).

### `contains`

Two modes, selected by the type of the claim:

- **Array claim**: any element must `DeepEqual` the rule value. Typical case: `claim_path=groups, operator=contains, value="admins"`.
- **String claim**: substring match. The rule value must also be a string.
- Anything else (number, bool, null, object) returns false.

Mixing types: `contains value=1` against `groups=["1","2"]` is false — strings and numbers don't deep-equal.

### `starts_with`

String prefix. Both claim and value must be strings. Validation refuses non-string rule values at Configure time.

Useful for hierarchical groups (`org/foo/...`) or DN-style claims. Not anchored on word boundaries — `starts_with value="ad"` matches `"administrator"`.

### `regex`

RE2 syntax (Go's `regexp` package). Compiled twice — once at Configure time for validation (a bad pattern aborts the save), once per evaluation. For array claims, any element that string-matches passes; non-string elements are stringified with `fmt.Sprint` before matching.

Not anchored. `^` and `$` if you want anchoring. RE2 means no backreferences and no lookaround — same restrictions as Go's `regexp` package.

## `claim_filters` — gating sign-in

Evaluated in order; AND across rules. The first failure short-circuits the sign-in with `PermissionDenied: claim filter rejected`.

Failure conditions (any of these counts as "this rule failed"):

- Claim path doesn't resolve.
- Operator's evaluation returns false.

There is no negation. If you need "must not contain X", use a regex with negative lookahead — except RE2 has no lookaround, so in practice you'll write a positive expression for what you do want to see.

Empty filter list = no gating. The default config has no filters; every authenticated user passes through.

### Simulator behaviour

`/api/v1/admin/simulate-claims` runs `claims.TraceFilters` which evaluates **every** rule even after the first failure. The response includes one trace entry per rule with:

- `claim_found` — did the path resolve?
- `claim_value` — what was at that path? (`null` when not found)
- `match` — did this rule pass?

The overall `filters_passed` is the AND of all `match` flags. Use this to find rules that would fail in production *if* the user got past an earlier one — useful for catching latent bugs in rules nobody's exercised yet.

## `claim_role_mapping` — assigning roles

First-match-wins walk through `rules` in array order. The first rule whose claim resolves **and** evaluates true wins; its `role` is the answer.

- Default role: `user`. Returned when no rule matches.
- Allowed roles: `user` or `admin` only. Validation rejects anything else at Configure time.
- The role string is written into the merged claims as `silo_role`. The host's own role-mapping pass reads it as a hint — the host has final say on what role the Silo user ends up with.

### Ordering matters

Put most-specific rules first. A common shape:

```json
[
  {"claim_path": "groups", "operator": "contains", "value": "silo-admins", "role": "admin"},
  {"claim_path": "groups", "operator": "contains", "value": "silo-staff",  "role": "admin"},
  {"claim_path": "groups", "operator": "contains", "value": "silo-users",  "role": "user"}
]
```

The last rule is redundant (it would assign the default), but explicit-is-better-than-implicit if you ever flip the default.

### Trace from the simulator

`TraceRole` returns the index of the matching rule (or `-1` for the default fallback). The simulator surfaces both:

```json
{"role": "admin", "role_rule_index": 0}
```

When a user reports "I should be admin but I'm not", `role_rule_index` tells you which rule matched (often a too-permissive earlier rule grabbing them as `user` before the admin rule got a look).

## End-to-end example

Goal: only members of `staff` may sign in; members of `staff-admins` get admin; rest of staff get user.

```json
{
  "claim_filters": [
    {"claim_path": "groups", "operator": "contains", "value": "staff"}
  ],
  "claim_role_mapping": [
    {"claim_path": "groups", "operator": "contains", "value": "staff-admins", "role": "admin"}
  ]
}
```

- A user with `groups=["staff","staff-admins"]` passes the filter, hits the first mapping rule, ends up `admin`.
- A user with `groups=["staff"]` passes the filter, no mapping rule matches, falls through to default `user`.
- A user with `groups=["external"]` fails the filter; the role mapping never runs.
- A user with no `groups` claim at all fails the filter (missing-claim = no match).

## Edge cases worth knowing

- `groups` claims are sometimes strings (space-separated or comma-separated) instead of arrays. If your IdP does this, `contains` does substring matching — works, but be careful: `contains "admin"` would match `"administrators"` and `"badmin"`. Use `regex` with explicit word boundaries when this matters: `\\bsome-group\\b`.
- Nested-object access stops at the first non-object intermediate, so if a claim sometimes comes back as a string and sometimes as a structured value, your dotted path will fail silently for the string case. Filter first on the structured-form claim path, then map on it.
- Boolean claims (`email_verified`, custom flags): `equals true` (the JSON literal) is the way. `equals "true"` is a different rule and won't match the boolean.
- `regex` and `starts_with` against array claims work member-wise. `equals` against arrays does not — by design, to force operators to use `contains` for membership.
