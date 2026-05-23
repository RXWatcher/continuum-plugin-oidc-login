# Admin Panels — Discovery, Diagnostics, Claim Simulator

The plugin's admin SPA at `/admin` exposes three diagnostic panels in addition to the settings/claim-filter/role-mapping editors. They exist so an operator can answer "is this thing working?" without needing to trigger a real OAuth flow against the live IdP.

All three panels are admin-only (`X-Silo-User-Role: admin`); they live behind `requireAdmin` in `internal/admin/server.go`.

## Discovery panel

What it does: server-side fetch of `<issuer_url>/.well-known/openid-configuration` from the plugin runtime, plus a summary of the JWKS it points at.

Use it when:

- Initial setup, to confirm `issuer_url` is right and the IdP is reachable from the plugin's network.
- After a network/proxy/firewall change, to confirm outbound HTTPS from the plugin still works.
- Diagnosing "id_token verification: failed to verify signature" errors — the JWKS summary shows whether the IdP is currently advertising keys at all.

Endpoint: `GET /api/v1/admin/discovery` (10-second timeout, 10 MiB body cap).

Response on success: the raw discovery document, plus:

- `ok: true`
- `jwks_keys`: an array of `{kid, kty, alg, use}` objects, one per JWK. Empty/missing if the JWKS fetch failed.

Response on failure: `200 OK` with `{"ok": false, "error": "..."}`. The handler deliberately doesn't return non-200 — the SPA renders the error inline.

Common failure shapes:

- `dial tcp ...: i/o timeout` — outbound HTTPS blocked or DNS broken in the plugin's network. The plugin uses `http.DefaultClient`; no proxy or custom CA support.
- `x509: certificate signed by unknown authority` — IdP using a private CA; you need that CA in the plugin's trust store (or run a TLS-terminating proxy).
- `discovery 404: <body>` — `issuer_url` is wrong. Most IdPs have a trailing-path issuer (Keycloak's `/realms/<realm>`, Auth0's bare host); see [idp-cookbook.md](idp-cookbook.md).
- `invalid JSON: ...` — IdP returned HTML (login wall) instead of JSON. Usually a path-not-quite-right that's hitting a generic landing page.

## Diagnostics panel

What it does: takes an `id_token` you paste in, verifies it against the live JWKS (issuer, audience, expiry, signature), and returns the decoded claims.

Use it when:

- A specific user is being rejected and you want to see what claims the IdP is actually emitting for them.
- Designing a new filter or role-mapping rule and you want a real example claim set rather than handcrafted JSON.
- Confirming JWKS rotation completed (a token signed with a recently-rotated key should verify cleanly here once the plugin's JWKS cache picks it up; otherwise restart the plugin to force a re-fetch).

Endpoint: `POST /api/v1/admin/decode-id-token` with body `{"id_token": "..."}`.

Response: `{"verified": true|false, "claims": {...}|null, "error": "..."}`. Verification failures return `verified: false` plus the underlying `go-oidc` error message; the panel renders the message verbatim.

Where to get an id_token to paste:

- Silo's auth audit log at debug log level captures id_tokens for failed/rejected logins.
- The IdP's own user dashboard (Authentik, Keycloak admin console) can usually issue one on demand.
- An end-to-end OAuth dance done with a tool like `oidc-client` if you have a developer console.

Note that pasted tokens are not persisted; the SPA can wire the decoded claims into a "seed filter rule" or "seed role-mapping rule" shortcut, but the token itself is in-memory only.

## Claim simulator

What it does: runs the **same** filter, email-verified, and role-mapping pass that `ExchangeCode` performs after merging id_token + userinfo, but against admin-supplied claims and (optionally) unsaved rule sets.

Use it when:

- Authoring rules — paste a claim set, try filter shapes, see immediately which rules would reject the user and why.
- Reproducing "this user can't sign in" reports — paste claims from the Diagnostics panel and confirm the gate behaviour without touching the user's account.
- Confirming a role change before saving — set `filters` and `role_mapping` to your draft, get a per-rule trace.

Endpoint: `POST /api/v1/admin/simulate-claims` with body:

```json
{
  "claims": { "...": "..." },
  "filters": [...],
  "role_mapping": [...],
  "email_verified_required": true
}
```

`filters`, `role_mapping`, and `email_verified_required` are optional pointers. Omit them to use the saved config; supply them to preview unsaved page state.

Response shape:

```json
{
  "allowed": true,
  "filters_passed": true,
  "filter_trace": [
    {"index": 0, "claim_path": "groups", "operator": "contains", "value": "staff",
     "claim_value": ["staff"], "claim_found": true, "match": true}
  ],
  "email_verified_check": {
    "required": true, "claim_found": true, "claim_value": true, "passed": true
  },
  "sub_present": true,
  "role": "user",
  "role_rule_index": -1,
  "identity": {"sub": "abc", "email": "a@b", "name": "..."}
}
```

Key fields:

- `allowed` — final yes/no: filters passed AND email-verified check passed AND `sub` is present.
- `filter_trace` — every rule, even after the first failure. Use `claim_found=false` to spot typos in claim paths.
- `role_rule_index` — index of the rule that won the role assignment, or `-1` if no rule matched and the default `user` was used.
- `identity` — what the host would receive as the user's `sub`/`email`/`name`. Same name fallback as `ExchangeCode`: `name` → `given_name + family_name` → `given_name` → `family_name` → `email`.

The simulator runs entirely server-side using the same `internal/claims.TraceFilters` and `TraceRole` functions, so a result here is faithful to what a real login attempt would do.

## What none of these panels do

- They do not contact the IdP's token endpoint. Token-exchange errors (`oauth2: cannot fetch token`) only show up in a real login attempt or in plugin process logs.
- They do not test the redirect URI registration. The Discovery panel confirms the IdP is reachable, but only an actual login (or an explicit `curl` from the IdP side) confirms the redirect URI is registered correctly.
- They do not exercise the host's session creation or role mapping. The simulator returns the claims the plugin *would* hand to the host; what the host does with `silo_role` and `silo_link_by_email` is its own concern.
