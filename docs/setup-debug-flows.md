# OIDC Login — Operations And Debugging Runbook

Operator-facing depth notes. The [README](../README.md) covers what the plugin is, the high-level flow, and the configuration surface. This file is for the things you actually reach for when a login is failing at 2am.

Related docs in this directory:

- [claims-and-roles.md](claims-and-roles.md) — deep semantics of filters, role mapping, the four operators, and the simulator.
- [admin-panels.md](admin-panels.md) — what each admin panel does, what its responses mean.
- [idp-cookbook.md](idp-cookbook.md) — per-IdP gotchas (Authentik, Keycloak, Auth0, Okta, Google, Entra, GitLab).

## The flow, with the failure point for every step

The login dance is six hops. Knowing exactly which hop is failing is the entire job of this runbook.

```
 1. Discovery        plugin → IdP   GET /.well-known/openid-configuration
 2. Authorize        browser → IdP  redirect to authorization_endpoint
 3. Callback         IdP → host     302 to <host>/api/v1/auth/oauth/<install-id>/callback
 4. Token exchange   plugin → IdP   POST token_endpoint (auth code + PKCE verifier)
 5. JWKS verify      plugin local   verify id_token sig + iss + aud + exp + nonce
 6. UserInfo         plugin → IdP   GET userinfo_endpoint (best-effort, sub must match)
 7. Gate + map       plugin local   email_verified, claim_filters, role mapping
```

### Step 1 — Discovery

- Done once per Configure (initial install + every time global config changes), in `internal/oidc.NewProvider`. Failure aborts the Configure call; the plugin will refuse to start.
- The plugin uses `http.DefaultClient` — no proxy support, no custom CA bundle. If your IdP sits behind a corporate proxy or uses a private CA, discovery will fail with `Get .../.well-known/openid-configuration: ...`.
- The admin **Discovery panel** (`GET /api/v1/admin/discovery`) re-runs this fetch on demand from the plugin runtime and returns the raw doc + a JWKS summary. Use it before assuming the network path is fine.
- `issuer_url` is trimmed of trailing slashes at Configure time, so `https://idp.example.com/` and `https://idp.example.com` are the same. But the issuer string inside the discovery doc must match what the plugin requested — `go-oidc` enforces this. Mismatched issuers usually mean you configured `https://idp/` when the IdP advertises `https://idp` (or vice-versa with a path-suffix).

### Step 2 — Authorize

- `InitAuthorize` mints a fresh PKCE verifier (48 random bytes → base64url) and a 32-byte nonce per attempt. Verifier never leaves the plugin process; only the S256 challenge goes to the IdP.
- The redirect URI is supplied by the host per call (`req.GetRedirectUri()`) and overlaid on the cached `oauth2.Config`. Shape:
  ```
  https://<silo-host>/api/v1/auth/oauth/<install-id>/callback
  ```
  Every install gets its own `<install-id>`. If you reinstall the plugin you get a new ID; the old redirect URI registered with the IdP becomes dead weight and the new one must be registered before the first login attempt.
- The state value comes from the host and is round-tripped via `provider_state`. The plugin's stash also includes `pkce_verifier` and `nonce`.

### Step 3 — Callback

- The host is what receives the callback; the plugin is invoked through `ExchangeCode` afterwards. If the browser is hitting "not found" or "invalid client" before the plugin is involved, the problem is host-side or IdP-side, not the plugin.
- Common shape mistakes that look like plugin bugs but aren't:
  - IdP registered with `http://` instead of `https://`.
  - IdP registered with a different host (staging vs. prod).
  - Trailing slash on the redirect URI registered with the IdP — most IdPs do an exact-string match.
  - Reverse proxy stripping `/api/v1/auth/oauth/<install-id>/callback` because the path rule only forwards `/api/v1/*` to the host but not to the auth router.

### Step 4 — Token exchange

- Done by `golang.org/x/oauth2`. Client authentication mode is whatever the IdP advertises in discovery (`token_endpoint_auth_methods_supported`); the plugin doesn't override. If the IdP requires `client_secret_post` but advertises `client_secret_basic` first, expect cryptic 401s — most major IdPs are fine, see the IdP cookbook for the exceptions.
- The plugin's state check runs **before** token exchange and uses `crypto/subtle.ConstantTimeCompare`. If `provider_state.state` was empty (older host build), the check is skipped and the host is expected to do it upstream. New hosts always populate state.

### Step 5 — JWKS verify

- The `id_token` is verified by `go-oidc` against the JWKS fetched during discovery: signature (alg from JWKS header), issuer, audience (`client_id`), and expiry. Time skew is whatever `go-oidc` defaults to (about a minute); the plugin doesn't tune it.
- JWKS rotation: `go-oidc` caches keys with the library default (around 10 minutes). After a rotation on the IdP side, expect up to that cache window of "id_token verification: failed to verify signature" errors before the plugin picks up the new keys. Restarting the plugin forces a re-fetch.
- The plugin checks the nonce against the value it stashed in `provider_state` at step 2. A `nonce mismatch` means the same `provider_state` survived two flows (most likely the host re-played a stale state value, or the user opened the login link twice).

### Step 6 — UserInfo

- Best-effort. If the IdP returns an error, has no `userinfo_endpoint`, or the body fails to decode, the plugin proceeds with just the `id_token` claims.
- The one hard rule: if userinfo returns a `sub` and it disagrees with the `id_token`'s `sub`, the login is rejected with `userinfo subject mismatch`. This protects against a confused-deputy scenario where userinfo would shadow a `name`/`email` for a different account.
- userinfo claims merge on top of id_token claims — userinfo wins on collisions. Useful: many IdPs put rich claims (`groups`, custom claims) only in userinfo, not the id_token.

### Step 7 — Gate and map

- Three local passes after the merge, in order:
  1. `email_verified_required` (default true). The merged claim must be the boolean `true`. The string `"true"` does **not** pass — IdPs vary on this and the plugin enforces the OIDC spec. If your IdP only ever emits the string form, flip `email_verified_required` to false and add a `claim_filters` rule that checks for the string value instead.
  2. `claim_filters` — AND across rules. Missing claim path = failed match. First failure short-circuits.
  3. Role mapping — first match wins; default `user`. Written into `merged["silo_role"]`. The host applies its own role-mapping pass on top, but it consults `silo_role` as a hint.
- `link_by_email=true` writes `merged["silo_link_by_email"] = true`. The host reads that flag and may link to an existing Silo user with the same email. **The plugin itself never matches users — linking is entirely a host decision.**

## Per-install redirect URI

Two installs of this plugin = two `<install-id>` values = two independent redirect URIs. That's why the docs say "install once per IdP": the IdP doesn't know about Silo's install IDs, so two installs pointed at the same IdP with the same client would both have valid registrations but each would receive callbacks aimed at the other. The redirect URI is the disambiguator.

If you genuinely need two installs against the same IdP (e.g. different audiences), use two OAuth **clients** on the IdP side and register the matching redirect URI for each install separately.

## Error → likely cause cheatsheet

The plugin maps every failure path to a gRPC status code. Silo surfaces these in its auth audit log; you can also pull them from plugin process logs.

| gRPC code | Plugin message | Where it comes from | What to check |
| --- | --- | --- | --- |
| `Unimplemented` | "OIDC plugin is OAuth-only; use InitAuthorize / ExchangeCode" | `Authenticate` called by mistake | Host configuration; the plugin declares `auth_modes=["oauth2"]` only. |
| `FailedPrecondition` | "plugin not configured" | `InitAuthorize` or `ExchangeCode` before Configure | Configure didn't complete; check plugin logs for `oidc provider: ...` errors during startup. |
| `InvalidArgument` | "missing pkce_verifier or nonce in provider_state" | `ExchangeCode` got an empty/stale `provider_state` | Host replayed a request without re-running `InitAuthorize`. |
| `Unauthenticated` | "state mismatch" | constant-time state check failed | User opened two login tabs, or the callback was tampered with. |
| `Internal` | "token exchange: ..." | `oauth2.Exchange` failed | Wrong client secret, IdP returned 4xx, network/TLS error. Tail of the error is the IdP's response. |
| `Internal` | "no id_token in response" | IdP returned tokens without `id_token` | Scopes likely missing `openid`; check the configured `scopes`. |
| `Internal` | "id_token verification: ..." | JWKS sig/iss/aud/exp failure | JWKS rotation, clock skew, wrong audience, wrong issuer URL. |
| `Unauthenticated` | "nonce mismatch" | id_token's nonce ≠ stashed nonce | Replay attack or duplicate flow execution. |
| `Internal` | "decode id_token claims: ..." | id_token claims body wasn't a JSON object | Broken IdP. |
| `Unauthenticated` | "id_token missing subject" | no `sub` claim | Broken IdP. |
| `Unauthenticated` | "userinfo subject mismatch" | userinfo `sub` ≠ id_token `sub` | Confused-deputy condition; reject is correct, investigate IdP. |
| `PermissionDenied` | "email not verified" | `email_verified_required=true` and merged claim isn't boolean true | See "email_verified semantics" below. |
| `PermissionDenied` | "claim filter rejected" | AND-fail on `claim_filters` | Use the **Claim simulator** panel; it traces every rule, not just the first failure. |

## `email_verified_required` and `link_by_email` semantics

- `email_verified_required` (default `true`): the merged claim must be the literal boolean `true`. JSON `true` from id_token or userinfo both work. String `"true"`, integer `1`, or missing claim all fail. If your IdP emits strings only, set this to `false` and add `{"claim_path": "email_verified", "operator": "equals", "value": "true"}` to `claim_filters` instead — that gives you the same effective gate while sidestepping the type mismatch.
- `link_by_email` (default `false`): when `true`, the plugin tags returned claims with `silo_link_by_email=true`. The host uses that as permission to link this external login to a Silo user whose email already exists. **Only enable this if you trust that the IdP's `email` claim is verified and unique.** Auth0, Google, and Microsoft personal accounts can all let users sign up with arbitrary emails — enabling link-by-email against an untrusted IdP is account takeover.

## Common operator-side failure patterns

- Reverse proxy rule forwards `/admin/*` and `/api/v1/admin/*` but not `/api/v1/auth/oauth/<install-id>/callback` — login looks broken but admin UI works. The callback is owned by the host, not the plugin, so the rule needs to cover the host's auth router too.
- `database_url` points at the shared `public` schema. Migrations succeed (the schema's there), but you've polluted shared tables and other plugins/Silo core may collide. Use a dedicated `oidc_login` schema; the DSN should include `search_path=oidc_login` (see manifest description).
- Operator runs `curl` against `<issuer>/.well-known/openid-configuration` from their laptop, sees a 200, and concludes discovery should work. Discovery runs from the **plugin runtime** network. Use the admin Discovery panel.
- `email_verified` is the boolean `false` (user signed up but never confirmed). `email_verified_required=true` rejects them; nothing in the logs distinguishes "claim missing" from "claim is false" other than the message. Use the Claim simulator with the user's decoded id_token to see which it is.
- After reinstalling the plugin, the redirect URI changed (new `<install-id>`) but nobody updated the IdP. First login attempt fails with whatever the IdP's "unknown redirect_uri" error looks like — usually a generic IdP error before the plugin is ever invoked.
- Secrets rotate on host restart, invalidating encrypted `client_secret`. This shouldn't happen with a stable Silo install but does happen in dev when the host's secret-encryption key isn't pinned. Symptom: discovery still works (issuer is plaintext) but token exchange fails with `unauthorized_client`.

## Live debugging checklist

When a real user can't sign in, do these in order:

1. **Discovery panel** — if it errors, fix discovery; nothing else matters.
2. **Diagnostics panel** — paste the user's last id_token (the host's auth audit log can capture this when log level is debug, or have the user sign in to a dev instance and grab it from the IdP's user dashboard). It runs the live JWKS verifier and shows you exactly which claim values are present.
3. **Claim simulator** — paste the decoded claims, leave filters/role mapping at their saved values. The trace tells you which filter rejected the user, or what role they'd get.
4. **Plugin process logs** — every Configure call logs `configured issuer_url=... display_name=... provider_configured=...`. Every login failure logs the gRPC status. If you see no log line at all when the user attempts to sign in, the host never reached the plugin (callback routing issue).
5. **`/api/v1/health`** — a 200 here only confirms the plugin's HTTP routes are reachable. It says nothing about OIDC config or database health.

## Verification after a config change

1. Save in the SPA. The plugin re-runs Configure synchronously; a validation error is shown inline.
2. The plugin's logs will show a fresh `configured ...` line and `provider_configured=true` once the OIDC discovery completes.
3. Open Discovery panel → confirm `ok: true` and the JWKS summary has at least one key.
4. Run Claim simulator with a known-good claims set. Confirm the role and filter trace match expectations.
5. Sign in end-to-end from a private browser window. Private window matters: an existing host session can mask first-login bugs.
