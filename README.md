# OIDC Login for Silo

`silo.oidc-login` is a generic OpenID Connect authentication provider for Silo. It is multi-instance by design — install one copy per identity provider (Authentik, Keycloak, Auth0, Okta, Google, Microsoft Entra ID, GitLab, or any IdP that publishes standard OIDC discovery metadata).

Reach for [`silo.whmcs-login`](https://github.com/RXWatcher/silo-plugin-whmcs-login) instead when WHMCS billing is your source of identity; this plugin is for IdPs that expose `/.well-known/openid-configuration` and JWKS-signed ID tokens.

## Category

Lives under **Auth** in the Silo plugin catalog.

## Capabilities

| Type | ID | Purpose |
| --- | --- | --- |
| `auth_provider.v1` | `oidc` | OAuth2 authorization-code login with OIDC discovery, JWKS-verified ID tokens, claim filtering, and merged userinfo claims returned to the host. |
| `http_routes.v1` | `spa` | Admin SPA exposing settings, claim-filter and role-mapping editors, discovery and token diagnostics, and a sign-in simulator. |

Declared HTTP routes:

| Route | Method | Access | Notes |
| --- | --- | --- | --- |
| `/assets/*` | `GET` | public | Bundled icons (Authentik, Keycloak, Auth0, Okta, Microsoft, Google, GitLab, generic key). |
| `/admin` | `GET` | admin | Navigable admin entry labelled "OIDC Login". |
| `/admin/*` | `GET` | admin | SPA sub-routes. |
| `/api/v1/admin/*` | `*` | admin | Admin JSON API consumed by the SPA. |
| `/api/v1/health` | `GET` | public | Liveness probe. |

## Dependencies

- Standalone auth provider. Plugs into the Silo host's `auth_provider.v1` plane; the host owns session creation and applies role mappings against the claims this plugin returns.
- A Postgres connection string (`database_url` in global config) is required. The plugin runs migrations on its dedicated `oidc_login` schema and uses it for persisted settings and claim/role rules.
- Built against [`continuum-plugin-sdk`](https://github.com/Silo-Server/silo-plugin-sdk) (Runtime, HttpRoutes, AuthProvider servers) and serves via the SDK runtime loop.

Host: [`Silo-Server/silo-server`](https://github.com/Silo-Server/silo-server).

## External services

- The configured OIDC identity provider — exactly one per install. The plugin talks outward to:
  - the issuer's discovery document (`<issuer>/.well-known/openid-configuration`),
  - its `authorization_endpoint` (browser redirect),
  - its `token_endpoint` (server-side code exchange),
  - its JWKS endpoint (ID token signature verification),
  - its `userinfo_endpoint` (best-effort claim enrichment).

No other outbound dependencies.

## Auth flow

1. The user picks this provider on the Silo login screen; the host calls `InitAuthorize`.
2. The plugin mints a fresh PKCE verifier (S256) and `nonce`, builds the authorize URL from the discovered `authorization_endpoint`, and returns it along with `provider_state` (pkce_verifier + nonce + state).
3. The IdP redirects back to `https://<silo-host>/api/v1/auth/oauth/<install-id>/callback` with `code` and `state`.
4. The host calls `ExchangeCode`. The plugin verifies the callback `state` (constant-time) against `provider_state`, exchanges the code with PKCE, verifies the ID token against JWKS (issuer, audience, expiry, signature), checks the nonce, and best-effort fetches userinfo (subject must match).
5. ID token claims and userinfo are merged (userinfo wins on collision). Optional `email_verified` enforcement and `claim_filters` gating run here.
6. The plugin returns `external_subject`, display name, email, and the merged claim set to the host. The host then applies its own role-mapping pass using the `silo_role` hint (and `silo_link_by_email` when enabled) that this plugin attaches to the claims.

## Claim filters and role mapping

The admin SPA provides visual editors for two ordered rule lists:

- **Claim filters** — every rule must match (AND semantics) before sign-in is allowed. A missing claim path counts as a failed match.
- **Role mapping** — rules are walked in order, first match wins, falling back to role `user`. Roles are restricted to `user` or `admin`.

Both share the same rule shape: a dotted `claim_path` (e.g. `realm_access.roles`), an `operator`, and a `value`. Supported operators are `equals`, `contains`, `starts_with`, and `regex`. `starts_with` and `regex` require string values; `regex` patterns are compiled at config validation time so malformed rules are rejected before they reach a login attempt.

The admin page also ships:

- a **Discovery panel** that hits `/.well-known/openid-configuration` from the plugin runtime and reports endpoints + JWKS reachability;
- a **Diagnostics panel** to paste an ID token, verify it against the live JWKS, and seed filter or role-mapping rules straight from a decoded claim;
- a **Claim simulator** that runs the configured filter/mapping rules against arbitrary claims (or the last decoded token) and shows per-rule traces, including which rule rejected a user.

Example — gate sign-in to a group, elevate one group to admin:

```json
{
  "claim_filters": [
    {"claim_path": "groups", "operator": "contains", "value": "silo-users"}
  ],
  "claim_role_mapping": [
    {"claim_path": "groups", "operator": "contains", "value": "silo-admins", "role": "admin"}
  ]
}
```

## Configuration

Global config is loaded by `internal/runtime` and stored in the plugin's own Postgres schema after install. `database_url` is the only manifest-level field; everything else is managed via the admin SPA.

| Key | Required | Description |
| --- | --- | --- |
| `database_url` | yes (manifest) | DSN for the dedicated `oidc_login` schema. |
| `issuer_url` | yes | OIDC issuer (origin URL). HTTPS required except for localhost. Trailing slash is stripped. |
| `client_id` | yes | OAuth client ID issued by the IdP. |
| `client_secret` | yes | OAuth client secret. Stored encrypted; the admin API exposes only a `has_client_secret` flag. |
| `scopes` | no | Space-separated scopes. Must include `openid`. Defaults to `openid profile email`. |
| `display_name` | no | Login-button label for this install. Defaults to `Sign in with OIDC`. |
| `icon_url_path` | no | Bundled icon filename, absolute http(s) URL, or root-relative path. |
| `claim_filters` | no | JSON array of `{claim_path, operator, value}` rules. AND semantics. |
| `claim_role_mapping` | no | JSON array of `{claim_path, operator, value, role}` rules. First-match wins; default `user`. |
| `email_verified_required` | no | Reject ID tokens with `email_verified=false`. Defaults to `true`. |
| `link_by_email` | no | When set, the plugin attaches `silo_link_by_email=true` to the returned claims so the host can link to an existing Silo user with the same email. Defaults to `false`. |

Redirect URI to register with the identity provider:

```text
https://<silo-host>/api/v1/auth/oauth/<install-id>/callback
```

Each install of the plugin gets its own `<install-id>` and therefore its own redirect URI — that's what makes the "install once per IdP" model work without collisions.

## Detailed docs

- [Operations and debugging runbook](docs/setup-debug-flows.md) — flow internals, error → cause mapping, live debugging checklist.
- [Claims, filters, and role mapping](docs/claims-and-roles.md) — semantics of paths, operators, AND filters, first-match role mapping.
- [Admin panels](docs/admin-panels.md) — what Discovery, Diagnostics, and Claim Simulator do and when to use each.
- [IdP cookbook](docs/idp-cookbook.md) — per-IdP gotchas (Authentik, Keycloak, Auth0, Okta, Google, Entra, GitLab).

## Build and release

```bash
make build      # builds the SPA (pnpm) then the Go binary
make test       # go test ./... + pnpm run test --run
```

CI builds linux-amd64 binaries on push to main via the reusable workflow in [RXWatcher/silo-plugin-repository](https://github.com/RXWatcher/silo-plugin-repository) and publishes them to the catalog at [`./binaries/`](https://github.com/RXWatcher/silo-plugin-repository/tree/main/binaries).
