# continuum-plugin-oidc-login

Continuum plugin: generic OAuth2 / OIDC authentication. Multi-instance —
install once per IdP (Authentik, Keycloak, Auth0, Okta, Google, Azure AD,
GitLab, etc.).

Implements the `auth_provider.v1` capability with discovery, PKCE, and
JWKS-verified id_tokens. Includes an admin SPA at `/admin` for visual
editors of claim filters and role mapping, plus a Diagnostics panel for
decoding pasted id_tokens against the live JWKS.

## Build

```bash
make build           # builds web/dist then the Go binary
go test ./...        # plugin Go tests
cd web && pnpm run test --run    # SPA component tests
```

The binary embeds the SPA bundle and 8 placeholder icon SVGs.

## Capabilities

- `auth_provider.v1` (id `oidc`) — OAuth2 init + code exchange
- `http_routes.v1` (id `spa`) — bundled admin SPA + asset serving

## Config schema

| Key | Required | Description |
|---|---|---|
| `issuer_url` | yes | IdP base URL (discovery resolves `<issuer>/.well-known/openid-configuration`). |
| `client_id` | yes | OAuth client ID issued by the IdP. |
| `client_secret` | yes | OAuth client secret. |
| `scopes` | no | Space-separated OIDC scopes (default `openid profile email`). |
| `display_name` | no | Login button label (default `Sign in with OIDC`). Multi-IdP installs each set their own. |
| `icon_url_path` | no | Bundled icon SVG filename (default `generic-key.svg`). Must be one of: `authentik.svg`, `keycloak.svg`, `auth0.svg`, `okta.svg`, `microsoft.svg`, `google.svg`, `gitlab.svg`, `generic-key.svg`. |
| `claim_filters` | no | JSON array of `{claim_path, operator, value}` rules; ALL must pass for sign-in. |
| `claim_role_mapping` | no | JSON array of `{claim_path, operator, value, role}` rules; first match wins. |
| `email_verified_required` | no | Reject id_tokens with `email_verified=false` (default `true`). |
| `link_by_email` | no | Auto-link to existing user on email collision (default `false`; safer confirmation flow otherwise). |

## Claim filter / role mapping operators

- `equals` — JSON-typed deep equality.
- `contains` — array element membership OR string substring.
- `starts_with` — string prefix.
- `regex` — RE2 match (any element for array claims).

`claim_path` supports dot-notation for nested objects (e.g. `realm_access.roles`).

## Operator runbook

Per IdP install:

1. Build & upload via `make build` then `POST /api/v1/admin/plugins/uploads`.
2. Note the assigned `install_id`. The redirect URI to register at the IdP is
   `https://<continuum-host>/api/v1/auth/oauth/<install-id>/callback`.
3. At the IdP admin UI, register an OAuth client (type: confidential web).
   - Authentik / Keycloak / Okta / Auth0 / Microsoft / Google / GitLab —
     the discovery doc and JWKS work out of the box.
4. Open the plugin's `/admin` SPA, paste `issuer_url` + credentials, click
   **Test discovery** to confirm the IdP is reachable, then **Save**.
5. Add claim filters / role mapping rules as needed; the Diagnostics panel
   lets you paste an id_token and click claim names to auto-populate them.

## Example configurations

**Authentik with group gating + admin elevation:**

```jsonc
{
  "claim_filters": [
    { "claim_path": "groups", "operator": "contains", "value": "continuum-users" }
  ],
  "claim_role_mapping": [
    { "claim_path": "groups", "operator": "contains", "value": "continuum-admins", "role": "admin" }
  ]
}
```

**Google Workspace, restricted to one company domain:**

```jsonc
{
  "claim_filters": [
    { "claim_path": "hd",             "operator": "equals", "value": "company.com" },
    { "claim_path": "email_verified", "operator": "equals", "value": true }
  ]
}
```

**Keycloak with `realm_access.roles`:**

```jsonc
{
  "claim_filters": [
    { "claim_path": "realm_access.roles", "operator": "contains", "value": "continuum-access" }
  ]
}
```

## Architecture notes

- Stateless plugin: discovery + JWKS are cached in-process and rebuilt on
  each Configure call or restart.
- Built on `github.com/coreos/go-oidc/v3` for discovery, JWKS fetch, and
  id_token signature/nonce verification.
- Continuum host owns the `oauth_session` table, signed state, and the
  account-linking confirmation flow; this plugin contributes only the
  IdP-specific OAuth handling.

## Known limitations (out of scope for v1)

- No RP-initiated logout (continuum logout is local).
- No refresh tokens — users re-run the OAuth flow when their session expires.
- No backchannel / front-channel single logout.
- No dynamic client registration; pre-register the OAuth client at the IdP.
- Only `client_secret_post` (with `client_secret_basic` as discovery fallback)
  for token endpoint auth; `private_key_jwt` / `tls_client_auth` are TBD.

## Spec & plan

- Spec: `/opt/worktrees/continuum-rh/docs/superpowers/specs/2026-05-12-oidc-login-design.md`
- Plan: `/opt/worktrees/continuum-rh/docs/superpowers/plans/2026-05-12-oidc-login.md`
