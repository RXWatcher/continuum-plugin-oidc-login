# continuum-plugin-oidc-login

Generic OAuth2 / OIDC authentication for Continuum. **Multi-instance** — install once per identity provider (Authentik, Keycloak, Auth0, Okta, Google, Azure AD, GitLab, etc.). Each install configures one IdP independently.

Implements OAuth2 + PKCE with discovery and JWKS-verified id_tokens. Includes an admin SPA at `/admin` for visual editors of claim filters and role mapping, plus a Diagnostics panel for decoding pasted id_tokens against the live JWKS.

Companion plugin to [`continuum.whmcs-login`](../continuum-plugin-whmcs-login/) — pick this one when your IdP speaks standard OIDC.

## Capabilities

| Capability | Notes |
|---|---|
| `auth_provider.v1` (`oidc`) | OAuth2 init + code exchange. |
| `http_routes.v1` (`spa`) | Bundled admin SPA at `/admin`, plus `/assets/*`. |

The redirect URI to register at each IdP is `https://<continuum-host>/api/v1/auth/oauth/<install-id>/callback`.

## Configuration

| Key | Required | Description |
|---|---|---|
| `issuer_url` | yes | IdP base URL; discovery resolves `<issuer>/.well-known/openid-configuration`. |
| `client_id` | yes | OAuth client ID issued by the IdP. |
| `client_secret` | yes | OAuth client secret. |
| `scopes` | no | Space-separated OIDC scopes (default `openid profile email`). |
| `display_name` | no | Login-button label (default "Sign in with OIDC"). Each install picks its own. |
| `icon_url_path` | no | Bundled SVG filename. One of: `authentik.svg`, `keycloak.svg`, `auth0.svg`, `okta.svg`, `microsoft.svg`, `google.svg`, `gitlab.svg`, `generic-key.svg`. |
| `claim_filters` | no | JSON array of `{claim_path, operator, value}` rules. **All** must pass for sign-in. |
| `claim_role_mapping` | no | JSON array of `{claim_path, operator, value, role}` rules. First match wins. |
| `email_verified_required` | no | Reject id_tokens with `email_verified=false` (default `true`). |
| `link_by_email` | no | Auto-link to existing user on email collision (default `false`; safer confirmation flow otherwise). |

## Claim filter / role mapping operators

- `equals` — JSON-typed deep equality.
- `contains` — array element membership OR string substring.
- `starts_with` — string prefix.
- `regex` — RE2 match (any element for array claims).

`claim_path` supports dot-notation for nested objects (e.g. `realm_access.roles`).

## Example — Authentik with group gating + admin elevation

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

## Dependencies

- No Postgres schema (stateless).
- Outbound HTTPS to the configured IdP's discovery + JWKS endpoints.

## Install (per IdP)

1. `make build`, upload via `POST /api/v1/admin/plugins/uploads`.
2. Note the assigned `install_id`. The redirect URI to register at the IdP is `https://<continuum-host>/api/v1/auth/oauth/<install-id>/callback`.
3. At the IdP admin UI, register an OAuth client (type: confidential web). Authentik / Keycloak / Okta / Auth0 / Microsoft / Google / GitLab — the discovery doc and JWKS work out of the box.
4. Open the plugin's `/admin` SPA, paste `issuer_url` + credentials, click **Test discovery**, then **Save**.
5. Add claim filters / role mapping rules as needed; the Diagnostics panel lets you paste an id_token and click claim names to auto-populate them.

## Build & test

```bash
make build           # builds web/dist then the Go binary
go test ./...        # plugin Go tests
cd web && pnpm run test --run    # SPA component tests
```

The binary embeds the SPA bundle and 8 placeholder icon SVGs.

## Status

v0.1.0. Functional.
