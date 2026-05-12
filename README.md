# continuum-plugin-oidc-login

Continuum plugin: generic OAuth2 / OIDC authentication. Multi-instance —
install once per IdP (Authentik, Keycloak, Auth0, Okta, Google, Azure AD,
GitLab, etc.).

Implements the `auth_provider.v1` capability with discovery, PKCE, and
JWKS-verified id_tokens. Includes an admin SPA at `/admin` for visual
editors of claim filters and role mapping, plus a Diagnostics panel for
decoding pasted id_tokens against the live JWKS.

## Capabilities

- `auth_provider.v1` (id: `oidc`) — OAuth2 init + code exchange
- `http_routes.v1` (id: `spa`) — bundled admin SPA + asset serving

## Config schema

| Key | Required | Description |
|---|---|---|
| `issuer_url` | yes | IdP base URL (discovery resolves `<issuer>/.well-known/openid-configuration`) |
| `client_id` | yes | OAuth client ID |
| `client_secret` | yes | OAuth client secret |
| `scopes` | no | Space-separated OIDC scopes (default `openid profile email`) |
| `display_name` | no | Login button label (default `Sign in with OIDC`) |
| `icon_url_path` | no | Bundled icon SVG filename (default `generic-key.svg`) |
| `claim_filters` | no | JSON array of `{claim_path, operator, value}` rules; all must pass |
| `claim_role_mapping` | no | JSON array of `{claim_path, operator, value, role}` rules; first match wins |
| `email_verified_required` | no | Reject id_tokens with `email_verified=false` (default `true`) |
| `link_by_email` | no | Auto-link to existing user on email collision (default `false`) |

See [`docs/superpowers/specs/2026-05-12-oidc-login-design.md`](https://example.invalid)
for full design notes.
