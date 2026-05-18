# OIDC Login for Continuum

`continuum.oidc-login` adds generic OAuth2/OIDC sign-in to Continuum. It is a
multi-instance auth provider: install it once per identity provider, such as
Authentik, Keycloak, Auth0, Okta, Google, Microsoft Entra ID, or GitLab.

Use this plugin when your identity provider supports standard OIDC discovery
and JWKS-verified ID tokens. Use `continuum.whmcs-login` when your user source
is WHMCS billing.

## Detailed Operations Docs

- [Setup, debugging, and communication flows](docs/setup-debug-flows.md)

## Features

- OAuth2 authorization-code flow with PKCE.
- OIDC discovery via `<issuer>/.well-known/openid-configuration`.
- JWKS verification for ID tokens.
- Per-install display name and icon.
- Claim filters to allow or deny sign-in.
- Claim role mapping to assign Continuum roles.
- Optional email verification enforcement.
- Optional email-based account linking.
- Admin SPA for configuration, discovery testing, claim filter editing, role
  mapping, and token diagnostics.

## Configuration

| Key | Required | Description |
|---|---|---|
| `issuer_url` | yes | OIDC issuer URL. HTTPS is required except for localhost testing. |
| `client_id` | yes | OAuth client ID issued by the identity provider. |
| `client_secret` | yes | OAuth client secret. |
| `scopes` | no | Space-separated scopes. Must include `openid`. Defaults to `openid profile email`. |
| `display_name` | no | Login-button label for this install. |
| `icon_url_path` | no | Bundled icon filename managed by the admin SPA. |
| `claim_filters` | no | JSON array of rules that must pass before sign-in is allowed. |
| `claim_role_mapping` | no | JSON array of rules that map claims to Continuum roles. |
| `email_verified_required` | no | Reject ID tokens with `email_verified=false`. Defaults to true. |
| `link_by_email` | no | Auto-link to an existing Continuum user when email collides. Defaults to false. |

Redirect URI to register at the identity provider:

```text
https://<continuum-host>/api/v1/auth/oauth/<install-id>/callback
```

## Claim Rules

Claim paths use dot notation for nested objects, for example
`realm_access.roles`. Supported operators:

- `equals`
- `contains`
- `starts_with`
- `regex`

Example group gate and admin mapping:

```json
{
  "claim_filters": [
    {"claim_path": "groups", "operator": "contains", "value": "continuum-users"}
  ],
  "claim_role_mapping": [
    {"claim_path": "groups", "operator": "contains", "value": "continuum-admins", "role": "admin"}
  ]
}
```

## Setup

1. Install the plugin and note the assigned installation ID.
2. Register an OAuth client in the identity provider using the redirect URI
   above.
3. Open the plugin admin page in Continuum.
4. Enter issuer URL, client ID, client secret, and scopes.
5. Test discovery and configure claim filters or role mapping as needed.

## Build And Test

```bash
make build
go test ./...
cd web && pnpm run test --run
```
