# OIDC Login Setup, Debugging, And Flows

Plugin ID: `continuum.oidc-login`
Version documented: `0.1.0`

## Purpose

generic OpenID Connect authentication provider for Continuum.

## Runtime Dependencies

- Continuum plugin host
- An OIDC provider with issuer metadata
- Registered redirect URI for this plugin installation

## Setup Checklist

1. Create an OIDC client in the identity provider.
2. Configure issuer_url, client_id, client_secret, scopes, and display_name.
3. Set claim filters or role mapping if access should be restricted.
4. Install/enable the provider in Continuum auth settings.
5. Test login in a private browser session and verify user linking behavior.

## Configuration Reference

- `issuer_url`
- `client_id`
- `client_secret`
- `scopes`
- `display_name`
- `icon_url_path`
- `claim_filters`
- `claim_role_mapping`
- `email_verified_required`
- `link_by_email`

Use the plugin manifest/admin form as the source of truth for field validation and defaults. Keep database credentials scoped to the plugin schema unless a plugin explicitly needs read access to Continuum core tables.

## Exposed Routes

- `GET /assets/* [public]`
- `GET /admin [authenticated]`
- `GET /admin/* [authenticated]`
- `* /api/v1/admin/* [authenticated]`
- `GET /api/v1/health [public]`

## Capabilities

- `auth_provider.v1 (oidc) - Generic OIDC authentication. Multi-instance: install once per IdP.`
- `http_routes.v1 (spa) - Visual editors for claim filters and role mapping.`

## Operational Flows

### Login

1. User chooses the OIDC button in Continuum.
2. The plugin redirects to the issuer authorization endpoint.
3. The issuer returns an authorization code to the plugin callback.
4. The plugin exchanges the code, validates tokens/claims, applies filters/mapping, and returns identity data to Continuum.
5. Continuum creates or links the user session.

## How This Plugin Communicates

- Implements auth_provider.v1 for Continuum core.
- Talks outward to the OIDC issuer.
- Does not need a plugin database for normal auth flow.

## Debugging Runbook

- Check /.well-known/openid-configuration from the plugin runtime when issuer discovery fails.
- Validate redirect URI exactly matches the provider registration.
- If users are rejected, inspect email_verified_required, claim_filters, and role mapping.
- If duplicate accounts appear, review link_by_email.
- Use /api/v1/health for a basic plugin route check.

## Log And Health Checks

- Start with Continuum Admin -> Plugins and confirm the installation is enabled.
- Check the plugin process logs around startup for manifest loading, migration, and route registration.
- Check scheduled task logs when a workflow depends on polling or reconciliation.
- Confirm the plugin routes are reachable through Continuum using the access level shown above.
- For database-backed plugins, verify the configured role can connect, create/migrate tables in its schema, and read/write expected rows.

## Common Failure Patterns

- Wrong installation ID selected in a portal or router setting after reinstalling a plugin.
- Plugin database URL points at the public schema instead of the dedicated plugin schema.
- Reverse proxy forwards the SPA route but not `/api/*`, `/api/v1/*`, `/assets/*`, or provider-specific public routes.
- Network checks are run from the operator laptop instead of from the Continuum/plugin runtime network.
- Secrets are regenerated during restart, invalidating signed URLs, encrypted fields, or login state.

## Verification After Changes

1. Restart or reload the plugin installation.
2. Open the plugin route or admin page in Continuum.
3. Exercise the smallest workflow that crosses a plugin boundary.
4. Confirm both the source plugin and destination plugin record the same request/session/login identifier.
5. Leave the scheduled reconciler enough time to run, then confirm terminal state or a useful error.
