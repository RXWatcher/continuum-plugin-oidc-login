# IdP-Specific Cookbook

Each IdP has its own quirks around issuer paths, group claims, and how it spells "email verified". This file collects the recurring gotchas. Treat it as "things that surprised someone enough to write them down" rather than as a substitute for the IdP's own docs.

Common to all of them:

- The redirect URI registered with the IdP must be `https://<silo-host>/api/v1/auth/oauth/<install-id>/callback`. Exact-string match. Get the `<install-id>` from the Silo admin → Plugins detail page.
- Scopes must include `openid`. The plugin defaults to `openid profile email`; add IdP-specific scopes (e.g. `groups`) as needed.
- The IdP must publish a valid `/.well-known/openid-configuration` and a JWKS. The admin Discovery panel will tell you whether this is true from inside the plugin runtime.

## Authentik

- **Issuer URL**: `https://<authentik-host>/application/o/<application-slug>/`. The trailing slash is what Authentik publishes; the plugin strips it, but make sure the host portion matches exactly.
- **Groups claim**: only present in **userinfo**, not the id_token by default. The plugin merges userinfo into the claim set, so `claim_path=groups` works out of the box — but if you switched to a token-only flow, set up an Authentik "Scope Mapping" to also emit `groups` in the id_token.
- **email_verified**: Authentik emits it as a boolean. Default `email_verified_required=true` works.
- **Common error**: setting issuer URL to the Authentik root rather than the application's slug. Discovery succeeds but the issuer in the doc won't match what the plugin expects and `go-oidc` will fail at construction time with an issuer mismatch.

## Keycloak

- **Issuer URL**: `https://<keycloak-host>/realms/<realm>`. No trailing slash, no `/auth` prefix on Keycloak 17+ (older deployments may need `/auth/realms/<realm>`).
- **Groups claim**: not present by default. You must add a "Group Membership" client scope mapper on the client; pick "groups" as the token claim name and tick "Add to ID token" and "Add to userinfo". Without this, `claim_path=groups` always misses.
- **Realm roles vs. client roles**: realm roles land under `realm_access.roles`; client roles under `resource_access.<client-id>.roles`. Use the dotted path syntax accordingly.
- **email_verified**: boolean. Works out of the box.
- **Common error**: client configured as "confidential" in Keycloak but "Service Accounts Enabled" left off and "Standard Flow Enabled" turned off. The plugin needs the standard authorization code flow.

## Auth0

- **Issuer URL**: `https://<tenant>.auth0.com` (or your custom domain). No trailing slash.
- **Groups / roles**: not native OIDC claims. You either need Auth0 Actions / Rules to inject them as custom claims, **or** you map them to namespaced claim paths like `https://yourapp.example.com/roles`. Claim paths with `/` or `:` in segment names will not pass `ValidateClaimPath` (segment regex is `[A-Za-z_][A-Za-z0-9_-]*`), so use an underscored namespace token in Auth0's Action and a matching dotted path here.
- **email_verified**: boolean. Auth0 social connections (Google, GitHub) generally set it to true; database connections require email confirmation. Enabling `link_by_email` against Auth0 is risky unless you've explicitly disabled signup or vetted every connection.
- **Common error**: the Auth0 application is configured as "Single Page Application" (PKCE-only, public client). The plugin sends a `client_secret`; the IdP responds with `unauthorized_client`. Configure the application as "Regular Web Application" instead.

## Okta

- **Issuer URL**: depends on whether you're using the org authorization server (`https://<org>.okta.com`) or a custom one (`https://<org>.okta.com/oauth2/<authServerId>`, often `/oauth2/default`). Custom servers expose more claims and let you customise group claims; the org server is more limited.
- **Groups claim**: add a "Groups" claim under the auth server's claims tab; choose ID token *and* userinfo, regex or filter as needed.
- **email_verified**: present and boolean.
- **Common error**: using the org-level issuer when you needed a custom auth server (or vice-versa). Discovery succeeds either way; the failure is at id_token verification because the `iss` value won't match.

## Google

- **Issuer URL**: `https://accounts.google.com`. No customisation.
- **Groups / orgs / roles**: Google does not emit group memberships in id_tokens or userinfo. If you need group gating against Google, you have to do it host-side (e.g. matching domain) — the plugin's filter system can match `claim_path=hd` (hosted domain) for Workspace tenants:
  ```json
  {"claim_path": "hd", "operator": "equals", "value": "yourdomain.com"}
  ```
  `hd` is only present for Workspace accounts; consumer `@gmail.com` accounts won't have it, so this filter doubles as "Workspace-only".
- **email_verified**: boolean, almost always true.
- **link_by_email**: safe **only** if you also gate on `hd`. Without `hd`, anyone with a Gmail account matching an existing Silo email would be linked.

## Microsoft Entra ID (Azure AD)

- **Issuer URL**: `https://login.microsoftonline.com/<tenant-id>/v2.0`. The `/v2.0` suffix matters — without it you get v1 endpoints which emit a non-standard claim shape (`upn` instead of `preferred_username`, etc.).
- **Multi-tenant**: setting `<tenant-id>` to `common` or `organizations` is supported by Entra but the plugin's audience check still applies — make sure your app registration's audience matches.
- **Groups claim**: not present by default. Enable "Group claims" under Token configuration in the app registration (choose "Group ID" for opaque IDs or "sAMAccountName" if you've synced to AD).
- **email vs. preferred_username**: Entra often doesn't return `email` for personal Microsoft accounts. Either request the `email` optional claim under Token configuration, or fall back to `preferred_username` for the display fallback chain (the plugin already does this).
- **email_verified**: not always emitted. If you require it but Entra isn't sending it, the user is rejected with "email not verified". Either set `email_verified_required=false`, or configure Entra to issue an `email_verified` optional claim if your tenant supports it.
- **Common error**: registering the redirect URI as a "Single-page application" platform redirect URI in the app registration. Use "Web" platform instead — same URI but a different platform type, and only the latter accepts a client secret.

## GitLab

- **Issuer URL**: `https://gitlab.com` for the SaaS, or `https://gitlab.example.com` for self-managed. No trailing path.
- **Groups claim**: GitLab emits `groups_direct` (groups the user is a direct member of) and a few siblings. They're present only when the `openid` scope is accompanied by the right user-info scopes; the plugin's default `openid profile email` is usually enough for `groups_direct` to appear in userinfo.
- **email_verified**: GitLab emits it; behaviour is sane.
- **Common error**: registering the application at the group level rather than the user/instance level. Group-level applications restrict who can sign in via OAuth in ways that don't surface as a clean error — the user just sees a generic GitLab denial page.

## Generic / other IdPs

If your IdP isn't listed:

1. Use the Discovery panel to confirm the discovery doc and JWKS are reachable.
2. Trigger one real login and capture the id_token (Silo auth audit log at debug level).
3. Paste it into the Diagnostics panel — confirm the claim shape and which claims live in id_token vs. userinfo.
4. Write your filter and role-mapping rules against that claim set, run them through the Claim simulator before saving.

The plugin imposes only generic OIDC requirements: discovery, JWKS-verified id_tokens with nonce, code flow with PKCE, and either id_token or userinfo carrying the claims you want to filter on. Anything that ships a standards-compliant `/.well-known/openid-configuration` will work without per-IdP code.
