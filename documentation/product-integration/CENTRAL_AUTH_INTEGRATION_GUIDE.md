# Central Auth integration guide

## Architecture and responsibility boundaries

Central Auth is the shared identity provider. It stores central accounts, authentication state, security settings/events, OAuth clients and tokens, product catalog/plan/subscription/entitlement data, organization memberships and product-role permission mappings.

Each separately deployed product owns its own database, local user mapping, business data, business roles, and authorization for every product resource. Do not copy sales, finance, booking, inventory or other product records into Central Auth. Do not treat Central Auth login as permission to use every product or every tenant.

The current implementation performs these checks at the Central Auth product-access endpoint: active and verified user; active product and organization; active membership and matching product-role permission; active/trialing current subscription for the organization and product; active verified subscription owner; seat count within plan limit; and both the `access` and requested feature entitlement enabled. The product must still check its own tenant and resource ownership.

## Status of the integration flow

**Implemented and locally verified:** OIDC discovery; authorization-code flow; exact registered redirect matching; authorization state echo; required nonce; PKCE S256; consent screen; one-time five-minute authorization code; token exchange; short-lived opaque bearer access token; RS256 ID token; JWKS; userinfo; logout and allowlisted post-logout redirect; product-bound client metadata and token/code; product-access decision with a server credential and exact client/product audience checks. Evidence is in `OidcFlowTest`, `OidcClientIntegrationTest` and `ProductServerAccessTest`.

**Not verified in deployment:** separate process/browser SSO, external DNS/TLS, production signing-key custody, production cookies/proxies, email inbox delivery, and PostgreSQL behavior on populated OIDC tables.

**Not implemented / gap:** refresh token for the custom OIDC token table, standard OAuth revocation/introspection endpoints, mTLS or service identity independent of a shared secret, role/feature usage metering, and product registration UI/API. The current logout revokes all custom OIDC access tokens belonging to the signed-in user, not only the current client.

## End-to-end onboarding

1. Agree the product's stable slug, Central Auth issuer, callback/logout URLs, web/mobile topology, needed OIDC scopes, and product-level feature/permission keys.
2. Register an active product through an approved Central Auth operator/schema provisioning process. No supported product CRUD endpoint/command currently exists.
3. Create an OAuth authorization-code client with exact redirect URI(s). Public clients must use PKCE; confidential clients keep their client secret only on a trusted server.
4. Configure OIDC metadata and the immutable product binding with `oidc:client:configure`; see [Product registration](PRODUCT_REGISTRATION.md).
5. Integrate discovery and authorization-code flow as described in [OIDC flow](OIDC_FLOW_AND_TOKEN_VALIDATION.md). The product generates and checks state, nonce and PKCE verifier itself.
6. Verify the ID-token signature and claims before mapping a local product identity. Use `(issuer, sub)` as the external identity key; do not key a product account by email.
7. Provision an expiring client/product-bound server credential using the operator-only commands in [Product registration](PRODUCT_REGISTRATION.md). Keep its secret only in backend secret storage.
8. For product features, the product backend calls the product-access endpoint using both its server credential and the user's valid Central Auth bearer token; server-select organization, feature and permission. Treat the result as an additional gate, not a replacement for local policy.
9. Create or map the user's product-local account and tenant association only after successful authentication and applicable authorization. Do not provision broad roles based solely on email or identity claims.
10. Verify denial behavior, tenant isolation, logout/revocation consequences, key rollover handling and incident response in isolated staging before release.

## Product integration contract

Central Auth emits an ID token with `iss` equal to `rtrim(APP_URL, '/')`, `aud` equal to the registered OIDC client UUID, `sub` either the user's public UUID or a client-specific pairwise HMAC subject, `iat`, `exp`, `auth_time`, `nonce`, and `at_hash`. It signs with RS256 and publishes RSA public keys with `kid` at the JWKS URI. Scope-dependent claims include `name` and `preferred_username` (`profile`), email fields (`email`), phone fields (`phone`), and `visionweb_product` (`product_access` when client is product-bound).

The `product_access` scope and `visionweb_product` claim identify the client's configured product. They do not prove the user has a current membership, subscription, entitlement, role permission, tenant membership or record ownership. Request a fresh product-access decision at the backend for each protected operation or according to a short, explicitly risk-approved cache policy.

The product-access request accepts `organization` (UUID), `feature` and `permission`; optional `product` is only a consistency hint and must match the persisted client binding. The API derives both product and OIDC client from the authenticated server credential, then requires the user's opaque token record to match that exact client and product. For this custom decision contract, the stored token `oauth_client_id` is the effective client audience; opaque access tokens do not contain a JWT `aud`. A user must not choose permission strings or organization identifiers that the server blindly trusts: the product backend should select them from its own route/policy and current resource tenant.

See [Authorization and tenant security](AUTHORIZATION_AND_TENANT_SECURITY.md) for required local authorization and known gaps, and [Laravel product integration](LARAVEL_PRODUCT_INTEGRATION.md) for a relying-party pattern.

## No shared Central Auth internals

Separate products must not connect to Central Auth's database, reuse its Eloquent models or `RequireProductAccess` middleware, share session cookies, inspect token hashes, or assume they can trust its private signing key. Integrate through the published issuer/JWKS and documented HTTPS endpoints. Keep local business authorization and identity mapping within the product.
