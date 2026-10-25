# Product and OAuth client registration

## Registration boundary

Central Auth has separate `products`, `product_plans`, `product_organizations`, subscriptions, entitlement, membership, product-role and permission tables. This keeps product business records out of Central Auth.

There is currently **no supported product create/update API, web workflow or dedicated Artisan product-registration command**. The Master Admin product page is a read view. An operator must provision a product and its initial catalog data through the organization's approved database/change-management process after reviewing the migrations in `database/migrations/2026_10_24_220747_create_product_access_tables.php`. Do not treat direct writes as a public integration API. A controlled product-catalog provisioning command/API is a gap to resolve before repeatable product onboarding.

Use a permanent lowercase product slug (for example `suss`) and never recycle it for a different product. Products must be active before a product-bound OIDC client can be configured. Plans must reference the same product. Product organizations are scoped to one product and have independent tenant IDs.

## Create and bind the OAuth client

The built-in Passport client command supports authorization-code clients by default. Choose an exact callback URI and use a public client for native/browser-only clients, or a confidential client only when a trusted server can keep the secret. Use a dedicated client per deployed product environment and client application.

Example operator commands (examples only; not executed here):

```powershell
# Server-side confidential web client. Passport displays the secret only at creation;
# transfer it directly to the deployment secret manager, never source control.
php artisan passport:client --name="VisionWeb SUSS Staging" --redirect_uri="https://suss-staging.example.test/auth/central/callback" --no-interaction

# For a public client, choose --public and require PKCE.
php artisan passport:client --public --name="VisionWeb SUSS Mobile" --redirect_uri="https://suss.example.test/auth/callback" --no-interaction

# Replace <client-uuid> with the client ID, not its secret.
php artisan oidc:client:configure <client-uuid> --client-type=confidential --subject-type=pairwise --scopes=openid,profile,email,product_access --product=suss --logout-redirects="https://suss-staging.example.test/signed-out"
```

For the `--public` client, set `--client-type=public` in the configure command. For a confidential client, retain the default `confidential`. The configure command validates that the existing Passport client is not revoked and supports `authorization_code`; it checks public/confidential against whether that Passport client has a secret, requires `openid`, accepts only `openid`, `profile`, `email`, `phone`, `product_access`, and requires an active product slug when `product_access` is enabled. It always stores `require_pkce=true`, `require_consent=true`, and `enabled=true` unless `--disabled` is supplied. Consent is always shown by the current authorization controller; do not assume `require_consent=false` disables it.

`--logout-redirects` accepts a comma-separated exact allowlist. The command permits HTTPS URIs or HTTP localhost/loopback URIs and rejects fragments. The authorization redirect must also be registered in Passport and is matched exactly by Central Auth at request time. Do not use wildcard callbacks or untrusted redirect parameters.

The command's `--subject-type` can be `public` or `pairwise`; prefer `pairwise` for products that should not correlate a user across clients. Pairwise subject derivation depends on stable APP_KEY. Changing APP_KEY changes derived subjects unless the persisted subject mapping already exists; preserve APP_KEY and its backups.

## Values to record in product's deployment configuration

Store issuer and endpoints from `/.well-known/openid-configuration`, not from request input. Store `client_id`, the exact redirect URI, expected product slug, and—only for confidential backend clients—the secret in a secret manager. Never embed a confidential secret in JavaScript, mobile binaries, logs, issue reports, or checked-in config.

| Central Auth value | Source |
|---|---|
| Issuer | Discovery JSON `issuer`, exactly `rtrim(APP_URL, '/')` |
| Client ID | Passport UUID returned at client creation |
| Product slug | Active `products.slug` bound by the operator command |
| Callback | Exact URI registered on Passport client |
| Product scope | `product_access` only for a product-bound client |
| Client type | `confidential` or `public`, consistent with Passport client secret presence |

## Change and revoke procedures

Treat client redirect, product binding, scope and secret changes as security-sensitive deployment changes. The current configure command updates metadata for a client; review the change, redeploy the intended client config, and verify the discovery issuer and callback in staging. No web UI is provided for creating product clients. Central Auth Master Admin can revoke a client, which disables that client and revokes its Passport access/refresh tokens; tests cover that admin behavior. User logout has broader custom OIDC token impact, described in the OIDC guide.

Never rebind a client to another product as a shortcut for multi-product access. Register a separate client per product boundary. An authorization request cannot override `product` or `product_id`; Central Auth persists the server-configured product binding through the authorization code and opaque access token.

## Product-server credentials

The existing `POST /api/oidc/product-access` requires a separate server credential bound to the exact OIDC client and product. Provision it only after OIDC client metadata is enabled, the client is active and authorization-code capable, `product_access` is allowlisted, and the product binding resolves to an active product:

```powershell
php artisan auth:product-credential:create <client-uuid> --name="SUSS production API" --reason="Approved SUSS production integration" --expires-at="2027-01-25T00:00:00+00:00"
php artisan auth:product-credential:revoke <credential-uuid> --reason="Rotate SUSS API credential"
```

Both operations require an operator reason of 5–500 characters and confirmation unless `--force` is explicitly supplied. Creation requires future RFC 3339 expiry within one year, generates a 256-bit random secret, stores only Laravel's password hash, and displays the UUID/secret once. Revoke marks it unavailable immediately. Creates and revocations are written to security events and the hash-chained audit log; the secret is never recorded. The shell operator is recorded as console provisioning with no Central Auth user actor, so deployment process access and command-output retention must be controlled.

Send the user access token as `Authorization: Bearer <opaque-token>` and the server credential using `X-VisionWeb-Product-Credential` (credential UUID) plus `X-VisionWeb-Product-Secret` (64 lowercase hex characters). The credential's persisted client UUID and product ID must match the token row's client UUID/product ID and the active OIDC metadata binding. Therefore, a product with multiple OIDC clients provisions a separate server credential per client. This is exact client/product audience binding for the opaque token; it is not an `aud` claim inside that token. The optional JSON `product` field cannot authenticate a caller and only acts as a mismatch check.

For rotation, create a replacement with a future expiry, deliver it through secret management, deploy/test it, then revoke the old UUID. Expiring/revoked credentials, revoked/disabled clients, disabled OIDC metadata, changed product binding and inactive products all deny. Never expose the secret to browser JavaScript or commit it. This shared-secret mechanism does not provide mTLS or a standard OAuth introspection protocol.

## Onboarding record

For each product, record the product owner, product slug, environment, client UUID, client type, product binding, callback and logout URIs, scope allowlist, secret-manager location (not the secret), planned issuer/JWKS rotation handling, local identity mapping, product API authorization contract, tenant model, owner/seat policy, test evidence, incident contact and rollback/revocation procedure.
