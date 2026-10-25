# Laravel product integration

This guide describes how a future Laravel product can act as an OIDC relying party without importing Central Auth internals. The callback and JWT steps below are **pseudocode/architecture examples**, not a ready-made package or executed application. Select a maintained OIDC client library that supports authorization code, PKCE S256, nonce, issuer/audience validation, JWKS key refresh and safe session transactions. Do not hand-roll production JWT verification.

## Keep product identity local

Create a product-local identity mapping table with a unique key on `(issuer, subject)` and a foreign key to the product-local user. Store only the identity claims the product needs. `email` can change and may be absent; never use it as the immutable account key or automatically merge accounts because email strings match. If account linking is offered, require an authenticated, audited proof-of-control flow.

Do not add Central Auth's `User` model, database connection, `auth:api` guard, `RequireProductAccess` middleware or session cookie to the product. The Central Auth account and product account remain separate records.

## Login-start pattern (pseudocode)

Use discovery to obtain issuer and endpoints from trusted deployment configuration. The state, nonce and verifier must be random, short-lived, one-time and bound to the browser's login transaction. Keep verifier and nonce server-side for a web app; protect the transaction against CSRF and session fixation.

```php
// PSEUDOCODE: adapt to the selected maintained OIDC client and session store.
$state = base64url(random_bytes(32));
$nonce = base64url(random_bytes(32));
$verifier = base64url(random_bytes(32));
$challenge = base64url(sha256_binary($verifier));

store_pending_login(
    state: $state,
    nonce: $nonce,
    verifier: $verifier,
    created_at: now(),
    expires_at: now()->addMinutes(5),
);

redirect_to_discovered_authorization_endpoint([
    'client_id' => configured_client_id(),
    'redirect_uri' => configured_exact_callback(),
    'response_type' => 'code',
    'scope' => 'openid profile email product_access',
    'state' => $state,
    'nonce' => $nonce,
    'code_challenge' => $challenge,
    'code_challenge_method' => 'S256',
]);
```

Use only scopes registered for the client. `product_access` requires that client to be bound to an active product. A missing membership does not prevent identity login; the product decision later denies access.

## Callback pattern (pseudocode)

```php
// PSEUDOCODE: run validation with a maintained OIDC library.
$pending = consume_pending_login_from_current_session();
abort_unless($pending && ! $pending->expired(), 400);
abort_unless(hash_equals($pending->state, request('state', '')), 400);
abort_if(request()->filled('error'), 403);

$tokens = oidc_client()->exchangeCode(
    code: request('code'),
    redirectUri: configured_exact_callback(),
    codeVerifier: $pending->verifier,
);

$claims = oidc_client()->validateIdToken(
    jwt: $tokens->idToken,
    issuer: configured_exact_issuer(),
    audience: configured_client_id(),
    nonce: $pending->nonce,
    allowedAlgorithms: ['RS256'],
    jwksUri: discovered_jwks_uri(),
);

abort_unless($claims->visionweb_product === configured_product_slug(), 403);
$localUser = resolve_product_identity($claims->iss, $claims->sub);
login_product_user($localUser);
regenerate_product_session_id();
```

Also validate token expiry and issued-at; make state and nonce single-use; reject unknown `kid` only after an appropriate bounded JWKS refresh; enforce callback URI exactness; and avoid logging code, access token, ID token or verifier. If email verification is a product requirement, require `email_verified === true` as a separate policy; do not treat it as authorization for an organization.

## Product API authorization pattern

The following is also **pseudocode**. It illustrates a Laravel service boundary, not a currently provided Central Auth Laravel SDK:

```php
// PSEUDOCODE inside the product backend, after product-local authentication.
$resource = ProductRecord::query()
    ->where('tenant_id', $authorizedTenant->id)
    ->findOrFail($recordId);

abort_unless($resource->tenant_id === $authorizedTenant->id, 404);
$this->authorize('update', $resource); // Product-local policy.

$decision = Http::withToken($centralAccessToken)
    ->withHeaders([
        // These are product-owned config keys populated from its secret manager.
        'X-VisionWeb-Product-Credential' => config('services.central_auth.credential_id'),
        'X-VisionWeb-Product-Secret' => config('services.central_auth.credential_secret'),
    ])
    ->acceptJson()
    ->timeout(3)
    ->post($trustedCentralAuthProductAccessUrl, [
        'organization' => $authorizedTenant->central_auth_organization_uuid,
        'feature' => 'records', // Server-selected, not request input.
        'permission' => 'records.update', // Server-selected.
        'product' => 'your-product-slug', // Optional consistency hint.
    ]);

if ($decision->status() !== 200 || $decision->json('access') !== true) {
    abort(403);
}
abort_unless($decision->json('product') === 'your-product-slug', 403);
abort_unless($decision->json('organization') === $authorizedTenant->central_auth_organization_uuid, 403);
```

This endpoint now requires an expiring server credential bound to the exact OIDC client and product, as well as the user's opaque bearer token. Provision credentials with the commands in [Product registration](PRODUCT_REGISTRATION.md), store the secret in the product backend's secret manager, and send only over HTTPS. The token record's persisted OIDC client ID is checked against the credential's client binding and acts as the effective audience for the opaque token. No server secret belongs in browser JavaScript. Fail closed on timeout, malformed response or 401/403; do not treat network failure as allow.

This is a custom shared-secret contract, not mTLS or standard OAuth introspection; independent product-server identity and live deployed integration remain unverified. Do not claim product API security until the product validates its own user tokens and tests its own tenant/resource authorization.

## Product-local policies and identity

Use Laravel policies/gates for product-owned resources. The Central Auth organization UUID must map to a product-local tenant, and each database query must constrain by that local tenant. A successful Central Auth decision does not prove that a particular row belongs to that tenant. Re-check ownership in every operation and background job. Keep product roles such as Store Admin or Cashier inside the product's authorization model; do not map them to a universal Central Auth role.

## Test plan for the product

Before production, use isolated fixtures and test:

- Valid issuer, signature, audience, subject, nonce, state, PKCE and product claim.
- Unknown client, wrong callback, wrong issuer/audience, invalid signature, expired token, replayed state/nonce and mismatched product.
- Suspended/unverified user, missing/suspended membership, wrong organization, expired/suspended subscription, disabled feature, missing permission, exceeded seat and revoked token.
- Tenant/resource IDOR attempts across every read/write/export route.
- Central Auth/network outage is deny-by-default; no cached allow outlives its approved short TTL.
- Account linking cannot merge different `(iss, sub)` identities solely by matching email.

The Central Auth local integration fixture is `tests/Feature/OidcClientIntegrationTest.php`; it does not replace the product's own end-to-end tests.
