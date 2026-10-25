# OIDC flow and token validation

## Supported metadata and endpoints

Fetch discovery from `GET /.well-known/openid-configuration` at the configured issuer. Current metadata advertises:

- Authorization Code response only (`response_types_supported: ["code"]`).
- `RS256` ID-token signing.
- Scopes `openid`, `profile`, `email`, `phone`, `product_access`.
- Token endpoint authentication methods `client_secret_basic`, `client_secret_post`, `none`.
- PKCE challenge method `S256` only.
- UserInfo, JWKS, custom product-access, and custom end-session endpoint URLs.

| Method and path | Function |
|---|---|
| `GET /.well-known/openid-configuration` | Current discovery document |
| `GET /oidc/jwks` | RSA signing public keys in JWKS format (`kid`, `RS256`) |
| `GET /oidc/authorize` | Authenticated browser authorization request |
| `POST /oidc/authorize/approve` | CSRF-protected browser consent decision |
| `POST /oidc/token` | Authorization-code exchange; returns opaque bearer access token and ID token |
| `GET /oidc/userinfo` | User claims using a valid opaque bearer token |
| `POST /oidc/logout` | Browser session logout and custom OIDC token revocation; optional allowlisted redirect |
| `POST /api/oidc/product-access` | Central product/org/entitlement/permission decision for a valid product-bound token |

Routes are defined in `routes/web.php` and `routes/api.php`; behavior is in `OidcController`.

## Authorization request

Generate independent cryptographically random `state`, `nonce`, and PKCE `code_verifier` in the relying party. Persist them server-side or in a secure short-lived browser transaction bound to the initiating user-agent/session. Send only the S256 challenge. Redirect the user to the discovered authorization endpoint with:

```text
client_id=<registered-client-uuid>
redirect_uri=<exact-registered-callback>
response_type=code
scope=openid email product_access
state=<one-time-random-value>
nonce=<one-time-random-value>
code_challenge=<BASE64URL(SHA256(code_verifier))>
code_challenge_method=S256
```

`product` and `product_id` request parameters are prohibited. Product binding is loaded from Central Auth's registered client metadata. `product_access` requires that binding to reference an active product. The user must have an active, email-verified Central Auth account and authenticate to the web session. Current implementation always displays consent. Central Auth exact-matches `redirect_uri` against the Passport client list and restricts scopes to the configured allowlist including `openid`.

On approval, Central Auth returns `code` and the original `state` to the exact callback. Denial returns `error=access_denied` and state. The code is random, stored as a SHA-256 hash, expires after five minutes, is tied to client, exact redirect, scopes, product binding, nonce and PKCE challenge, and is one-time-use.

## Callback and token exchange

At the callback, first compare returned `state` to the exact pending transaction. Reject missing/mismatched state, errors, stale transaction or unexpected issuer/client. Exchange the code from the product backend over TLS at the discovered token endpoint, using the original redirect URI and PKCE verifier. Confidential clients authenticate with Basic or POST client secret; public clients send no secret. Never put a confidential secret in a browser.

The custom exchange accepts `grant_type=authorization_code`, `client_id` (unless Basic auth supplies it), `client_secret` (for POST auth), `code`, `redirect_uri`, and `code_verifier`. It checks client status/type/secret, exact code/client/redirect, expiry, one-use and S256 verifier, current client scope/binding, and active verified user. The JSON response contains `access_token`, `token_type=Bearer`, `expires_in`, `id_token`, and `scope`; there is no refresh token. The access token is a random opaque bearer string whose hash is stored. Default configured lifetimes are 10 minutes for the OIDC access token and 5 minutes for the ID token (`config/auth.php`); token `expires_in` is returned by the server. Treat values as runtime configuration, not hardcoded client assumptions.

## Validate the ID token

Use a maintained OIDC/JWT library in the product. Do not write ad hoc JWT validation in production. Fetch the issuer's JWKS over authenticated HTTPS, select the RSA key by `kid`, verify signature and allow only the discovered `RS256` algorithm. Then require:

1. `iss` exactly equals the configured discovery issuer (currently `rtrim(APP_URL, '/')`).
2. `aud` contains exactly the expected client identity; current tokens set a string client UUID. Reject unexpected audiences. No `azp` claim is currently emitted; if a future token has multiple audiences, require and validate `azp` according to the relying-party library/policy.
3. Signature is valid, `exp` is in the future, `iat` is acceptable and not unreasonably future-dated, and `nonce` equals the pending one-time value.
4. The callback transaction's `state` matches; PKCE was enforced at the token endpoint using the verifier retained by this client.
5. For product clients, `visionweb_product` equals the product slug configured for this client. This claim is present only with `product_access` scope and an active product binding.
6. Validate `at_hash` against the returned access token if the client library supports/mandates this claim. Central Auth includes it in the ID token.

The `sub` is client-specific identity: default `public` subject mode returns the Central Auth `users.public_id`; `pairwise` uses a persisted client-specific subject, initially derived by HMAC using APP_KEY. Persist the product account mapping under `(issuer, sub)`, not email. Email and phone claims are optional scope-dependent profile data, not stable identity keys or authorization grants.

Current claims: standard `iss`, `sub`, `aud`, `iat`, `exp`, `auth_time`, `nonce`, `at_hash`; with `profile`: `name`, `preferred_username`; with `email`: `email`, `email_verified`; with `phone`: `phone_number`, `phone_number_verified`; with a bound `product_access` client: `visionweb_product`. No organization, role, permission, subscription, feature entitlement or business-resource ownership claim is issued.

## UserInfo and opaque token validation

Send the opaque access token only in `Authorization: Bearer <token>` to discovered UserInfo or the custom product-access endpoint over TLS. Central Auth hashes and looks up the token and checks not revoked, not expired, client not revoked, OIDC metadata enabled, and user active/verified. `GET /oidc/userinfo` returns only claims permitted by stored scopes. Do not decode the access token, treat it as a JWT, store it in local storage, log it, or accept it as proof of product entitlement.

`POST /api/oidc/product-access` requires both the user's `Authorization: Bearer <opaque-token>` and product-server headers `X-VisionWeb-Product-Credential: <credential-uuid>` and `X-VisionWeb-Product-Secret: <64-hex-secret>`. JSON is `{ "organization": "<organization-uuid>", "feature": "<feature-key>", "permission": "<permission-key>" }`, with optional `product` as a matching consistency hint. Require `product_access` scope. The credential is bound in Central Auth to one registered OIDC client and one product. The user's token row must match that exact client and product; the token is opaque and has no JWT `aud` claim, so the persisted client ID is the effective audience check at this endpoint. The endpoint then checks current Central Auth organization access. Product backends—not browsers—must choose organization, feature and permission based on their route and local policy.

Missing, invalid, expired or revoked server credentials return `401 invalid_product_server_credentials`; wrong token/client/product audience, wrong product hint or denied access returns `403`; a valid decision returns `200`. The custom shared-secret mechanism requires TLS, stores only a password hash, supports expiring overlapping credentials and revocation, and records create/revoke actions. It is not standard OAuth introspection and does not provide mTLS, a separate service identity beyond the secret, or product-server credential delivery beyond operator-controlled CLI provisioning. Keep the secret in backend secret storage; never expose it in browser code.

## Logout, revocation and key rotation

`POST /oidc/logout` requires the Central Auth web session and browser CSRF token. With a signed-in user it revokes all that user's custom OIDC access tokens, logs out the Central Auth web guard, invalidates the session and regenerates the CSRF token. Optional `client_id` plus `post_logout_redirect_uri` must match the client's exact configured post-logout allowlist; optional state is returned. This is broader than per-client logout. It does not expose a bearer-token revocation endpoint or make already copied ID tokens disappear.

Admin revocation of an OAuth client disables the client and revokes Passport access/refresh tokens; token lookups also reject disabled OIDC clients. The signed-in user's Connected Applications page can revoke that user's tokens for one client, including custom OIDC access tokens. Standard `/oauth/revoke`, introspection, refresh-token and offline-access flows are not implemented for the custom OIDC token store. In addition, the current logout endpoint revokes all the user's custom OIDC access tokens regardless of client. Plan short token lifetime and account/session remediation accordingly.

Central Auth exposes valid non-retired/non-expired RS256 keys via JWKS. Retain old public keys long enough for clients to validate tokens signed before rotation. No live rotation/custody verification is recorded; follow [deployment setup](LOCAL_STAGING_PRODUCTION_SETUP.md).

## Evidence

- `tests/Feature/OidcFlowTest.php`: discovery/JWKS, signature and claims, failed verifier, replay, redirect and PKCE rejection, expiry/revocation, logout redirect, client configuration.
- `tests/Feature/OidcClientIntegrationTest.php`: local relying-party redirect/login/consent/code exchange, state/nonce/PKCE, JWKS signature, claims, userinfo, product binding, subscription/membership denials and tampering.
- `tests/Feature/ProductServerAccessTest.php`: server credentials, revocation/expiry and operator lifecycle commands, valid decision, client/product audience isolation and membership denial.

These are test-harness integrations, not a separately deployed browser client.
