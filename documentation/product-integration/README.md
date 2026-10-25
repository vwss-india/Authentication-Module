# Central Auth product integration

This folder is the onboarding entry point for a separately deployed VisionWeb product integrating with Central Auth 2.0. Read these documents in order:

1. [Central Auth integration guide](CENTRAL_AUTH_INTEGRATION_GUIDE.md)
2. [Product registration](PRODUCT_REGISTRATION.md)
3. [OIDC flow and token validation](OIDC_FLOW_AND_TOKEN_VALIDATION.md)
4. [Authorization and tenant security](AUTHORIZATION_AND_TENANT_SECURITY.md)
5. [Laravel product integration](LARAVEL_PRODUCT_INTEGRATION.md)
6. [Local, staging and production setup](LOCAL_STAGING_PRODUCTION_SETUP.md)
7. [Production deployment guide](PRODUCTION_DEPLOYMENT_GUIDE.md)
8. [Troubleshooting](TROUBLESHOOTING.md)

## Document index

| Document | Use it for |
|---|---|
| [CENTRAL_AUTH_INTEGRATION_GUIDE.md](CENTRAL_AUTH_INTEGRATION_GUIDE.md) | System boundaries, supported flow and onboarding sequence |
| [PRODUCT_REGISTRATION.md](PRODUCT_REGISTRATION.md) | Product records, Passport clients, product binding and controlled registration |
| [LARAVEL_PRODUCT_INTEGRATION.md](LARAVEL_PRODUCT_INTEGRATION.md) | Laravel relying-party and backend API patterns |
| [OIDC_FLOW_AND_TOKEN_VALIDATION.md](OIDC_FLOW_AND_TOKEN_VALIDATION.md) | Discovery, authorization, PKCE, callback, JWT and opaque access-token checks |
| [AUTHORIZATION_AND_TENANT_SECURITY.md](AUTHORIZATION_AND_TENANT_SECURITY.md) | Membership, subscriptions, entitlements, permissions and ownership |
| [LOCAL_STAGING_PRODUCTION_SETUP.md](LOCAL_STAGING_PRODUCTION_SETUP.md) | Environment, HTTPS, keys, deployment and operations |
| [PRODUCTION_DEPLOYMENT_GUIDE.md](PRODUCTION_DEPLOYMENT_GUIDE.md) | Consolidated release commands, secrets, migrations, operations and post-deployment verification |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Errors, causes and evidence-based investigation |

The accompanying [production environment template](CENTRAL_AUTH_PRODUCTION.env.example) contains blank secrets and replacement placeholders. Do not deploy it unchanged.

## Implementation status and limitations

The documentation reflects the checked-in Central Auth implementation as inspected on 2026-10-25. `tests/Feature/OidcFlowTest.php` and `tests/Feature/OidcClientIntegrationTest.php` exercise discovery, authorization-code + PKCE, token exchange, RS256 ID-token verification, userinfo and the product-access decision in the local test harness. This is automated local evidence, not a live separately deployed product integration.

| Status | Meaning in this guide |
|---|---|
| **Implemented and locally verified** | Code and cited automated tests cover the behavior. |
| **Implemented; deployment verification outstanding** | The implementation exists, but external infrastructure, browser behavior or deployed client has not been verified. |
| **Not implemented / integration gap** | Do not build a product on an assumed endpoint or capability; agree and implement the contract first. |

Important limits:

- Central Auth supports a custom OIDC discovery/authorization-code implementation, not every optional OpenID Connect endpoint or profile. Check the listed metadata and this guide; do not assume standard refresh, revocation, introspection or UserInfo behavior beyond what is listed.
- The current OIDC access token is opaque. Product APIs cannot validate it locally as a JWT. The product-access endpoint now requires a separate expiring server credential paired to the exact OIDC client and product, plus the user's opaque bearer token. This is implemented and covered by isolated feature tests; live deployment and secret custody are not verified. It is a custom contract, not standard OAuth introspection, and has no caller mTLS identity beyond the shared secret.
- Central Auth authenticates users and evaluates a product-level organization membership/subscription/entitlement/permission decision. It cannot authorize a product's invoices, bookings, inventory rows or other product-owned resources. Each product API must enforce its own tenant and record ownership.
- Product records do not have a dedicated supported self-service/API registration workflow. Client metadata can be configured through a deployment-controlled command only after the product and Passport client already exist.
- Product-server credentials are provisioned and revoked through deployment-controlled Artisan commands. There is no web admin workflow for their lifecycle; operator shell access is the privileged control plane.
- Usage-limit values are persisted and displayed, but the current product-access decision does not meter or enforce usage counts.
- No live SSO client, production TLS/key custody, SMTP inbox delivery, payment provider, or independent product API has been verified. Populated PostgreSQL migration compatibility remains unverified because an approved source backup is unavailable.

Source of truth: `routes/web.php`, `routes/api.php`, `app/Http/Controllers/Api/V1/OidcController.php`, `app/Console/Commands/ConfigureOidcClient.php`, `app/Console/Commands/CreateProductServerCredential.php`, `app/Console/Commands/RevokeProductServerCredential.php`, `app/Services/ProductAccessService.php`, `app/Services/ProductServerCredentialService.php`, `app/Http/Middleware/AuthenticateProductServer.php`, `app/Http/Middleware/RequireProductAccess.php`, `app/Http/Controllers/ProductAccessController.php`, migration `2026_10_24_230758_create_product_api_credentials_table.php`, and the tests cited in each guide.
