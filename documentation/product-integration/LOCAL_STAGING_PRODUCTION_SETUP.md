# Local, staging and production setup

## Environment separation

Use separate Central Auth and product deployments, client IDs, callback URLs, signing keys, issuer URLs, databases and secrets for local development, staging and production. Never point a product's production callback at local/staging or reuse a client secret across environments. Do not use production user data to test integration unless an approved, protected copy process exists.

For local work, use an isolated Central Auth test environment and a localhost callback registered on that environment's client. Authorization redirect matching is exact. HTTP callback URIs should be limited to loopback in development; use HTTPS for shared staging and production. The product must trust Central Auth issuer from deployment configuration—not from user request parameters.

## Central Auth configuration actually supported

The local deployment configuration needs the following checked settings; actual values belong in deployment secret/config management, never documentation or source control.

| Configuration | Requirement / implementation |
|---|---|
| `APP_ENV` | `production` for production. |
| `APP_DEBUG` | `false` in production. |
| `APP_URL` | Exact public HTTPS Central Auth origin. This is the OIDC issuer base and discovery URL source. |
| `APP_KEY` | Secret, stable encryption key. OIDC signing private key records are encrypted with Laravel Crypt; pairwise subject derivation also uses APP_KEY. Back up securely and plan re-encryption/identity impact before rotation. |
| `APP_PREVIOUS_KEYS` | Laravel key-transition support exists in `config/app.php`; preserve required previous keys during a controlled transition. It does not remove the need for an APP_KEY rotation plan. |
| `SESSION_SECURE_COOKIE`, `SESSION_HTTP_ONLY`, `SESSION_SAME_SITE` | Production config forces Secure and HttpOnly; use `true`, `true`, `lax` (or validate stricter policy with browser flows). Central Auth browser login/consent depends on its session and CSRF. |
| `TRUSTED_PROXIES` | Empty trusts no proxies. Behind reverse proxy, set exact trusted IP/CIDR entries; never wildcard. Check actual forwarded-proto behavior and public HTTPS URL. |
| `SECURITY_CSP_ENABLED` | Defaults enabled outside local/testing. Validate the actual browser pages/assets before overriding. |
| `CORS_PATHS`, `CORS_ALLOWED_ORIGINS`, `CORS_ALLOWED_METHODS`, `CORS_ALLOWED_HEADERS`, `CORS_MAX_AGE`, `CORS_SUPPORTS_CREDENTIALS` | Default empty/off. Keep same-origin unless the browser deployment truly needs cross-origin API access. If enabled, set exact origins/paths/methods/headers and only use credentials with explicit origins. |
| `OIDC_ACCESS_TOKEN_EXPIRE_MINUTES`, `OIDC_ID_TOKEN_EXPIRE_MINUTES`, `OIDC_KEY_RETENTION_MINUTES` | Configured in `config/auth.php`; default access token is 10 minutes, ID token 5 minutes, key retention 1440 minutes. Coordinate key retention with actual token lifetime and caches. |
| `MAIL_MAILER`, `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM_ADDRESS` | Laravel mail configuration; `.env.example` defaults to `log`, which does not prove delivery. Configure an approved provider and verify a real inbox before relying on email verification/recovery. Never put credentials in source control. |

Run `php artisan app:check-production-readiness` in the configured environment. It checks non-secret app/session/CSP/CORS/proxy settings only. A pass does not establish TLS/DNS, SMTP delivery, provider functionality, key custody, client integration, database backup or production readiness.

## Signing-key custody and rotation

Passport's OAuth keys and OIDC RS256 signing keys are related in current bootstrap behavior: if there is no active OIDC key record, OIDC loads Passport `oauth-private.key` and `oauth-public.key`, then stores a private-key copy encrypted under APP_KEY. OIDC publishes eligible public signing keys through `/oidc/jwks`; ID tokens carry `kid`. Do not print or copy key material into application logs, docs, tickets or client deployments.

Before deployment, the operator must provision or confirm existing keys through the controlled secrets process, restrict filesystem/database access, verify encrypted backup and restore, and retain old public keys during planned rotation. Never run `passport:keys --force` against existing keys as a troubleshooting shortcut. Rotation must account for current tokens, persisted OIDC signing-key rows, JWKS cache lifetime, application instances and APP_KEY encryption. No production key custody or rotation has been verified for this repository.

## SMTP and other providers

Automated tests can assert notification behavior but do not prove inbox delivery. Configure provider credentials in the deployment platform, deliver a test message to a controlled inbox, verify links use the public HTTPS `APP_URL`, and inspect sanitized mail/provider logs. SMS and WhatsApp currently fall back to registered email; do not describe them as delivered through their named channels. Payment persistence is not a payment-gateway integration; separately configure provider webhooks, signature verification, reconciliation and failure handling before accepting billing.

## Database, backup and retention

Keep product business databases separate from Central Auth. Migration `2026_10_24_230758_create_product_api_credentials_table.php` has now also succeeded on the separate fresh PostgreSQL 18.6 staging database `vwss_central_auth_staging_verify`; all 20 migrations are recorded there. The table's UUID/client/product constraints, lifecycle fields and two indexes were inspected. Staging is fresh, not restored, and contains no representative credential or OIDC rows. Populated OIDC-row compatibility and populated-table lock behavior remain unverified because there is no approved source/verified backup. Before any production schema deployment, confirm target identity, PostgreSQL version, backup owner/provenance and tested restore procedure. Never migrate the active application database as a verification step. See the [consolidated production deployment guide](PRODUCTION_DEPLOYMENT_GUIDE.md) for the required backup and forward-migration gate; do not claim populated-data compatibility or production lock behavior from this empty staging database.

Maintain encrypted backups and regularly test restore to a newly created isolated database. Define retention for security events, audit logs, incident reports, tokens and backups; restrict access and record deletion. Do not restore into an existing database or run destructive migration commands as a release check.

## Deployment and release steps

1. Provision isolated DB, queue/cache, secrets and HTTPS endpoint for each environment; verify target identity before migration.
2. Provision stable APP_KEY and Passport/OIDC signing keys through controlled secret operations; verify custody and recovery.
3. Set production app/session/CSP/proxy configuration and run the readiness command without exposing configuration values.
4. Provision active product and plan through approved catalog change control; create and bind an environment-specific authorization-code client.
5. Configure exact redirects, client secret handling, scopes and product slug; test against staging discovery/JWKS.
6. Verify real mailbox delivery and user verification/recovery; verify all required external provider contracts separately.
7. Run integration security tests including denial, tenant isolation, token expiry/revocation, JWKS rollover, outage behavior and product-local policies.
8. Deploy under change control with backup and rollback plan. Validate TLS, secure cookies, CSP browser console, proxy headers, audit events and monitoring.
9. Record release evidence, operator approvals, client configuration, incident contact, token/session remediation and rollback/revocation steps.

## Product-server credential deployment

The existing `POST /api/oidc/product-access` requires the product server credential reference and secret headers in addition to the end-user opaque bearer token. Create a credential only in an authorized Central Auth operator shell, after the product, authorization-code Passport client, OIDC metadata, `product_access` scope and product binding exist:

```powershell
php artisan auth:product-credential:create <client-uuid> --name="SUSS staging API" --reason="Approved SUSS staging integration" --expires-at="2027-01-25T00:00:00+00:00"
```

The command confirms unless `--force` is supplied, requires an operator reason, and requires a future RFC 3339 expiration no more than one year away. It prints a credential UUID and 256-bit random secret once. Capture this output only in a protected interactive terminal, place the secret directly in the product backend's secret manager, and do not save command output to build/deploy logs. The database stores only a Laravel password hash. Multiple active credentials may overlap for rotation. Deploy the replacement to the product, verify it, then revoke the old one:

```powershell
php artisan auth:product-credential:revoke <credential-uuid> --reason="Rotate SUSS staging credential"
```

These commands run under deployment shell/operator access; there is no web UI. Create/revoke operations write security events and hash-chained audit records without recording the secret. Credentials stop working when expired/revoked, their client is revoked/disabled, its product binding changes, or the product is inactive. Use TLS, restrict secret-manager access, rotate on staff/vendor changes or suspected disclosure, and do not expose credentials in browser code.

This is shared-secret service authentication and exact client/product audience binding, not mTLS, per-request signing or standardized introspection. Decide timeouts, bounded retries, any short decision cache, incident response and future service identity controls before production. Product-local resource ownership remains the product's responsibility.
