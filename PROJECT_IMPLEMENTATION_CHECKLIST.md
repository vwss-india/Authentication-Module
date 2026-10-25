# VisionWeb Central Auth 2.0 implementation checklist

Updated: 2026-10-25 (local deployment and UI/UX completion verification)

The implementation preserves the pre-existing portal work and the untracked `visionweb-app-ui-kit/` source tree. PostgreSQL migrations were run only on the fresh isolated `vwss_central_auth_staging_verify` database (18.6); the active database was inspected read-only and not migrated.

Historical checkpoint sections retain their earlier counts. The later **Final local deployment and UI/UX verification** section is authoritative for the current run's results and remaining tasks.

## Completed work and evidence

| Feature | Status | Implementation and evidence |
|---|---|---|
| Public landing page, shared responsive portal layout, kit styling and assets | Implemented and verified (build); browser rendering not fully verified | `resources/views/welcome.blade.php`, `resources/views/layouts/portal.blade.php`, `resources/css/app.css`, `resources/js/app.js`, `vite.config.js`; local Bulma/theme/JS imports; `npm.cmd run build` passed |
| Web login/logout, passkey login handoff, account, profile and password change | Implemented and verified in feature tests | `WebSessionController`, `AccountSecurityController`, account/login views; `AccountSecurityWebTest`, `WebSessionAuthTest` |
| Registration, email verification/resend, password recovery | Implemented and verified in feature tests; real inbox not verified | Auth browser pages plus existing API workflow; `PasswordRecoveryTest`, `AuthApiTest`, `PortalTest`; SMS/WhatsApp selection honestly falls back to registered email |
| MFA/TOTP, recovery codes, trusted devices/sessions and passkeys | Browser workflows implemented; server actions and integration paths tested; physical WebAuthn browser ceremony not verified | `resources/views/security-settings.blade.php`, web-session routes to existing `MfaController`/`WebAuthnController`, `AccountSecurityWebTest`, `MfaFlowTest`, `WebAuthnFlowTest` |
| Connected OAuth applications and security activity | Implemented and verified in feature tests | User-scoped revocation and event queries in `AccountSecurityController`; `PortalTest`, `AccountSecurityWebTest` |
| Master Admin provisioning and authorization | Implemented and verified in focused tests | `CentralAdmin`, `RequireCentralAdmin`, `RequireCentralAdminPermission`, grant/revoke console commands; browser/API route permissions; grant reasons are 5–500 chars, wildcard grants require `--allow-wildcard`, and account status is rechecked under row locks; `AdminAuthorizationTest` (10 tests, 56 assertions after final hardening) |
| Admin users, account status/remediation, event/audit views, OAuth client review/revocation | Implemented and verified | `AdminController`, protected admin routes and views; tests cover guest/user/limited-admin/full-admin behavior, secret omission, revocation and audit |
| User incident reporting and private status view | Implemented and verified | `IncidentController`, `security_incidents`, private owner-scoped reports; `SecurityIncidentTest` |
| Admin incident investigation, immutable original evidence, notes, transitions and remediation | Implemented and verified in feature tests | `incident_investigation_entries` keeps notes separate; guarded route permissions and audit; `SecurityIncidentTest` |
| Product catalog, plans, organization subscriptions, entitlement/permission decision | Implemented and verified in feature tests | `ProductAccessService`, `RequireProductAccess`, `ProductAccessController`; migration `2026_10_24_220747_create_product_access_tables.php`; `ProductAccessTest` |
| Owner-managed staff membership using the owner subscription | Implemented and verified | Organization owner-only member workspace, verified-account assignment, organization role validation, transaction/seat checks, membership suspension; `ProductAccessTest` |
| OAuth/OIDC integration | Automated local relying-party flow implemented and verified; separate deployed client/browser not verified | `OidcClientIntegrationTest` executes authorization, state/nonce/PKCE, code exchange, JWKS signature and claim validation, userinfo, and product entitlement decisions; existing `OidcFlowTest` retained |
| OAuth client-to-product binding | Implemented and verified in local automated integration tests; PostgreSQL and deployed-client verification remain outstanding | `oidc:client:configure --product=<active-slug>` binds metadata; binding is persisted through authorization code/access token and signed `visionweb_product` ID-token claim; product-access endpoint derives product from token and rejects altered product hints. `OidcClientIntegrationTest` and `OidcFlowTest`: 9 passed, 95 assertions. Migration `2026_10_24_223453_add_product_binding_to_oidc_tables.php`. |
| Security audit integrity and event monitoring | Existing implementation retained; covered by full test suite | Existing hash-chained audit and event monitor tests; sensitive account/admin/report actions recorded |
| Full Laravel suite | Implemented and verified using SQLite in-memory | Final run: `php artisan test --compact`: **160 passed, 899 assertions**, exit 0. PHPUnit used `sqlite :memory:` and did not connect to PostgreSQL. |
| PostgreSQL 18 migration and credential schema | Implemented and verified on fresh isolated PostgreSQL staging; restored dataset compatibility not verified | `vwss_central_auth_staging_verify` at `127.0.0.1:5432`, PostgreSQL 18.6, remains a fresh non-restored staging DB. The new `2026_10_24_230758_create_product_api_credentials_table.php` was the only pending migration and succeeded; Laravel reported 2s. All 20 migrations are recorded applied. Table inspection verified UUID/client/product columns, expiry/revocation/use timestamps, two compound indexes, and restrictive FKs to `oauth_clients` and `products`. Existing OIDC rows and populated-table lock behavior remain untested. |
| Frontend production build | Implemented and verified | Final `npm.cmd run build` passed using Vite 8.3.5. An npm lockfile was generated offline from installed packages (no install or package.json version change); `npm.cmd ci` is now the reproducible build install command. |
| PHP formatting | Implemented and verified | `vendor/bin/pint --dirty --format agent`: passed |
| Production frontend bundle | Implemented and verified | `npm.cmd run build`: passed with Vite 8.3.5; remote font fetch removed in favor of the local UI kit/system font stack |
| Dependency audit and route registration | Implemented and verified | `composer audit`: no advisories; `php artisan route:list --except-vendor`: 98 routes listed before final permission annotations; no duplicate route names observed |

## Remaining work, limits, and next actions

| Feature | Status | Next action / dependency |
|---|---|---|
| Browser-level end-to-end rendering and responsive checks | Blocked by environment/tooling | No browser automation dependency or browser execution was available. Add/run approved browser automation in the deployment/CI environment and verify login, recovery, security settings, admin denial, and incidents. |
| Live SMTP/inbox delivery | Blocked by external configuration | Configure SMTP and verify an actual inbox delivery. Feature tests verify notification behavior only. |
| SMS and WhatsApp delivery | Blocked by external provider | No provider credentials/configuration exist in this implementation. UI states that those choices currently deliver through registered email. |
| Payment provider and automated subscription billing | Blocked by external provider | Persistence and lifecycle/access contracts exist; no payment gateway is claimed. Configure provider credentials, webhook verification, reconciliation, and provider-specific tests before billing use. |
| Subscription/plan lifecycle administration | Implemented partially; not fully verified | Persisted catalog and subscription records, status/period enforcement, user/admin overview exist. Add authorized provisioning/update workflows and provider reconciliation when operationally specified. |
| Product-specific resource ownership | Implemented at organization membership/access boundary; product API integration incomplete | Each separately deployed product must enforce its own resource/record ownership using the central access decision plus its own database and policies. Test against each actual product client/API. |
| PostgreSQL 18 migration against restored existing OIDC data and populated-table locking | Blocked by missing approved source/verified backup | Backup discovery found no PostgreSQL dump in the repository. `.env.backup` was not opened because it may contain secrets and is not validated as database backup; `database/database.sqlite` is not PostgreSQL. Project documentation/configuration does not establish `vwss_central_auth_fresh` as an approved backup source or authorize backing it up. No backup, restore, or database migration was attempted in this follow-up. Resume only with an operator-approved source and verified dump, restore into a newly created unused DB, and never overwrite the existing fresh staging DB. |
| Live separate-client/browser SSO | Implemented but not fully verified | In-process relying-party fixture validates the protocol flow. Configure and test a separately running client against deployment URLs, HTTPS, registered redirect URIs, and real key material. |
| Production hardening | Application controls implemented and tested; deployment configuration remains a release gate | Headers/CSP, production-secure cookies, empty-by-default CORS and explicit trusted proxies are implemented. The readiness command correctly fails on local APP_ENV/debug/HTTP URL/Secure/CSP values. Verify real production host/proxy/HTTPS/key/SMTP/backup setup before release. |

## Admin bootstrap

Create an existing active and email-verified account first. Provision it through an authorized deployment shell; public registration and profile updates cannot grant admin access:

```powershell
php artisan auth:admin:grant admin@example.com --reason="Approved initial operator" --permissions="*" --allow-wildcard --force
```

`*` grants every permission and is rejected unless the operator also supplies `--allow-wildcard`; without `--force`, the command asks for explicit full-admin confirmation. Grant and revoke reasons must be 5–500 characters. For least privilege, use a comma-separated allowlist such as `users.read,security.read,incidents.read`. Available permissions are `dashboard.read`, `users.read`, `users.manage`, `security.read`, `security.audit`, `oauth.read`, `oauth.manage`, `products.read`, `incidents.read`, `incidents.manage`, and `incidents.remediate`. Revocation uses `php artisan auth:admin:revoke admin@example.com --reason="Operator rotation" --force`; the command serializes grant changes, rechecks the grant, and refuses to remove the last active verified admin.

## PostgreSQL 18 staging verification and remaining procedure

Verified in this task: PostgreSQL client/server 18.6 at `127.0.0.1:5432`; active DB `vwss_central_auth_fresh`; dedicated fresh staging DB `vwss_central_auth_staging_verify` created only after confirming it did not exist, that the target was distinct from active, and that the local server role had `CREATEDB`. Staging is owned by `postgres`, was created with `template0`, and is not a restored data copy. Laravel process-scoped DB environment overrides selected staging without changing `.env`; `db:show` and a direct PostgreSQL identity query confirmed target/server before migration. All migrations succeeded on staging. Active database remained at 15 migrations (four new migrations pending), 1 OAuth client, 2 Passport access tokens, and zero OIDC metadata/code/access-token rows in read-only before/after checks. Read-only schema inspection confirmed the three pre-migration OIDC tables lacked `product_id` and retained their client/user foreign keys. No migration, rollback, seed, or destructive operation targeted active DB.

Populated staging follow-up is blocked: no verified PostgreSQL database backup was found, and project documentation/configuration does not identify `vwss_central_auth_fresh` as an approved source or authorize taking a backup from it. The `.env.backup` candidate was not opened because it may contain secrets and is not validated as a database dump; the local SQLite file is not a PostgreSQL backup. No backup, restore, or migration was performed in this follow-up. Next, an operator must identify and approve the source and provide a verified PostgreSQL backup with provenance/timestamp and integrity evidence. Restore it only into a newly created unused database (never into the existing staging database), then measure the binding migration against existing OIDC rows and lock duration. Do not run `migrate:fresh`, `db:wipe`, or rollback against valuable data.

The admin, incident and product-access migrations create new tables with Laravel schema-builder types and dependency-ordered foreign keys. Migration `2026_10_24_223453_add_product_binding_to_oidc_tables.php` ran successfully on PostgreSQL 18.6 staging. It adds nullable bigint product foreign keys to OIDC metadata, authorization-code and access-token tables; on the fresh staging schema the three columns were nullable, constraints validated with `ON DELETE RESTRICT`, all orphan counts were zero, and no product_id indexes were present on those tables. Existing-row compatibility remains unverified because staging contained no OIDC records. PostgreSQL may lock/validate existing code/token rows while adding constraints; measure on a restored copy and schedule a controlled deployment window. Its down path drops only those foreign keys/columns; no rollback was executed.

## Product API integration boundary

`RequireProductAccess` is local middleware for a Central Auth Laravel API using `auth:api` Passport tokens; it reads Central Auth's own database and is not a drop-in for separate products. An operator binds an OIDC client using `php artisan oidc:client:configure {clientId} --scopes=openid,email,product_access --product=suss`; the product slug must resolve to an active product. Central Auth stores this binding and propagates its product id into authorization codes and opaque access-token records. `POST /api/oidc/product-access` uses the token-bound product; the optional `product` request field is only a consistency hint and a mismatch is denied. Central Auth verifies token state/scope, active identity, product membership, subscription, seat rules, entitlement and product-role permission, returning 200 for allow, 401 for invalid token, and 403 for insufficient scope/denial.

Separate APIs must trust a configured issuer, validate the ID-token signature against Central Auth JWKS, enforce exact `iss`, their own ID-token `aud`, `exp`/`iat`, and transaction-bound state/nonce/PKCE; require `visionweb_product` to match their registered product and the required scope. For the opaque bearer product decision, send both the user's token and the expiring product-server credential bound to that same OIDC client/product. Central Auth checks that token's persisted client/product audience and current membership/subscription/entitlement/permission. Every product API must additionally bind the authorized organization to its own tenant and enforce resource ownership and product-specific permissions on each operation. Repository tests verify Central Auth's local flow only; no independent SUSS/finance/booking API has been integrated or verified.

## Current test/build commands

```powershell
php artisan test --compact
vendor/bin/pint --dirty --format agent
npm.cmd run build
composer audit
php artisan route:list --except-vendor
git diff --check
```

## Production hardening checkpoint (2026-10-25)

| Requirement | Status | Evidence / remaining action |
|---|---|---|
| Global security headers and CSP | Implemented and automated tests passed; browser compatibility not verified | `SecurityHeaders`, Laravel 13 global middleware registration, per-response script nonces, CSP-safe local styles/event handlers; `ProductionHardeningTest`. Browser-check CSP/login/MFA/passkey/OIDC pages before deployment. |
| Session cookie production security | Implemented and tests passed | Production forces Secure and HttpOnly; SameSite defaults Lax; `SessionConfigurationTest`. Actual HTTPS browser cookie behavior remains deployment verification. |
| CORS | Implemented and automated tests passed | `config/cors.php` defaults to no cross-origin paths/origins and credentials false. Keep disabled unless exact browser-origin contract exists. |
| Trusted proxies | Implemented and automated tests passed | `ConfiguredTrustProxies` uses exact configured IP/CIDR values and trusts none by default. Operator must supply only known proxy addresses when deployed behind a proxy. |
| Deployment readiness validation | Implemented; production check correctly fails on local configuration | `app:check-production-readiness` is config-only, does not expose secrets, and does not establish TLS, SMTP, key custody, or external SSO. Current local output: exit 1 for local APP_ENV, debug enabled, HTTP localhost APP_URL, Secure=false, CSP disabled. |
| Passport/OIDC key custody | Implemented signing mechanisms; production custody not verified | No keys were read or changed. Operator must verify secure provisioning, filesystem ACLs, encrypted backups, APP_KEY stability and staged rotation. Never use `passport:keys --force` over existing keys. |
| Product API security contract | Central Auth checks verified in local tests; independent APIs unverified | Product APIs validate issuer/signature/audience/expiry, state/nonce/PKCE, product claim and scopes; opaque access token via Central Auth product-access endpoint; enforce their own tenant/resource ownership. |
| Populated PostgreSQL migration compatibility/lock behavior | Blocked | No approved source database or verified backup. No database command/migration was run in this hardening pass. Follow the safe staging procedure in final verification report. |
| Live separate-client SSO | Not verified | Automated local relying-party test only; no separately deployed client. |
| Live SMTP, SMS/WhatsApp, payment integration | Blocked by external providers | No inbox/provider evidence. |
| Browser E2E and deployed TLS/proxy topology | Not verified | No browser automation or production deployment environment was available. |
| Regression suite | Implemented and verified | Focused: **104 passed, 604 assertions**. Full SQLite in-memory suite: **148 passed, 831 assertions**. |
| Frontend build / formatting / diff | Verified | `npm.cmd run build` passed (Vite 8.3.5); `vendor/bin/pint --dirty --format agent` passed; `git diff --check` exit 0 (line-ending normalization warning only). |

No migration, seeder, rollback, database write, or active-database connection was used for this pass. Do not treat local settings as deployment values. See the production hardening follow-up in `PROJECT_FINAL_VERIFICATION.md` for exact operator configuration and evidence limitations.

## Product integration documentation (2026-10-25)

| Requirement | Status | Evidence / remaining action |
|---|---|---|
| Dedicated product integration guide set | Implemented and cross-checked against current source | `documentation/product-integration/README.md` and eight linked guides (including the deployment guide) cover architecture, product/client registration, Laravel relying party, OIDC/token validation, tenant/product authorization, environment setup and troubleshooting. |
| Actual endpoints, claims, scopes, token types and denial behavior | Documented from implementation | Sources: `routes/web.php`, `routes/api.php`, `OidcController`, `ConfigureOidcClient`, `ProductAccessService`, product-access routes and cited feature tests. Integration tests are local test-harness evidence only. |
| Product API server authentication and audience binding | Implemented and locally verified; live deployment unverified | Existing `/api/oidc/product-access` requires expiring client/product-bound server credentials plus the user's opaque bearer token; token's stored client/product must match. Tests: `ProductServerAccessTest`, `OidcClientIntegrationTest`. No mTLS or service identity beyond shared-secret possession. |
| Product registration/catalog workflow | Gap documented | No supported product create/update API or command; catalog provisioning requires controlled operator/schema workflow. |
| Usage-limit enforcement | Gap documented | `usage_limit` is persisted/displayed but not metered by the access decision. Do not sell it as enforced quota. |
| Docs formatting/links | Verified | Scanned relative Markdown links across the product-integration Markdown guides; no broken targets. `git diff --check` after updates exited 0, with only the pre-existing password-reset Blade CRLF normalization warning. |

## Product server credential implementation (2026-10-25)

| Requirement | Status | Evidence / remaining action |
|---|---|---|
| Authenticate product server on existing product-access endpoint | Implemented and verified locally | `AuthenticateProductServer` middleware requires credential UUID + secret headers; missing, invalid, expired or revoked credential returns 401. Failure security events omit secret material. |
| Credential/client/product binding and token audience | Implemented and verified locally | Migration `2026_10_24_230758_create_product_api_credentials_table.php`; credential FK binds exact Passport client and product. Controller checks the opaque token's stored `oauth_client_id` and `product_id` against the credential. Separate OAuth clients require separate credentials, even for one product. |
| Secure credential lifecycle | Implemented and verified locally | `auth:product-credential:create` displays a random 256-bit secret once, stores only `Hash::make`, requires reason/confirmation/future RFC3339 expiry <= 1 year; `auth:product-credential:revoke` revokes and audits. Rotate with overlap. Shell operator is recorded as console source without a user actor. |
| Product authorization decision | Implemented and verified locally | Existing `ProductAccessService` still checks active verified identity, product/org membership, active subscription/owner, seat count, entitlements and role permission. Product-local tenant/resource checks remain the product API's responsibility. |
| Focused regression suite | Verified using SQLite in-memory | `php artisan test --compact tests/Feature/ProductServerAccessTest.php tests/Feature/OidcClientIntegrationTest.php tests/Feature/OidcFlowTest.php tests/Feature/ProductAccessTest.php`: **27 passed, 163 assertions**. Includes credential secrecy assertions and discovery URL check for the existing `/api/oidc/product-access` route. |
| Migration verification | Implemented and verified on isolated PostgreSQL staging | The migration was applied only to `vwss_central_auth_staging_verify` after read-only confirmation that it was distinct from configured active `vwss_central_auth_fresh`; active database received no migration or write. See the final verification report for actual status, schema, duration and limits. |
| Live separate product API/service identity | Not verified / remaining gap | No mTLS, signed request, standard introspection, deployment secret manager or independent API tested. Shared-secret credentials are custom; validate TLS, storage, rotation and outage policy in staging before production. |

## Final local deployment and UI/UX verification (2026-10-25)

| Screen / workflow | Status | Evidence and remaining verification |
|---|---|---|
| Public landing, login, registration, verification, recovery and reset | Implemented and server-render verified | `PortalTest` checks guest rendering/shared layout and reset response headers; auth API tests cover request behavior. Real JS/browser and inbox delivery are not verified. |
| OIDC consent | Implemented and local flow verified | `OidcFlowTest` checks kit layout, permission list and approve/deny controls and then tests approval, callback and token flow. No live browser client. |
| Passport OAuth consent/device screens | Implemented and view-render verified | `PortalTest` checks shared layout, device-code input, and existing named approval/denial actions. Device grant was not browser-executed. |
| Profile/password/account security | Implemented and feature-verified | `AccountSecurityWebTest` and `PortalTest` cover persistence, validation, session/app ownership and audit. No browser visual inspection. |
| MFA/recovery codes/trusted devices/sessions/passkeys | Server workflows implemented and automated paths verified | `AccountSecurityWebTest`, `MfaFlowTest`, `WebAuthnFlowTest`; physical passkey ceremony and authenticator UI remain unverified. |
| Product access and member assignment | Implemented and feature-tested | `ProductAccessTest` verifies product/organization membership, subscription, entitlement, seat and permission decision. Product record ownership remains in the product API. |
| User reports and admin investigation | Implemented and feature-tested | `SecurityIncidentTest` covers private reports, recorded evidence, status/notes, audit and remediation. |
| Master Admin screens/actions | Implemented and authorization-tested | `AdminAuthorizationTest`/`SecurityIncidentTest` cover guest, ordinary user, scoped admin and full admin paths, direct browser/API denials and audited actions. |
| Responsive navigation/forms/feedback | Kit integration implemented; browser verification outstanding | Bulma 0.9.x + local VisionWeb theme/JS, responsive columns/table wrappers and mobile burger are used. Named-route scan found no missing view route references or placeholder links/forms. No browser automation tool/package was available for viewport or console checks. |

UI fixes in this pass: password reset now uses the shared kit layout while retaining no-store/no-referrer headers; registration success no longer turns into a false error when `sessionStorage` is unavailable; OIDC, Passport OAuth and device consent views use the shared layout and preserve their POST/CSRF/approval routes; the existing UI-kit wordmark is bundled into both portal/admin navigation.

### Final checks

- Focused auth/UI/security/OIDC/product suite: **53 tests, 340 assertions**, passed.
- Full SQLite in-memory suite: **160 tests, 899 assertions**, passed.
- Isolated PostgreSQL 18.6 staging: pending credential migration succeeded, Laravel reported 2s; all **20 migrations** applied. Schema columns, two indexes, FKs and `RESTRICT` behavior inspected. Fresh DB only; populated rows/locks not verified.
- Vite production build passed; generated `package-lock.json` offline without installing packages or modifying `package.json`.
- Pint and Composer platform checks passed; Composer audit found no advisories. Composer validation passed with exact WebAuthn version-pin warning.
- Production readiness command exited 1 on local development configuration, as expected; it did not expose secret values.
- Blade named-route scan found no missing links; final `git diff --check` exited 0 after all edits.

### Deployment deliverables and external gates

The consolidated deployment guide and safe non-secret environment template are [`documentation/product-integration/PRODUCTION_DEPLOYMENT_GUIDE.md`](documentation/product-integration/PRODUCTION_DEPLOYMENT_GUIDE.md) and [`documentation/product-integration/CENTRAL_AUTH_PRODUCTION.env.example`](documentation/product-integration/CENTRAL_AUTH_PRODUCTION.env.example). They contain lockfile-based install/build steps, PHP/runtime needs, environment configuration, TLS/DNS/proxy, SMTP, key custody, admin bootstrap, backup/forward-migration, cache/scheduler, health checks, and post-deployment verification. Only local Windows/XAMPP development evidence exists; actual server OS, control panel, web server and topology are unknown and must be provided before OS-specific commands can be safe.

Not verified: deployment, TLS/DNS, production database migration, populated PostgreSQL compatibility/locks, production key custody, live separate-client SSO, real SMTP inbox, physical-browser/passkey behavior, payment/SMS/WhatsApp, and independent product API tenant/resource enforcement. Not implemented: billing provider, usage metering, product self-service/catalog CLI and product-owned resource authorization. These are documented and must not be represented as operational.

**Local status: LOCAL COMPLETE — READY FOR MANUAL DEPLOYMENT.** Local verification is complete for manual deployment preparation; production readiness is not claimed. Follow the operator guide and provide the missing non-secret hosting facts before finalizing server-specific commands.
