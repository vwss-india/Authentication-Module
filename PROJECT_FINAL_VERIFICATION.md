# VisionWeb Central Auth 2.0 final verification

Updated: 2026-10-25 (local deployment and UI/UX completion verification)

This report describes executable evidence from the current repository. “Verified” refers to automated tests/builds listed below, not to production deployment or physical browser/provider behavior.

Earlier dated checkpoints below retain the evidence available at those points. The later **Final local deployment and UI/UX verification** section is authoritative for current test/build/migration status and supersedes earlier counts.

## Architecture and implementation

Central identity remains in the Laravel user/authentication schema. OAuth/OIDC continues to use Passport and the existing OIDC implementation. User portal pages use the existing VisionWeb UI kit's local Bulma CSS, theme CSS, and JavaScript. The admin panel is a separate route/layout boundary.

Admin grants live in `central_admins` and carry explicit permissions. The deployment-controlled `auth:admin:grant` command requires an active, verified account, a 5–500 character reason, and an allowlisted permission set; it never sets a password. Wildcard `*` requires the additional `--allow-wildcard` flag and a full-admin confirmation unless `--force` is explicitly supplied. Granting rechecks account status in a transaction under row locks. Browser and API actions enforce Central Admin status and route-level permissions. Sensitive actions are permission-checked and audited. Revocation serializes grant-row changes, rechecks the active grant, and protects the last active verified admin.

The normal portal covers login/logout, registration and verification notices, email-first recovery, profile/password management, MFA/TOTP and recovery codes, passkeys, sessions/trusted devices, connected applications, security activity, product access, and suspicious-activity reporting. SMS and WhatsApp are selectable recovery preferences only; while providers are absent, the interface explicitly says delivery falls back to registered email. No claim is made that a message reached an inbox.

Incident reports are private to their submitting user. Admin notes and findings are stored separately from the original report and authentication event rows. Admin incident actions support severity, constrained status transitions, assignment to self, investigation history, and revocation of sessions/tokens/devices. Authentication evidence such as IP and user agent is labeled contextual; Central Auth does not claim endpoint malware detection.

Products, plans, entitlements, organizations, subscriptions, organization-scoped roles/permissions, and memberships are stored separately from product business records. Access requires an active verified identity, active product/organization, membership permission, current organization subscription, an active subscription owner, seat compliance, and enabled feature entitlements. Owners can assign verified active staff under the owner's subscription and role/seat rules. Separate products remain responsible for business-record/resource ownership in their own APIs and databases.

## Changed and added files

- Admin: `app/Models/CentralAdmin.php`, `app/Http/Middleware/RequireCentralAdmin.php`, `app/Http/Middleware/RequireCentralAdminPermission.php`, `app/Http/Controllers/AdminController.php`, `app/Console/Commands/ProvisionCentralAdmin.php`, `app/Console/Commands/RevokeCentralAdmin.php`, `resources/views/admin/`, and protected routes in `routes/web.php` / `routes/api.php`.
- User account security and portal: `app/Http/Controllers/AccountSecurityController.php`, `app/Http/Controllers/Api/V1/Auth/WebSessionController.php`, `resources/views/account.blade.php`, `resources/views/auth/`, `resources/views/security*.blade.php`, and `resources/views/layouts/portal.blade.php`.
- Incidents: `app/Http/Controllers/IncidentController.php`, `resources/views/incidents/`, and admin incident views.
- Product access: `app/Services/ProductAccessService.php`, `app/Http/Middleware/RequireProductAccess.php`, `app/Http/Controllers/ProductAccessController.php`, and `resources/views/products/`.
- OAuth/OIDC: `app/Http/Controllers/Api/V1/OidcController.php`, `app/Console/Commands/ConfigureOidcClient.php`, local client integration test, and protected product-access endpoint.
- UI/build: `resources/css/app.css`, `resources/js/app.js`, `vite.config.js`; local UI-kit files under `visionweb-app-ui-kit/` remain unchanged and untracked.
- Migrations: admin, incident and product-access tables; nullable OIDC product bindings; and `2026_10_24_230758_create_product_api_credentials_table.php` for expiring product-server credentials. Current fresh PostgreSQL staging records 20 applied migrations; populated-source compatibility is still unverified.
- Tests: `AdminAuthorizationTest`, `AccountSecurityWebTest`, `SecurityIncidentTest`, `ProductAccessTest`, `OidcClientIntegrationTest`, `PortalTest`, and changes to existing session/auth tests.

## Evidence and outcomes

| Check | Result |
|---|---|
| Full Laravel suite | Final run: `php artisan test --compact` — **160 passed, 899 assertions**, exit code 0, using the `phpunit.xml` SQLite `:memory:` configuration. Not run against PostgreSQL. |
| Admin provisioning/revocation | After the final code change, `php artisan test --compact tests/Feature/AdminAuthorizationTest.php` — **10 passed, 56 assertions**; covers permission allowlist, explicit wildcard flag, reason validation, active admin safeguard and audit. |
| OIDC product binding | `php artisan test --compact tests/Feature/OidcClientIntegrationTest.php tests/Feature/OidcFlowTest.php` — **9 passed, 95 assertions** after binding changes; covers active product configuration, bound client, signed product claim, altered/omitted product request, invalid/unbound client, invalid redirect, expired subscription and inactive membership. |
| PostgreSQL 18 migrations | Fresh isolated `vwss_central_auth_staging_verify`, PostgreSQL **18.6**, `127.0.0.1:5432`; all **20 migrations** are recorded applied. The new `2026_10_24_230758_create_product_api_credentials_table.php` was the only pending migration and succeeded; Laravel reported **2 seconds**. The complete command including status/schema inspection took about 5.3 seconds. Staging is fresh, not restored. |
| PostgreSQL OIDC schema | Read-only `psql` inspection verified nullable `bigint` `product_id` columns on metadata/code/token tables; all three product foreign keys are validated and use `ON DELETE RESTRICT`; the migration is recorded as applied; zero orphan references. No product_id indexes exist on these OIDC tables. The staging OIDC tables contain zero rows, so existing-row compatibility and populated-table lock duration were not exercised. |
| Active PostgreSQL safety | `php artisan config:show` resolved the configured database name as `vwss_central_auth_fresh` (configuration only). The active database was not connected to or queried in this run. Staging DB commands used process-scoped overrides selecting `vwss_central_auth_staging_verify`; PHPUnit used SQLite memory. No active-database write was made. |
| Populated staging / backup follow-up | Blocked before restore or migration. Repository backup search found no PostgreSQL dump or backup artifact suitable for restore. `.env.backup` was not opened because it may contain secrets and is not validated as a database dump; `database/database.sqlite` is not a PostgreSQL backup. Project configuration and documentation do not establish `vwss_central_auth_fresh` as an approved source database or authorize creating a backup from it. No database was read, written, backed up, or restored during this follow-up. |
| Frontend production build | Final `npm.cmd run build` passed using Vite **8.3.5**. `package-lock.json` was generated offline with `npm.cmd install --package-lock-only --ignore-scripts --offline`; no package installation or package.json version change occurred. npm reported 0 vulnerabilities in 57 packages. |
| Pint / PHP platform | `vendor/bin/pint --dirty --format agent` and `composer check-platform-reqs` passed. CLI PHP is **8.5.11**; PDO PostgreSQL, OpenSSL, sodium, DOM/XML, fileinfo and session extensions are present. |
| Frontend production build | Final `npm.cmd run build` passed using Vite **8.3.5**. `package-lock.json` was generated offline with `npm.cmd install --package-lock-only --ignore-scripts --offline`; no package installation or package.json version change occurred. npm reported 0 vulnerabilities in 57 packages. |
| Composer validation / audit | `composer validate --no-check-publish` passed with the warning that `web-auth/webauthn-lib` is pinned exactly to 5.3.9; `composer audit` reported no vulnerability advisories. |
| Route/UI link scan | Registered-route enumeration and Blade `route()` reference scan found no missing named routes; no app-view `href="#"` or `action="#"` placeholders were found. |
| Whitespace/conflict check | `git diff --check` passed after review changes; both verification documents also passed a trailing-whitespace scan. |
| PostgreSQL migrations | The one newly pending additive migration ran on isolated PostgreSQL 18.6 staging only. No migration, status or query was run against the active database during this final pass. |
| Admin boundaries | Feature tests verify guest denial, ordinary-user browser/API denial, active-admin access, permission-limited admin denial/allow, privileged client revocation, account actions, and audit recording. |
| OAuth/OIDC | `OidcClientIntegrationTest` executes a local relying-party fixture through authorization redirect, login/consent, callback state validation, PKCE code exchange, discovery/JWKS, RS256 ID-token/issuer/audience/nonce/expiry/`at_hash` checks, userinfo, and authorized/unauthorized/expired-subscription product decisions. This is an automated local fixture, not a separately deployed browser client. |
| Recovery/email | Automated tests cover generic recovery behavior, token validity/expiry/reuse and notification behavior. No SMTP inbox was available/observed, so real delivery is not verified. |
| SMS/WhatsApp | Not verified or configured. The UI makes no delivery claim and explains email fallback. |
| Browser E2E | Not run; this checkout does not install Laravel Dusk or another browser automation package, and no browser execution was available. |

## Classification and outstanding items

- **Implemented and verified:** final SQLite suite (160 tests, 899 assertions); focused UI/auth/OIDC/admin/product/incident suite (53 tests, 340 assertions); 20 migrations on fresh PostgreSQL 18.6 staging; Vite build; Pint; Composer platform check/audit; local OIDC fixture and product credential authorization tests.
- **Implemented but not fully verified:** product-binding migration against a restored/representative OIDC dataset; lock behavior on populated OIDC tables; physical-browser passkey registration/login and responsive behavior; live separately deployed client SSO; production proxy/HTTPS/cookie/key configuration; product API resource ownership integration.
- **Blocked by operator-provided data/authorization:** no verified PostgreSQL backup and restore provenance is available; the active database's business purpose is undocumented, and no authorization exists to back it up. A populated staging migration/lock test cannot safely proceed. Real SMTP inbox delivery, SMS/WhatsApp providers, payment-provider execution, and physical browser automation remain unavailable/unverified.
- **Not implemented / known gaps:** billing-provider integration, usage-limit metering, product-catalog self-service/CLI provisioning and product-owned tenant/resource authorization inside separate product applications. Security headers/CSP, restrictive CORS and explicit proxy handling are implemented and covered by tests.

There are no fabricated dashboard statistics or sample persisted alerts. Payment configuration is not represented as present. Browser and live delivery claims are deliberately not made.

## Data safety and migration operations

Runtime `database.default` resolves to `pgsql`, while `phpunit.xml` explicitly sets `DB_CONNECTION=sqlite` and `DB_DATABASE=:memory:`. There is no `.env.testing` and `config/database.php` defines no separate PostgreSQL test connection. A local `database/database.sqlite` file exists but is not selected by PHPUnit. Prior read-only inspection identified the configured active database as `vwss_central_auth_fresh` on local PostgreSQL 18.6, but available project documentation/configuration does not establish whether it is production, staging, or another environment. It is not an approved backup source. Before the earlier fresh staging migration it had the three OIDC tables without `product_id`, their existing client/user foreign keys, and zero OIDC metadata/code/access-token rows. The separate `vwss_central_auth_staging_verify` database was created from `template0` and remains a fresh migrated staging database, not a restored copy. Backup discovery found no PostgreSQL dump in the repository. `.env.backup` was not opened because it may contain credentials and is not validated as a database backup; the SQLite database file is not a PostgreSQL dump. Populated-row compatibility remains untested.

The table-creation migrations add `central_admins`, `security_incidents` / `incident_investigation_entries`, and product/plan/entitlement/organization/subscription/role/membership tables. The new OIDC binding migration adds nullable bigint foreign keys referencing `products` to `oidc_client_metadata`, `oidc_authorization_codes` and `oidc_access_tokens`, with restrictive deletes. Existing OIDC rows remain unbound and identity-only clients continue to work. It does not rewrite existing rows or add indexes on large tables. PostgreSQL may take table locks while adding columns and validating foreign keys against existing OIDC code/token rows; schedule this additive migration in a controlled window and measure it on a restored staging copy before production. The nullable columns and foreign keys use Laravel's PostgreSQL schema grammar; no raw SQL or dialect-specific syntax is used. PostgreSQL 18 schema creation is verified on a fresh isolated database; compatibility with populated OIDC rows and populated-table locking remain unverified.

Rollback definitions drop only the new tables, in child-before-parent order, but doing so after deployment would delete admin grants, incident reports/investigation history, and product/subscription records. Do not run rollback on populated deployment data; back up first and prefer a forward repair. All 20 migrations have run on fresh PostgreSQL 18.6 staging. Populated-row compatibility and populated-table lock behavior remain unverified because staging was not restored from an approved backup.

Staging execution used process-scoped DB environment overrides without changing `.env` or application config: Laravel `config:show` and `db:show` confirmed `vwss_central_auth_staging_verify`, host `127.0.0.1`, port `5432`, PostgreSQL 18.6 immediately before migration; direct `psql` confirmed the same database and zero tables immediately before the write. The fresh database's initial `migrate:status` reported no migration table. After the latest staging migration, status showed all 20 migrations applied. Process environment overrides were restored after each command. The active DB was never the migration target. `RefreshDatabase` tests ran separately under the existing SQLite in-memory PHPUnit configuration. No rollback was run. For the populated-data follow-up, backup discovery found no suitable verified PostgreSQL backup and project evidence did not approve the active DB as a source; no backup, restore, or migration operation was attempted.

The `visionweb-app-ui-kit/` directory was preserved. Do not use Git reset/clean to manage the current working tree; several implementation files and the kit are untracked user/workspace state.

## Required deployment configuration

- The local runtime resolved `APP_ENV=local`, `APP_DEBUG=true`, `database.default=pgsql`, `session.secure=false`, and `mail.default=smtp`. These are the current machine's values, not evidence of production configuration. `.env.example` sets debug false but uses a localhost URL and log mailer. Do not copy it unchanged into deployment.
- `config/session.php` makes session cookies HttpOnly and SameSite Lax; secure-cookie defaults to true when `APP_ENV=production`, but an explicit `SESSION_SECURE_COOKIE=false` would override that. `SESSION_ENCRYPT` is false in the example. Verify HTTPS and production cookie values after config caching.
- No project `config/cors.php` or explicit trusted-proxy allowlist was found. Configure exact production origins and trusted proxy IPs/headers for the real load balancer; do not trust arbitrary forwarded headers.
- No global security-header or Content Security Policy middleware was found (the password-reset page sets Referrer-Policy locally). CSP requires a policy compatible with inline scripts in auth pages, Vite assets, WebAuthn fetches, and OAuth redirects; do not deploy a guessed policy. Verify frame protection, MIME sniffing, referrer policy, HSTS behind trusted TLS proxies, and CSP in staging.
- `.env` and Passport key paths are ignored by Git. Local Passport OAuth key files exist, but their permissions, production custody, and correspondence to production configuration were not verified; key values were not read. OIDC signing-key state in PostgreSQL was not queried. Set `APP_ENV=production`, `APP_DEBUG=false`, `APP_URL` to the HTTPS origin, and rotate/provision production-specific application, Passport, and OIDC keys under deployment secret control.
- Runtime mailer configuration resolves to SMTP, but no SMTP connection or inbox delivery was tested and no credential values were inspected. `.env.example` uses the log mailer. Configure production SMTP and verify a real inbox delivery. SMS/WhatsApp need actual provider adapters and tests.
- OAuth authorization redirects are checked against the exact registered URI list; post-logout redirects use the configured allowlist and HTTPS/localhost validation at client configuration. Still verify production callback origins, scopes, PKCE, consent, token expiry, and key rotation with real clients.
- A scheduled audit-chain verification runs daily and security alert monitoring runs every minute. OIDC key retention has a configured duration. No general event/audit/incident retention or automated database-backup policy/verification was found; set retention and backup/restore operations for the deployment and test restoration.
- Configure payment provider credentials/webhook verification only when a provider is selected; keep secrets in deployment secret storage.

## Product-access integration boundary

`oidc:client:configure` binds product-access clients by an operator-supplied active product slug: `php artisan oidc:client:configure {clientId} --client-type=public --scopes=openid,email,product_access --product=suss`. A client configured for `product_access` without an active product is rejected. The product id is taken only from server-side client metadata, copied into authorization codes and access tokens, and represented by the signed ID-token claim `visionweb_product`. Authorization requests cannot provide `product` or `product_id`. The product-access endpoint derives the product from the stored token binding; a supplied product hint is optional and must match. Changed client binding, disabled client/product, missing scope, expired/revoked token, invalid membership, subscription, entitlement or permission are denied. `OidcClientIntegrationTest` exercises this in a local relying-party fixture; it does not prove live SSO or secure a separately deployed API by itself.

Separate VisionWeb APIs must obtain issuer/endpoints from trusted deployment configuration (not an untrusted request); validate the Central Auth ID-token RS256 signature using trusted JWKS and `kid`; require exact configured `iss`, this API's ID-token `aud`, valid `exp`/`iat`, and the login transaction's one-time `state`, `nonce`, and PKCE verifier. Require `visionweb_product` to equal the product registered for that client and require `product_access`. The issued access token is opaque, not a locally verifiable JWT. For Central Auth's product-access decision, send it over TLS as `Authorization: Bearer`, plus the product server's provisioned `X-VisionWeb-Product-Credential` and `X-VisionWeb-Product-Secret`. The credential's stored OAuth client ID/product must match the token's stored client/product. The token's stored client ID is the effective audience at this custom endpoint; there is no JWT `aud` in the opaque token. Do not trust a request-supplied product or permission as proof. Each product API must independently verify tenant/resource IDs belong to the authorized organization and enforce its own role, row ownership and business rules on every read/write; Central Auth cannot inspect product databases or enforce resource ownership. This contract has only been exercised in local automated fixtures, not by independent product APIs.

## Run commands

```powershell
composer install
npm.cmd install
npm.cmd run build
php artisan serve
php artisan test --compact
vendor/bin/pint --dirty --format agent
```

Only after confirming the untracked `.env.predeploy` targets an isolated staging database and any existing data is backed up, run `php artisan migrate:status --env=predeploy` followed by `php artisan migrate --env=predeploy --force`. Do not use plain `php artisan migrate --force` against the current active connection.

Safely provision a narrowly scoped admin from an authorized deployment shell after creating an active, verified user:

```powershell
php artisan auth:admin:grant operator@example.com --reason="Approved security investigator" --permissions="security.read,incidents.read,incidents.manage" --force
```

Use `--permissions="*" --allow-wildcard` only for an intentionally full administrator. See `PROJECT_IMPLEMENTATION_CHECKLIST.md` for the complete allowlist and current feature-by-feature checkpoint.

## Production hardening follow-up (2026-10-25)

### Confirmed gaps and implementation

Before changes, non-secret runtime inspection showed `APP_ENV=local`, `APP_DEBUG=true`, `APP_URL=http://localhost:8000`, session Secure=false, HttpOnly=true, SameSite=Lax. These local values were not changed. Laravel 13's installed default CORS config allowed wildcard origins on API paths (without credentials). No project CORS config, global security headers, CSP, or trusted proxy allowlist existed. Laravel 13 already installs `TrustProxies` and `HandleCors` globally; changes configure those mechanisms rather than adding duplicates.

- Added `SecurityHeaders` globally through Laravel 13 `bootstrap/app.php`: nosniff, frame denial, Permissions Policy, Referrer Policy, CSP, and HSTS only on HTTPS requests in production. CSP is off in local/testing and defaults on elsewhere, uses a per-response nonce for inline scripts, and allows same-origin resources plus data images/fonts. Existing stricter reset-page Referrer Policy is preserved.
- Nonced existing inline scripts, removed inline styles and form event handlers, and moved styling/confirmation behavior into the Vite CSS/JS bundle so those interactions work under the policy.
- Added empty-by-default `config/cors.php`: same-origin only unless exact paths/origins are configured; credentials default off.
- Added `config/security.php` and `ConfiguredTrustProxies`, replacing Laravel 13's default proxy middleware. No proxy is trusted by default; configured IP/CIDR entries alone can supply forwarded host/proto/port/for headers.
- Production session settings force Secure and HttpOnly true, even if false env overrides are supplied. Local/test settings remain configurable; SameSite remains Lax by default.
- Added read-only `php artisan app:check-production-readiness`. It checks non-secret app/session/CORS/proxy/CSP configuration, suppresses APP_KEY values, and explicitly does not verify TLS, DB, SMTP, key custody, or external clients.
- No `.env`, key material, migration, or database was changed. Passport command help was inspected; no key creation, rotation, overwrite, or content/ACL inspection occurred.

### Verification evidence

| Check | Actual result |
|---|---|
| Focused security/auth/OIDC/admin | `php artisan test --compact tests/Feature/ProductionHardeningTest.php tests/Unit/SessionConfigurationTest.php tests/Feature/AuthApiTest.php tests/Feature/MfaFlowTest.php tests/Feature/PasswordRecoveryTest.php tests/Feature/WebAuthnFlowTest.php tests/Feature/OidcClientIntegrationTest.php tests/Feature/OidcFlowTest.php tests/Feature/AdminAuthorizationTest.php`: **104 passed, 604 assertions**, exit 0. An initial run exposed a missing `Illuminate\\Http\\Request` import in bootstrap exception configuration; fixed and rerun successfully. |
| Full suite | `php artisan test --compact`: **148 passed, 831 assertions**, exit 0, SQLite in-memory only. |
| Pint / PHP platform | `vendor/bin/pint --dirty --format agent` and `composer check-platform-reqs` passed. CLI PHP is **8.5.11**; PDO PostgreSQL, OpenSSL, sodium, DOM/XML, fileinfo and session extensions are present. |
| Frontend build | `npm.cmd run build`: passed with Vite 8.3.5. |
| Diff check | `git diff --check`: exit 0; only warning was CRLF-to-LF normalization for `resources/views/auth/password-reset.blade.php`. |
| Readiness command | `php artisan app:check-production-readiness`: exit 1 as expected for local runtime; flags APP_ENV, debug, HTTP APP_URL, Secure=false, and CSP disabled. HttpOnly, SameSite, CORS restrictions, proxy wildcard denial/syntax, and non-secret APP_KEY presence passed. It reported no trusted proxy list and no CORS paths. |

Header/proxy behavior is tested in `tests/Feature/ProductionHardeningTest.php`; production cookies in `tests/Unit/SessionConfigurationTest.php`. Browser CSP rendering, deployed TLS, and real proxy topology remain unverified. No database commands ran and the active PostgreSQL database was not used or modified.

### Deployment actions and unresolved items

Set `APP_ENV=production`, `APP_DEBUG=false`, and `APP_URL=https://<actual-central-auth-host>` in deployment configuration. Keep APP_KEY stable and secret. Terminate TLS and set Secure/HttpOnly session cookies (`SESSION_SECURE_COOKIE=true`, `SESSION_HTTP_ONLY=true`, SameSite `lax` or stricter after browser validation). CSP defaults on outside local/testing; validate deployed pages in a browser. Leave `TRUSTED_PROXIES` empty only for direct TLS termination; otherwise set exact trusted proxy IPs/CIDRs. Keep CORS disabled for same-origin use; configure exact origins and paths only if an actual browser integration requires them.

The readiness command cannot prove TLS/DNS, SMTP inbox delivery, external SMS/WhatsApp/payment providers, Passport key custody/permissions/backup/rotation, or live SSO. Do not use `passport:keys --force` over existing keys. Provision and back up Passport keys through deployment secret management; restrict filesystem access and plan rotation around outstanding tokens. OIDC signing records are encrypted under APP_KEY; key loss/rotation requires a planned impact/re-encryption procedure. No key contents were exposed or changed.

Populated PostgreSQL compatibility and lock behavior remain blocked by the previously documented absence of an approved source/verified backup. No live separate-client SSO or independent product API was tested. Product APIs must validate issuer, signature, audience, expiry, nonce/state/PKCE, `visionweb_product`, and scopes; validate opaque access tokens through Central Auth's product-access contract; and enforce their own tenant/resource ownership. **Deployment is not verified or production-ready.** Local values were intentionally left unchanged.

## Product integration documentation (2026-10-25)

Created the product integration documentation set under [`documentation/product-integration/README.md`](documentation/product-integration/README.md), with architecture, registration/binding, Laravel relying-party patterns, exact OIDC flow/token validation, product authorization and tenant rules, local/staging/production setup, and troubleshooting. These documents were checked against current routes, controllers, config, migrations and `OidcFlowTest`, `OidcClientIntegrationTest`, `ProductAccessTest`, and `AccountSecurityWebTest`; they describe the local integration test as test evidence, not live SSO. No application behavior, dependencies, database or UI kit were changed for this documentation task.

The existing `POST /api/oidc/product-access` now requires an expiring server credential bound to an exact OIDC client/product plus the user's opaque access token. It checks the token's stored OAuth client ID and product ID against the authenticated server credential; this is an effective client audience check for the opaque token, which has no JWT `aud` claim. Credentials are hashed, rotatable/revocable, and provisioned only through operator console commands. This is locally tested, not live deployment evidence. Remaining gaps include mTLS or independent service identity beyond shared-secret possession, standardized introspection, usage-limit metering/enforcement, and product catalog registration. Product-local tenant/resource ownership remains the product's responsibility.

## Product server decision credential hardening (2026-10-25)

Implemented on the existing `POST /api/oidc/product-access` route; no parallel endpoint was added. `AuthenticateProductServer` requires `X-VisionWeb-Product-Credential` (credential UUID) and `X-VisionWeb-Product-Secret` (64 lowercase hex characters) before controller validation. The user's separate opaque bearer token remains in `Authorization`. Credentials are bound by foreign keys to one Passport OIDC client and product; auth also requires the client active, OIDC metadata enabled and still bound to that product, product active, `product_access` in the registered scope allowlist, credential unexpired/unrevoked, and `Hash::check` success. The user token's persisted client and product must exactly match the server credential; another client in the same product is a wrong audience and is denied. User identity, membership, subscription, owner, seats, entitlements and role permission remain checked by `ProductAccessService`; product APIs still enforce their own tenant/resource ownership.

New operator-only commands `auth:product-credential:create` and `auth:product-credential:revoke` require reasons, confirmation unless `--force`, and explicit future RFC 3339 expiry within one year. Creation returns a 256-bit secret once and stores only a Laravel password hash; no public route can create one. Create/revoke writes audit and security events without secret values. Rotations can overlap: deploy the new credential, verify it, then revoke the prior credential. The schema is in `database/migrations/2026_10_24_230758_create_product_api_credentials_table.php`. In the final pass this migration was applied only on isolated PostgreSQL 18.6 staging; the configured active database was not connected to or modified.

Focused verification after implementation and formatting: `php artisan test --compact tests/Feature/ProductServerAccessTest.php tests/Feature/OidcClientIntegrationTest.php tests/Feature/OidcFlowTest.php tests/Feature/ProductAccessTest.php` — **27 passed, 163 assertions**, exit 0. Tests cover missing/invalid/revoked/expired server credentials, valid access, wrong client audience, cross-product/client mismatch, membership denial, credential create/revoke auditing and secret hashing, expiry bounds, secret absence from audit/security-event data, the discovery decision-endpoint URL, and existing OIDC/entitlement behavior. The test uses `phpunit.xml` SQLite `:memory:`. `vendor/bin/pint --dirty --format agent` passed after the final PHP changes. No live separately deployed product/API security test has run.

Also corrected a discovery mismatch found during this implementation: `visionweb_product_access_endpoint` now advertises the actual `/api/oidc/product-access` route instead of `/oidc/product-access`; the OIDC discovery test asserts this URL.

The exact headers, endpoint behavior, operator commands, rotation procedure, response status handling and remaining service-identity limits are documented in [`documentation/product-integration/README.md`](documentation/product-integration/README.md) and its linked guides.

## Final local deployment and UI/UX verification (2026-10-25)

### UI/UX screen evidence

| Screen / workflow | Local result | Evidence and limits |
|---|---|---|
| Public landing, login, registration, email verification, recovery and password reset | **Implemented and server-render verified** | `PortalTest` renders the guest pages, checks the shared VisionWeb shell, and verifies reset `no-store`/`no-referrer` headers. API tests cover authentication, verification and recovery behavior. Real JavaScript/browser behavior and inbox delivery are not verified. |
| OIDC consent | **Implemented and flow-verified in local tests** | `OidcFlowTest` checks the UI-kit layout, permission list and approve/deny controls, then exercises server approval, callback, PKCE exchange, RS256 ID token and product decision. No separate browser client was run. |
| Passport OAuth consent and device-code screens | **Implemented and view-render verified** | `PortalTest` renders the authorization/device views, checks shared layout and named form actions. No standalone Passport device-grant browser flow was executed. |
| Account/profile/password and account overview | **Implemented and feature-verified** | `PortalTest` and `AccountSecurityWebTest` cover ownership, validation, persistence and audit. Browser visual layout remains unverified. |
| MFA/TOTP, recovery codes, trusted devices, sessions and connected applications | **Implemented and server-action verified** | `AccountSecurityWebTest`, `MfaFlowTest` and `WebAuthnFlowTest` cover setup/status, ownership, rotation/revocation and account changes. Physical authenticator and browser behavior are unverified. |
| Passkey registration/authentication | **Implemented; server protocol paths tested** | WebAuthn challenges, replay and ownership cases are tested. No physical passkey ceremony was run in a browser. |
| Product access and organization member management | **Implemented and feature-tested** | `ProductAccessTest` covers subscription, entitlement, seats, membership and permission decisions. Separate product resource ownership remains product-side. |
| User incident report/status and admin investigation | **Implemented and feature-tested** | `SecurityIncidentTest` verifies private report ownership, evidence, transitions, notes, audit and remediation. |
| Master Admin dashboard, users, clients, security and incident actions | **Implemented and authorization-tested** | `AdminAuthorizationTest` and `SecurityIncidentTest` cover guest/ordinary/scoped/full admin access, browser/API denial, account controls and auditing. Tests do not substitute for a production browser review. |
| Responsive portal/admin layouts, navigation, forms and feedback states | **Implemented; browser viewport verification outstanding** | Local Bulma 0.9.x and VisionWeb theme are loaded through Vite; responsive columns/table containers and mobile navbar behavior come from the kit. Named route scan found no missing Blade route references or `href="#"` / `action="#"` placeholders. No browser automation tool/package was available to inspect actual viewport rendering or console behavior. |

The review fixed the password-reset page's inconsistent unthemed layout, made successful registration independent of optional `sessionStorage`, and moved OIDC/Passport/device consent pages into the shared kit layout without changing approval routes. The kit logo is bundled into the shared navbar through the Vite asset pipeline.

### Local verification commands and results

- `php artisan test --compact tests/Feature/PortalTest.php tests/Feature/OidcFlowTest.php tests/Feature/OidcClientIntegrationTest.php tests/Feature/ProductAccessTest.php tests/Feature/ProductServerAccessTest.php tests/Feature/AccountSecurityWebTest.php tests/Feature/AdminAuthorizationTest.php tests/Feature/SecurityIncidentTest.php` — **53 passed, 340 assertions**.
- After the final shared-navbar/logo asset change, `php artisan test --compact tests/Feature/PortalTest.php tests/Feature/OidcFlowTest.php` — **13 passed, 105 assertions**; then the full suite passed again.
- `php artisan test --compact` — **160 passed, 899 assertions**, exit 0; SQLite in-memory only.
- `vendor/bin/pint --dirty --format agent` — passed after PHP changes.
- `npm.cmd run build` — passed with Vite 8.3.5; emitted manifest, CSS and JS. Node 22.12.0 / npm 10.9.0.
- `npm.cmd install --package-lock-only --ignore-scripts --offline` — generated `package-lock.json` without installing packages or changing `package.json`; npm reported 0 vulnerabilities across 57 packages.
- `composer check-platform-reqs` — passed on PHP 8.5.11; runtime modules include PDO PostgreSQL, OpenSSL, sodium, DOM/XML, fileinfo, session and curl.
- `composer validate --no-check-publish` — valid with one warning: `web-auth/webauthn-lib` uses an exact `5.3.9` constraint.
- `composer audit` — no security vulnerability advisories found.
- `php artisan app:check-production-readiness` — exit 1, expected locally: production environment, debug off, HTTPS URL, Secure cookie and CSP checks fail; HttpOnly, SameSite, CORS and trusted-proxy checks pass. The command does not test external services.
- Blade route scan — 71 registered route names available; every Blade `route()` reference resolved; no empty `href`/form-action placeholders found.
- PostgreSQL staging — read-only precheck selected `vwss_central_auth_staging_verify` at `127.0.0.1:5432`, PostgreSQL 18.6, with exactly one pending migration. That migration succeeded; `migrate:status` then showed all **20 migrations** applied. `db:table product_api_credentials` showed UUID client/product FKs (`RESTRICT`), required expiry, nullable revocation/use timestamps and both compound indexes. Laravel reported 2 seconds for the migration; the combined migrate/status/schema command took about 5.3 seconds. This database is fresh and not restored; populated-row compatibility and production lock behavior remain unverified.
- `git diff --check` — exit 0 after all code, view, package and documentation updates; no warning was emitted.

`php artisan config:show` reported the configured application database name as `vwss_central_auth_fresh`; no connection or database query was made to it in this final run. The only database-changing command used process-scoped overrides for the distinct staging target. No migration, seeder, rollback, destructive SQL, `.env` modification or secret/key read occurred. No browser automation package/tool was found, so viewport rendering, browser console behavior and physical passkey ceremonies were not verified.

### Deployment package and server-side release gate

The consolidated operator guide is [`documentation/product-integration/PRODUCTION_DEPLOYMENT_GUIDE.md`](documentation/product-integration/PRODUCTION_DEPLOYMENT_GUIDE.md); the safe blank-secret template is [`documentation/product-integration/CENTRAL_AUTH_PRODUCTION.env.example`](documentation/product-integration/CENTRAL_AUTH_PRODUCTION.env.example). It covers dependency/build steps, runtime requirements, environment settings, HTTPS/DNS/proxy, SMTP, Passport/OIDC key custody, least-privilege admin provisioning, backup/restore gate, forward-only migration, cache/scheduler operations, health checks and post-deployment E2E checks. Repository evidence shows local Windows/XAMPP development only; the actual server OS, web server/control panel and hosting topology are unknown. OS-specific service/ACL commands are intentionally deferred until those non-secret details are provided.

Production deployment, HTTPS/DNS, real SMTP inbox delivery, production key custody, live separate-client SSO, production migration, populated PostgreSQL compatibility, payment/SMS/WhatsApp providers and independent product API authorization are **not verified**. Product catalog provisioning and usage-limit metering remain known implementation gaps; do not represent them as available/enforced. No defect from this local verification run remains unresolved, but deployment/integration gates remain. The application is not declared deployed or production-verified.

### Final classification

- **Implemented and verified:** final SQLite suite (160 tests, 899 assertions); focused UI/auth/OIDC/admin/product/incident suite (53 tests, 340 assertions); 20 migrations on fresh PostgreSQL 18.6 staging; Vite build; Pint; Composer platform check/audit; local OIDC fixture and product credential authorization tests.
- **Implemented but not fully verified:** responsive browser rendering, JavaScript/browser interaction, physical passkeys, populated PostgreSQL migration/lock behavior, deployed SSO, production TLS/proxy/cookie/key configuration, SMTP delivery.
- **Blocked by environment/provider/operator data:** actual server OS/hosting details; verified backup of an approved populated database; production host/database access; SMTP inbox and payment/SMS/WhatsApp providers; external product API instances.
- **Not implemented:** billing-provider integration, usage-limit metering, product-catalog self-service/CLI provisioning, mTLS/standard introspection, and product-owned tenant/resource authorization inside separate product applications.

**Local status: LOCAL COMPLETE — READY FOR MANUAL DEPLOYMENT.** The repository is locally verified for an operator-led deployment process once the actual host and hosting facts in the deployment guide are supplied. This is local readiness only, not production-readiness evidence; no server deployment is claimed.
