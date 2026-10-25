# Central Auth production deployment guide

This guide is the consolidated release procedure for VisionWeb Central Auth 2.0. It describes the repository's actual Laravel 13 / PHP 8.3+ / PostgreSQL configuration and the checks available in this codebase. The actual production server OS, web server/control panel, service account, proxy topology, DNS name and provider settings are not recorded in the repository. Do not apply OS-specific service, virtual-host, firewall or permission commands until those details are known.

**This is not evidence of a deployment.** No production host, DNS, TLS certificate, production database, SMTP inbox, separate browser SSO client or production signing-key custody was available in this verification. A production readiness command can check local configuration values; it cannot establish those external facts.

The companion [environment template](CENTRAL_AUTH_PRODUCTION.env.example) contains no secrets and is deliberately non-operational until every placeholder is replaced in the deployment secret/configuration system.

## 1. Release package and prerequisites

The application source, `composer.lock`, `package.json`, generated `package-lock.json`, `visionweb-app-ui-kit/`, and Vite's `public/build/manifest.json` plus referenced assets form the release inputs. Keep `vendor/` and `node_modules/` out of source control. Do not omit the UI kit: `resources/css/app.css` and `resources/js/app.js` import its local theme and behavior.

Local verification for this repository completed on PHP **8.5.11**, Node **22.12.0**, npm **10.9.0**, PostgreSQL **18.6**, and Vite **8.3.5**. `composer.lock` is present. There was no npm lockfile initially; `package-lock.json` was generated offline from the installed dependency tree without installing packages or changing `package.json`, then the Vite build succeeded. Use the repository lockfiles in release builds.

PHP must satisfy `composer.lock` (`composer check-platform-reqs`) and enable PDO with the PostgreSQL driver plus the extensions required by Composer packages. The verified local runtime has `pdo_pgsql`, OpenSSL, sodium, DOM, XML, fileinfo, session, JSON and the other locked platform requirements. A deployment must run the commands below with its own CLI PHP and confirm the web PHP handler has the same required extensions and configuration. Passport/WebAuthn operations require working cryptographic functions and a secure browser context (HTTPS, or localhost for local development).

### Build an artifact locally or in CI

Run from the repository root in PowerShell:

```powershell
composer install --no-interaction
composer check-platform-reqs
npm.cmd ci
npm.cmd run build
php artisan test --compact
vendor/bin/pint --dirty --format agent
git diff --check
```

The verified Vite build emits `public/build/manifest.json`, CSS, and JS. Include those outputs in the release artifact. Do not copy `.env`, `.env.backup`, Passport private keys, database exports, local OAuth credentials or tokens into an artifact. Keep dependency lockfiles and the local UI kit. On an environment without Node, build in CI and upload the generated `public/build/` directory with the release.

### Install application dependencies on the server

Run in the application release directory using the server's PHP CLI. These commands do not migrate the database:

```text
composer install --no-dev --prefer-dist --optimize-autoloader --no-interaction
php artisan app:check-production-readiness
```

If building assets on the server, use the lockfile and the installed Node/npm toolchain:

```text
npm ci
npm run build
```

Do **not** use `composer run setup` for an existing or production environment: this repository's setup script creates an environment file/key and invokes migrations. Do not run `php artisan key:generate` against an existing deployment; changing `APP_KEY` can invalidate encrypted data, OIDC key records and sessions.

## 2. Environment and secrets

Copy values from the companion template into the hosting platform's protected configuration store. Do not commit the filled file. Required deployment choices include:

- `APP_ENV=production`, `APP_DEBUG=false`, and the exact public HTTPS origin in `APP_URL`.
- A stable, secret `APP_KEY`. The OIDC key store encrypts private signing key material with Laravel encryption; key loss or rotation can make it unreadable. Keep any required `APP_PREVIOUS_KEYS` during a planned transition.
- `DB_CONNECTION=pgsql`, the isolated Central Auth production database endpoint/name, and a least-privilege database role. Keep each product's business database separate.
- Database-backed or appropriately shared session/cache/queue services for the chosen topology. Do not use local file sessions across multiple application instances.
- `SESSION_SECURE_COOKIE=true`, `SESSION_HTTP_ONLY=true`, and `SESSION_SAME_SITE=lax` unless a tested browser contract requires a stricter compatible setting.
- `TRUSTED_PROXIES` only for exact proxy IPs/CIDRs that actually forward traffic to the app. Empty means no proxy is trusted. Do not set a wildcard.
- Keep CORS empty for same-origin use. If an actual browser client needs cross-origin calls, set exact origins, paths, methods and headers; never combine arbitrary origins with credentials.
- `SECURITY_CSP_ENABLED=true`. Validate login, OIDC consent, MFA, recovery and passkey pages in a real browser before any policy adjustment.
- SMTP connection settings through protected configuration. A configured value does not prove delivery; send a message to a controlled inbox and verify the public HTTPS link.

The template intentionally leaves all credentials and private keys blank. Never paste secrets into this guide, an issue, a command transcript or application logs.

## 3. DNS, HTTPS, proxy and web server

Before opening public access, choose the Central Auth hostname and point DNS to the actual ingress. Install and verify a valid TLS certificate at the real TLS termination point. Set `APP_URL` to that HTTPS origin, and ensure the reverse proxy preserves the external host and HTTPS scheme. Only configure forwarded headers from known proxy IP/CIDRs. HSTS is emitted only for secure requests when `APP_ENV=production`; confirm HTTPS works on every relevant hostname before relying on it.

Serve only Laravel's `public/` directory. Disable directory listing and direct access to `.env`, source, `vendor/`, private keys, logs and database exports. Configure the actual web server's request-size, timeout and TLS policies for the chosen host; these values cannot be selected safely without the server and proxy details.

## 4. Signing keys and OAuth/OIDC clients

Passport private/public key files and OIDC signing-key rows are security-critical. The current implementation uses RS256 ID tokens and publishes public keys at `/oidc/jwks`; OIDC private key records are encrypted with `APP_KEY`. Do not overwrite, rotate or regenerate existing keys during deployment. Keep key files readable only by the application service identity, back them up encrypted with a tested restore path, and coordinate any rotation with token expiry, old public-key/JWKS cache retention and every relying party.

If this is a genuinely new environment with no Passport key pair, an authorized operator may run `php artisan passport:keys` once from a protected deployment shell after confirming the key paths are absent and the release procedure has a secure backup/custody plan. Never use `--force` as a repair command. Do not display private-key contents. Confirm the OIDC key record and public JWKS behavior using the deployment's approved health procedure; key custody is not proven by the presence of a file or database row.

Provision each environment's product, plan, OAuth client, exact redirect URI, allowed scopes and persisted product binding through the controlled registration process documented in [Product registration](PRODUCT_REGISTRATION.md). Authorization requests cannot choose the bound product. Do not reuse client IDs or server credentials across local, staging and production.

Central Auth's access decision is `POST /api/oidc/product-access`. A product backend sends the user's opaque bearer token and both `X-VisionWeb-Product-Credential` and `X-VisionWeb-Product-Secret` over TLS. Provision that credential only in a protected operator shell with `php artisan auth:product-credential:create ...`; its random secret is displayed once, so capture it directly into the product's server-side secret manager and never browser code or deployment logs. Rotate by deploying and verifying a second credential, then revoking the prior one. This custom shared-secret contract is not mTLS or standard OAuth introspection. Product APIs must still validate their ID tokens and enforce product tenant/resource ownership themselves.

## 5. Admin bootstrap and privilege control

Create the first admin only after the intended user account exists, is active and has verified email. Run the grant command from an authorized deployment shell; it prompts for confirmation by default and writes an audit event:

```text
php artisan auth:admin:grant operator@example.com --reason="Approved initial production operator" --permissions="dashboard.read,users.read,users.manage,security.read,security.audit,incidents.read,incidents.manage,incidents.remediate,oauth.read,oauth.manage,products.read"
```

Grant only permissions required for the operator's work. `--permissions="*" --allow-wildcard` deliberately grants full access and should be reserved for explicitly approved break-glass administration. No password is created or printed by this command. Revoke an admin using:

```text
php artisan auth:admin:revoke operator@example.com --reason="Operator access ended"
```

The command protects the last active admin from accidental removal. Verify admin sign-in and audit evidence using the authorized operator, then retain a separate controlled break-glass procedure.

## 6. Backup and database migration gate

**Database-changing deployment step — approval and verified backup required.** Local staging does not establish safety for the server database. Before a production schema change, the database owner must verify the target host, port, database name, server version, role and backup recovery point. Do not infer target identity from a shell's current `.env`.

Example backup commands for a controlled PostgreSQL operator shell (use protected PostgreSQL credential handling such as a restricted `PGPASSFILE`; never put a password on the command line):

```text
pg_dump --format=custom --file=<protected-backup-path> --host=<verified-db-host> --port=<verified-db-port> --username=<backup-role> <verified-db-name>
pg_restore --list <protected-backup-path>
```

Record the backup timestamp and provenance, verify its checksum and retention/restore policy, and prove restoration only into a **new, confirmed-unused isolated staging database**. Never restore over an existing database. The current repository evidence does not include an approved source backup, so populated OIDC-row migration compatibility and populated-table locking remain unverified.

After the exact production connection and a recoverable backup have been verified, inspect migration status and run only the forward migration command under the approved change window:

```text
php artisan migrate:status
php artisan migrate --force
```

The second command writes schema changes. Do not run `migrate:fresh`, `db:wipe`, rollback or schema-drop commands on deployment data. If a migration fails, preserve the resulting schema and logs (sanitized), stop deployment, and plan a forward repair. Do not automatically roll back. The latest additive migration creates `product_api_credentials`; fresh PostgreSQL 18.6 staging applied it successfully. No populated production-like source was restored for this verification.

For database rollback, use a tested restore plan only after explicit database-owner approval and only into a new isolated database; never restore into an existing production database as a reflexive rollback. Prefer a code rollback only when the previous release is known to be schema-compatible.

## 7. Filesystem, cache, scheduler and processes

The app's service identity needs read access to source, `vendor/`, and `public/build/`, and write access only to Laravel runtime directories such as `storage/` and `bootstrap/cache/`. Do not recursively grant write access to the whole project. The exact ACL/ownership commands depend on the unconfirmed server OS, web-server identity and deployment model.

After publishing the environment values, run from the release root:

```text
php artisan optimize:clear
php artisan config:cache
php artisan route:cache
php artisan view:cache
php artisan app:check-production-readiness
```

Restart the actual PHP application workers/processes using the hosting platform's approved mechanism after deploying code or configuration. If using queued mail/notifications, configure a durable queue and a supervised worker. If using scheduled security monitoring and audit-chain checks, configure the Laravel scheduler to invoke `php artisan schedule:run` once per minute. Verify those processes and alert on failures; do not assume local process state exists in production.

## 8. Health and post-deployment end-to-end verification

The Laravel `/up` health route, when enabled by the installed framework bootstrap, is a basic process health signal only. A successful HTTP response does not verify database writes, mail, OAuth, key custody or product authorization. Keep sensitive configuration and tokens out of health-check output.

After the public HTTPS hostname is configured, request the basic health route from an operator shell:

```powershell
curl.exe --fail --silent --show-error https://<central-auth-host>/up
```

On a Unix-like shell, use the same command with `curl` instead of `curl.exe`. Replace the placeholder with the verified public hostname; do not treat this response as an end-to-end sign-in test.

After DNS/TLS and deployment, an operator should verify in a real browser and controlled client:

1. HTTPS certificate/hostname, redirect behavior, secure/HttpOnly/SameSite session cookies, CSP console output, responsive navigation and no mixed-content/browser errors.
2. Registration policy, sign-in, email verification, recovery request and password reset using a controlled mailbox; MFA/TOTP, recovery-code and passkey setup/login/revocation on supported browsers.
3. Profile/password changes, session and connected-app revocation, account activity, user suspicious-activity report, and owner-only report status.
4. Admin authorization by guest, ordinary user, scoped admin and full admin; direct URL/API denial, audited user status change, investigation note/status action and remediation.
5. OIDC discovery/JWKS from the configured issuer; authorization-code + PKCE login in a separately deployed test client; validate state, nonce, RS256 signature, issuer, exact client audience, expiry and product claim; test denial and revocation.
6. Product access from a product backend using its protected server credential and user token. Test wrong client/product, revoked/expired credential, inactive account, missing membership, expired/suspended subscription, missing entitlement/permission, and tenant/resource ownership denial in the product API.
7. SMTP delivery to a controlled inbox, real recovery link host, scheduler/queue health, audit-integrity verification, backups and a restore drill.

No external check above is claimed complete by local tests. Central Auth's product-access decision does not replace token verification or resource authorization inside separate products, and authentication logs are not malware detection.

## 9. Verified local release evidence and remaining gates

The current repository verification is recorded in [`PROJECT_FINAL_VERIFICATION.md`](../../PROJECT_FINAL_VERIFICATION.md) and [`PROJECT_IMPLEMENTATION_CHECKLIST.md`](../../PROJECT_IMPLEMENTATION_CHECKLIST.md). This run verified the full PHPUnit suite on SQLite `:memory:`, the new migration on isolated fresh PostgreSQL 18.6 staging, the frontend build, and formatting/static checks. It did not touch the active PostgreSQL database. UI routes were inspected and Laravel feature-tested; no browser automation executable/package was available, so viewport, JavaScript and browser-console behavior remain unverified.

Before OS-specific server instructions can be finalized, provide these non-secret deployment facts together: server OS/version; hosting/control panel and web server; PHP version/SAPI and app service identity; deployment path/artifact method; TLS termination and proxy IP/CIDR topology; public Central Auth hostname/DNS ownership; PostgreSQL server version/hosted or local topology and backup/restore owner; queue/cache/scheduler process mechanism; SMTP provider and whether a controlled test inbox is available. Do not send credentials or secret values.
