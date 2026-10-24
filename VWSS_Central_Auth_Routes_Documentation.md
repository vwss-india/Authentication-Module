# VisionWeb Central Authentication — Routes and Integration Reference

This reference was written from the Laravel 13 route registry and the current route, controller, middleware, view, configuration, and installed-package source. It describes observed behavior; it is not a promise that an unconfigured external mail transport or production environment works.

## 1. Project routing overview

The application registers routes from `routes/web.php`, `routes/api.php`, and `routes/console.php` through `bootstrap/app.php`. The console file registers scheduled commands, not HTTP routes. API routes receive Laravel's `/api` prefix; their source prefix is `v1/auth`, giving the public API base path `/api/v1/auth`. The host is deployment-specific; use the configured auth origin as `{{AUTH_BASE_URL}}` below.

The verified `php artisan route:list --json` inventory contains **52 routes**:

| Route type | Count | Source |
| --- | ---: | --- |
| VisionWeb API | 26 | `routes/api.php` |
| Project browser and OIDC | 12 | `routes/web.php` |
| Laravel Passport | 10 | Installed Passport route file |
| Laravel filesystem local-disk serving | 2 | Laravel filesystem service provider |
| Laravel health check | 1 | `bootstrap/app.php` health route |
| Laravel Boost browser logs | 1 | Installed Boost service provider; conditional on Boost being enabled and local/debug mode |

There are no API route names in the registered inventory. Named web/protocol routes and package route names are listed below. Middleware shown is the registered route middleware; Laravel's global middleware and route-group middleware also apply.

## 2. Route inventory and summary

`—` means no route name was registered. Passport and framework routes are package-generated, not VisionWeb controllers.

| Method | Path | Route name | Type | Authentication/access | Purpose |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/auth/register` | — | API | Public; 5/min | Create pending account and email verification token |
| POST | `/api/v1/auth/login` | — | API | Public; 5/min; MFA middleware | Password login, optional trusted-device check, or MFA challenge |
| POST | `/api/v1/auth/login/2fa` | — | API | Public challenge exchange; 5/min | Complete TOTP/recovery-code login |
| POST | `/api/v1/auth/email/verify` | — | API | Public; 10/min | Consume email verification token |
| POST | `/api/v1/auth/email/resend` | — | API | Public; 3/min | Resend email verification instructions |
| POST | `/api/v1/auth/forgot-password` | — | API | Public; 5/min | Request password reset |
| POST | `/api/v1/auth/reset-password` | — | API | Public; 5/min | Consume reset token and change password |
| GET | `/api/v1/auth/me` | — | API | Passport bearer token; active and email-verified | Return public current-user fields |
| POST | `/api/v1/auth/logout` | — | API | Passport bearer token; active and verified | Revoke presented access/refresh token pair |
| POST | `/api/v1/auth/logout-all` | — | API | Passport bearer token; active and verified | Revoke user's Passport/OIDC tokens and database sessions |
| POST | `/api/v1/auth/phone/verify/request` | — | API | Passport bearer token; active and verified; 3/min | Email a phone verification code to account email |
| POST | `/api/v1/auth/phone/verify` | — | API | Passport bearer token; active and verified; 10/min | Consume phone verification code |
| GET | `/api/v1/auth/mfa/status` | — | API | Passport bearer token; active and verified | Read TOTP/recovery-code status |
| POST | `/api/v1/auth/mfa/totp/setup` | — | API | Passport bearer token; active and verified; 5/min | Start TOTP setup |
| POST | `/api/v1/auth/mfa/totp/confirm` | — | API | Passport bearer token; active and verified; 5/min | Confirm TOTP and issue recovery codes |
| POST | `/api/v1/auth/mfa/totp/disable` | — | API | Passport bearer token; active and verified; 5/min | Disable TOTP after password and current-code check |
| POST | `/api/v1/auth/mfa/recovery-codes/regenerate` | — | API | Passport bearer token; active and verified; 5/min | Replace recovery codes |
| GET | `/api/v1/auth/trusted-devices` | — | API | Passport bearer token; active and verified | List current user's active, unexpired trusted devices |
| DELETE | `/api/v1/auth/trusted-devices/{id}` | — | API | Passport bearer token; active and verified | Revoke one owned trusted device |
| POST | `/api/v1/auth/trusted-devices/revoke-all` | — | API | Passport bearer token; active and verified | Revoke all current user's trusted devices |
| POST | `/api/v1/auth/passkeys/registration/options` | — | API | Passport bearer token; active and verified; 5/min | Create WebAuthn registration challenge/options |
| POST | `/api/v1/auth/passkeys/registration/{challengeId}/verify` | — | API | Passport bearer token; active and verified; 5/min | Verify and store a passkey registration |
| POST | `/api/v1/auth/passkeys/authentication/options` | — | API | Public; 10/min | Create discoverable passkey authentication challenge/options |
| POST | `/api/v1/auth/passkeys/authentication/{challengeId}/verify` | — | API | Public; 10/min | Verify assertion and issue token or MFA challenge |
| GET | `/api/v1/auth/passkeys` | — | API | Passport bearer token; active and verified | List current user's passkeys |
| DELETE | `/api/v1/auth/passkeys/{publicId}` | — | API | Passport bearer token; active and verified | Revoke one owned passkey |
| GET | `/` | — | Browser | Public | Render welcome page |
| GET | `/login` | `login` | Browser | Public; no guest-only middleware | Render session login form |
| POST | `/login` | `login.store` | Browser | Session form; 5/min; CSRF | Process password/MFA sign-in |
| GET | `/reset-password` | `password.reset.form` | Browser | Public | Render reset page; reads token/email query values client-side |
| POST | `/logout` | `logout` | Browser | `auth:web`; 10/min; CSRF | Invalidate browser session and redirect to login |
| GET | `/.well-known/openid-configuration` | `oidc.discovery` | OIDC protocol | Public | OIDC discovery metadata |
| GET | `/oidc/jwks` | `oidc.jwks` | OIDC protocol | Public | Publish active signing public keys |
| GET | `/oidc/authorize` | `oidc.authorize` | OIDC protocol/browser | `auth:web`; 20/min | Validate authorization request and render consent |
| POST | `/oidc/authorize/approve` | `oidc.approve` | OIDC protocol/browser | `auth:web`; 10/min; CSRF | Approve/deny pending OIDC request and redirect client |
| POST | `/oidc/token` | `oidc.token` | OIDC protocol | Client authentication; 10/min; CSRF-exempt | Exchange OIDC code for OIDC access and ID tokens |
| GET | `/oidc/userinfo` | `oidc.userinfo` | OIDC protocol | OIDC bearer token; 30/min | Return scope-limited claims |
| POST | `/oidc/logout` | `oidc.logout` | OIDC protocol/browser | `auth:web`; 10/min; CSRF | Revoke OIDC tokens, end web session, optionally redirect |
| POST | `/oauth/token` | `passport.token` | OAuth protocol | Client/grant-specific; Passport `throttle` | Issue Passport OAuth token set |
| POST | `/oauth/device/code` | `passport.device.code` | OAuth protocol | Device client; Passport `throttle` | Start device authorization grant |
| GET | `/oauth/authorize` | `passport.authorizations.authorize` | OAuth/browser | Web session required by Passport controller | Render authorization consent |
| POST | `/oauth/authorize` | `passport.authorizations.approve` | OAuth/browser | `auth:web`; CSRF | Approve Passport authorization |
| DELETE | `/oauth/authorize` | `passport.authorizations.deny` | OAuth/browser | `auth:web`; CSRF | Deny Passport authorization |
| GET | `/oauth/device` | `passport.device` | OAuth/browser | Public | Render device user-code form |
| GET | `/oauth/device/authorize` | `passport.device.authorizations.authorize` | OAuth/browser | `auth:web` | Validate user code and render device consent |
| POST | `/oauth/device/authorize` | `passport.device.authorizations.approve` | OAuth/browser | `auth:web`; CSRF | Approve device request held in session |
| DELETE | `/oauth/device/authorize` | `passport.device.authorizations.deny` | OAuth/browser | `auth:web`; CSRF | Deny device request held in session |
| POST | `/oauth/token/refresh` | `passport.token.refresh` | Passport browser package | `auth:web`; web session/CSRF | Refresh Passport's transient SPA token cookie (not an OAuth refresh-token grant) |
| POST | `/_boost/browser-logs` | `boost.browser-logs` | Developer tooling | No route middleware; CSRF middleware explicitly removed; Boost conditional | Receive Boost-injected browser logs |
| GET | `/storage/{path}` | `storage.local` | Framework file route | Signed URL for private local disk; no user auth middleware | Serve local-disk file |
| PUT | `/storage/{path}` | `storage.local.upload` | Framework file route | Signed relative URL with `upload=true`; no user auth middleware | Write request body to local disk |
| GET | `/up` | — | Health check | Public | Laravel health response |

## 3. API routes — detailed integration reference

### API conventions

- Base URL: `{{AUTH_BASE_URL}}`; API prefix: `/api/v1/auth`.
- Send `Accept: application/json`; JSON requests should also send `Content-Type: application/json`. Bearer-protected routes require `Authorization: Bearer <access_token>`.
- The API middleware group is stateless for these routes; it does not require browser CSRF tokens. Validation errors are JSON when routed under `/api/*`; Laravel returns `422` with `message` and field-keyed `errors`. Rate limits return `429` with framework throttle headers. Listed `security.throttle:N,1` limits are N attempts per minute.
- `auth:api` uses Passport. `RequireActiveAccount` also requires `status=active` and a non-null `email_verified_at`; when an existing bearer token is used by an ineligible account, it revokes that access token and its associated refresh tokens and returns `403`.
- Common sample values such as `<token>` and `<timestamp>` are placeholders, not usable credentials. Do not log tokens, passwords, TOTP secrets, verification codes, or recovery codes.

### Identity, verification, and password recovery

| Method and path | Request | Success | Other behavior / errors |
| --- | --- | --- | --- |
| `POST /api/v1/auth/register` | JSON: `name` required string max 150; `username` optional string max 80, alpha-dash and unique; `email` required valid email max 254 and unique; `phone` optional string max 20 and unique; `password` required string 12–128 chars, with matching `password_confirmation`. | `201`: `{"message":"Registration received. Verify your email before signing in.","user":{"public_id":"…","name":"…","username":null,"email":"…","phone":null,"status":"pending","email_verified_at":null,"phone_verified_at":null}}` | `422` validation/duplicate identity; `429`. Password is hashed by the model. Creates pending account and one hashed email-verification token, invalidating prior pending token; sends `AuthEmailVerificationNotification` by mail. Token expires in 30 minutes. |
| `POST /api/v1/auth/login` | JSON: `email` required valid email max 254; `password` required string max 128; `device_name` optional string max 100. `trusted_device_token` is additionally read by the MFA middleware when present (it is not part of the controller's validated return data). | `200`: `{"token_type":"Bearer","access_token":"<token>","expires_at":"<timestamp>","user":{…public fields…}}`. If TOTP is enabled and no valid trusted-device token is supplied, `202`: `{"message":"Two-factor authentication is required.","mfa_required":true,"challenge_token":"<challenge>","expires_in":300}`. | `401` invalid credentials; `403` inactive/unverified account; `423` active lockout; `422` validation; `429`. Five failed password attempts lock the account for 15 minutes. Successful login resets failures and issues a Passport personal access token. A valid, unrevoked, unexpired trusted-device token bypasses the MFA challenge. |
| `POST /api/v1/auth/login/2fa` | JSON: `challenge_token` required string max 128; `code` required string max 128 (six-digit TOTP or recovery code); `device_name` optional string max 150; `trust_device` optional boolean. | `200`: `{"message":"Login successful.","token_type":"Bearer","access_token":"<token>","expires_at":"<timestamp>","user":{…}}`. If `trust_device=true`, also returns `trusted_device_token` and `trusted_device_expires_at`. | `422` invalid/expired/used challenge, invalid code, or validation; `423` lockout; `403` inactive/unverified; `429`. Challenge expires in 5 minutes and accepts at most five attempts. Recovery code is consumed on use. A trusted-device token is returned once; store it securely. Device trust lasts 30 days. |
| `POST /api/v1/auth/email/verify` | JSON: `email` required valid email max 254; `token` required string max 128. | `200`: `{"message":"Email verified successfully. You can now sign in.","user":{…,"status":"active","email_verified_at":"<timestamp>",…}}` | `422` unknown, invalid, expired, exhausted, or already-used token; `429`. Successful use activates a pending account. Five wrong attempts consume the token. |
| `POST /api/v1/auth/email/resend` | JSON: `email` required valid email max 254. | `202`: `{"message":"If an unverified account exists, verification instructions will be sent."}` | `422` validation; `429`. Response does not disclose account existence. Existing active challenge is invalidated and a replacement is sent only for an eligible pending account. |
| `POST /api/v1/auth/forgot-password` | JSON: `email` required valid email max 254. | `202`: `{"message":"If an eligible account exists, password reset instructions will be sent."}` | `422` validation; `429`. Response does not disclose existence. Only active users receive the reset notification. Reset token lifetime is the configured `auth.passwords.users.expire` (60 minutes in current config). |
| `POST /api/v1/auth/reset-password` | JSON: `email` required valid email max 254; `token` required string max 512; `password` required string 12–128 chars with matching `password_confirmation`. | `200`: `{"message":"Password reset successfully. Please sign in again."}` | `422` invalid/expired/used token, ineligible account, or validation; `429`. On success changes password and timestamp, invalidates remembered login, login MFA challenges, Passport access/refresh tokens, database sessions, and trusted devices. |
| `POST /api/v1/auth/phone/verify/request` | No body fields. Uses the authenticated user's stored phone and account email. | `202`: `{"message":"Phone verification instructions were sent to your account email."}` | Requires bearer token and active/verified account; `422` user has no phone; `409` phone is already verified; `429`. Code is sent by email only; no SMS/WhatsApp provider is invoked. Expiry uses `PHONE_VERIFICATION_EXPIRE_MINUTES` (default 10). A new challenge consumes any previous pending phone code. |
| `POST /api/v1/auth/phone/verify` | JSON: `code` required exactly six digits. | `200`: `{"message":"Phone number verified successfully.","user":{…,"phone_verified_at":"<timestamp>"}}` | Requires bearer token and active/verified account; `422` invalid, expired, consumed, exhausted, no-phone, or already-verified state; `429`. At most five wrong code attempts. Verification notification is sent to account email even though the number is the item being verified. |

### Current account and token/session endpoints

| Method and path | Request | Success | Errors and side effects |
| --- | --- | --- | --- |
| `GET /api/v1/auth/me` | Bearer token; no body. | `200`: `{"user":{"public_id":"…","name":"…","username":"…","email":"…","phone":"…","status":"active","email_verified_at":"…","phone_verified_at":null}}` | `401` missing/invalid/revoked/expired token; `403` inactive/unverified account. Does not return the password or internal numeric id. |
| `POST /api/v1/auth/logout` | Bearer token; empty body. | `200`: `{"message":"Signed out successfully."}` | `401` invalid token; `403` account not active/verified. Revokes only presented access token and its associated active refresh tokens. |
| `POST /api/v1/auth/logout-all` | Bearer token; empty body. | `200`: `{"message":"All sessions have been signed out."}` | `401` invalid token; `403` account not active/verified. Revokes all user's active Passport access/refresh tokens and OIDC access tokens and deletes database-backed session rows. |

### MFA and trusted devices

All routes here require bearer authentication and `RequireActiveAccount`, except the public `/login/2fa` exchange documented above.

| Method and path | Request | Success | Errors / side effects |
| --- | --- | --- | --- |
| `GET /api/v1/auth/mfa/status` | No body. | `200`: `{"totp_enabled":true,"unused_recovery_codes":10}` | `401`/`403`. Count is zero when TOTP is not enabled. |
| `POST /api/v1/auth/mfa/totp/setup` | No body. | `200`: `{"message":"Scan the provisioning URI, then confirm with a current code.","secret":"<returned-secret>","provisioning_uri":"otpauth://…"}` | `409` already enabled; `429`. Replaces unconfirmed setup and returns a secret only here. Protect it like a password; do not log or store it in client telemetry. |
| `POST /api/v1/auth/mfa/totp/confirm` | JSON: `code` required exactly six digits. | `200`: `{"message":"Two-factor authentication enabled.","recovery_codes":["<one-time-code>",…],"warning":"Save these codes securely. They will not be shown again."}` (10 codes). | `422` setup missing/unavailable or code invalid; `429`. Recovery codes are stored hashed and displayed once. |
| `POST /api/v1/auth/mfa/totp/disable` | JSON: `password` required string; `code` required exactly six digits. | `200`: `{"message":"Two-factor authentication disabled. All trusted devices were revoked."}` | `422` wrong password, TOTP not enabled, invalid/reused TOTP code; `429`. Revokes TOTP, marks unused recovery codes used, and revokes trusted devices. |
| `POST /api/v1/auth/mfa/recovery-codes/regenerate` | JSON: `password` required string; `code` required exactly six digits. | `200`: `{"message":"Recovery codes regenerated. Previous codes are no longer valid.","recovery_codes":["<one-time-code>",…]}` | `422` wrong password or unavailable/invalid TOTP; `429`. Replaces prior codes; ten new codes are displayed once. |
| `GET /api/v1/auth/trusted-devices` | No body. | `200`: `{"devices":[{"id":1,"public_id":"…","name":"…","ip_address":"…","user_agent":"…","last_used_at":"…","expires_at":"…","created_at":"…"}]}` | `401`/`403`. Returns only current user's unrevoked, unexpired devices. |
| `DELETE /api/v1/auth/trusted-devices/{id}` | Path `id`: numeric database identifier (route constrained to digits); no body. | `200`: `{"message":"Trusted device revoked."}` | `404` missing, revoked, or not owned by caller; `401`/`403`. |
| `POST /api/v1/auth/trusted-devices/revoke-all` | No body. | `200`: `{"message":"All trusted devices revoked.","revoked_count":2}` | `401`/`403`. Only caller's active devices are affected. |

### WebAuthn/passkey API

The client must use a browser WebAuthn implementation and send its serialized credential object as JSON. RP ID and allowed origins come from `config/webauthn.php`; registration requires resident key and user verification. Challenges expire after five minutes and are consumed once.

| Method and path | Request | Success | Errors / side effects |
| --- | --- | --- | --- |
| `POST /api/v1/auth/passkeys/registration/options` | Bearer token; no body. | `200`: `{"challenge_id":"<uuid>","public_key":{"challenge":"…","rp":{"name":"…","id":"…"},"user":{"id":"…","name":"…","displayName":"…"},"pubKeyCredParams":[…],"authenticatorSelection":{"residentKey":"required","userVerification":"required"},…}}` | `401`/`403`/`429`. Stores encrypted, one-use registration options; excludes existing active credentials. |
| `POST /api/v1/auth/passkeys/registration/{challengeId}/verify` | Bearer token; path challenge ID created above; JSON body is browser's serialized `PublicKeyCredential` attestation response; optional `name` string max 150 may be sent alongside credential members. | `201`: `{"message":"Passkey registered."}` | `422` invalid, expired, replayed, wrong-user, wrong-origin/RP, bad-attestation, duplicate credential, or invalid optional name; `401`/`403`/`429`. Stores verified public credential and metadata; challenge consumed. |
| `POST /api/v1/auth/passkeys/authentication/options` | Public; no body. | `200`: `{"challenge_id":"<uuid>","public_key":{"challenge":"…","rpId":"…","userVerification":"required","timeout":60000,…}}` | `429`. Creates a discoverable-credential assertion challenge; no account is selected at this stage. |
| `POST /api/v1/auth/passkeys/authentication/{challengeId}/verify` | Public; JSON body is serialized assertion `PublicKeyCredential`. | `200`: `{"token_type":"Bearer","access_token":"<token>","expires_at":"<timestamp>","user":{"id":1,"public_id":"…","name":"…","email":"…"}}`. When TOTP remains enabled, `202`: `{"mfa_required":true,"challenge_token":"<challenge>","expires_in":300}` instead of access token. | `401` invalid assertion/challenge, inactive/unverified/locked account, bad signature, stale counter, or replay; `429`. On accepted assertion updates authenticator counter/last-use. TOTP-enabled accounts must complete `/api/v1/auth/login/2fa`. |
| `GET /api/v1/auth/passkeys` | Bearer token; no body. | `200`: `{"data":[{"public_id":"…","name":"…","transports":"internal","last_used_at":"…","created_at":"…"}]}` | `401`/`403`. Lists only current user's nonrevoked credentials. |
| `DELETE /api/v1/auth/passkeys/{publicId}` | Bearer token; `publicId` must be UUID by route constraint; no body. | `200`: `{"message":"Passkey revoked."}` | `404` missing, already revoked, or not owned by caller; `401`/`403`. |

## 4. Web/browser routes — pages, forms, redirects, and access rules

Web routes use Laravel's `web` middleware (cookies, session, and CSRF) unless the route is a framework/package route outside that group. State-changing browser forms include CSRF tokens. There is no product-role authorization implemented in these routes.

| Method/path | Page/action | Inputs and behavior |
| --- | --- | --- |
| `GET /` | `routes/web.php` closure renders `resources/views/welcome.blade.php`. | Public static Laravel welcome page; no authentication behavior. |
| `GET /login` (`login`) | `WebSessionController::create`, `resources/views/auth/login.blade.php`. | Public; no guest-only restriction. Renders email/password and, if this session has a current pending MFA step, the code field. |
| `POST /login` (`login.store`) | `WebSessionController::store`; same login view on failures/MFA step, redirect on success. | CSRF form fields: `email` required valid email max 254; `password` required string max 128; `code` optional string max 128 (six-digit TOTP or recovery code). Valid credentials for TOTP account first create five-minute session-pending challenge and rerender with code input. Success logs web guard in, regenerates session ID, and redirects to intended URL (default `/`). Invalid credentials 401 with inline message; invalid MFA 422; locked 423; inactive/unverified 403; validation errors return the form with Laravel error bag. Five failed password/MFA attempts cause 15-minute account lockout. Rate limit 5/min. |
| `GET /reset-password` (`password.reset.form`) | Closure renders `resources/views/auth/password-reset.blade.php`. | Public query fields: `token`, `email`. The page reads them, immediately removes token from visible URL using `history.replaceState`, and submits new password plus confirmation as JSON to `/api/v1/auth/reset-password`. Responses appear as inline status text. Response sets `Referrer-Policy: no-referrer` and `Cache-Control: no-store, private`; page also declares `no-referrer`. Does not use a browser CSRF token because it calls the stateless API route. |
| `POST /logout` (`logout`) | `WebSessionController::destroy`. | Requires authenticated web session and CSRF token; 10/min. Logs out guard, invalidates session, regenerates CSRF token, records event, and redirects `/login`. |

### Passport browser pages and approval forms

Passport binds its pages through `AppServiceProvider` to `resources/views/auth/oauth/authorize.blade.php`, `auth/oauth/device/user-code.blade.php`, and `auth/oauth/device/authorize.blade.php`. These are package controller flows with project-provided templates.

- `GET /oauth/authorize` (`passport.authorizations.authorize`) is the OAuth authorization-code consent page. User must have a web session; unauthenticated users are sent through the `login` flow. OAuth request parameters are validated by Passport and include client, redirect URI, response type, state, and optional PKCE parameters. The page displays client/scopes and offers Approve/Deny.
- `POST /oauth/authorize` (`passport.authorizations.approve`) submits the Passport `auth_token` hidden field with CSRF protection. It returns a redirect to the exact registered client redirect URI with authorization code and state. Authorization code lifetime is 10 minutes per installed Passport service provider. Rejection is `DELETE /oauth/authorize` (`passport.authorizations.deny`), represented by `_method=DELETE` from the template; it completes the OAuth denial response.
- `GET /oauth/device` (`passport.device`) displays a form with `user_code`. If query `user_code` is present, it redirects to `/oauth/device/authorize?user_code=...`.
- `GET /oauth/device/authorize` (`passport.device.authorizations.authorize`) requires a signed-in web user, resolves the code, and shows client/scope consent. Invalid user code redirects back to `/oauth/device` with an error. The project template carries `auth_token`, client ID, and state hidden fields.
- `POST /oauth/device/authorize` approves the device challenge held in the web session; `DELETE /oauth/device/authorize` denies it (HTML uses method spoofing). Both require session auth and CSRF. The device client polls `/oauth/token` with its device code; user approval alone does not issue its token.
- `POST /oauth/token/refresh` (`passport.token.refresh`) is Passport's session-authenticated transient-token-cookie refresh. It returns text `Refreshed.` and sets the `laravel_token` cookie. It is not the OAuth `refresh_token` grant; that grant is submitted to `/oauth/token`.

These Passport routes do not have VisionWeb's custom `security.throttle` alias except where their route list shows Passport's package `throttle` middleware. Their effective limits are package/framework behavior, not a VisionWeb-specific limit asserted here.

## 5. OIDC and OAuth protocol routes

### Passport OAuth token and device endpoints

Passport registers its endpoints from `vendor/laravel/passport/routes/web.php`. Password and implicit grants are disabled by Passport defaults and no application code enables them. The active token grants observed in Passport's provider are authorization code, refresh token, client credentials, and device authorization. Personal access tokens are issued by the authenticated VisionWeb login/passkey controllers through Passport's `createToken`, not a separate package JSON management route. The package's Passport JSON management routes (`/oauth/tokens`, `/oauth/clients`, etc.) are not registered in the route inventory.

`POST /oauth/token` (`passport.token`) uses OAuth form parameters (JSON works in the project tests); confidential clients authenticate with `client_secret` or HTTP Basic, while public PKCE clients do not use a secret. Send `Accept: application/json` and do not put secrets in URLs.

| Grant | Request body fields | Successful result |
| --- | --- | --- |
| Authorization code | `grant_type=authorization_code`, `client_id`, `code`, exact `redirect_uri`; `code_verifier` for PKCE; confidential client secret via Basic or `client_secret` as accepted by Passport. | `200` JSON includes `access_token`, `token_type`, `expires_in`, `refresh_token`, and usually `scope`. Code is single-use. |
| Refresh token | `grant_type=refresh_token`, `refresh_token`, `client_id`; client authentication as required by that client. | `200` token response with new access and refresh tokens. Refresh token is revoked after use; replay/revoked/expired/wrong-client tokens fail as `400` `invalid_grant`. |
| Client credentials | `grant_type=client_credentials`, `client_id`, `client_secret`; optional requested `scope` subject to client/scopes configuration. | `200` includes access token, token type, expiry, scope; no user-bound refresh token in the verified test contract. |
| Device code | `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `client_id`, `device_code`. | `200` token response after approval; pending, denied, expired, or reused device codes follow OAuth device grant errors. |

`POST /oauth/device/code` begins the device flow; tested request is `client_id`. Successful response fields are `device_code`, `user_code`, `verification_uri`, `expires_in`, and `interval`. Display `verification_uri` and user code on the client device; the user completes approval in the browser route above. The OAuth server controls device code expiry and polling interval. The `/oauth/token` and `/oauth/device/code` routes use Passport's package `throttle` middleware.

Passport emits OAuth error JSON such as `{"error":"invalid_client"}`, `{"error":"invalid_grant"}`, or `{"error":"unsupported_grant_type"}` with OAuth-appropriate 4xx status. The exact message/headers are produced by installed Passport/League OAuth server. The global `RecordPassportTokenFailures` middleware records only failed token requests' grant type, not client secrets or grant credentials.

No project-specific Passport token lifetime override was found. Installed Passport's current defaults are one year for access tokens, refresh tokens, and personal access tokens; client-credentials tokens default to the access-token lifetime. Treat this as the current package default, not a stable VisionWeb policy. The application login and passkey endpoints return their actual Passport-issued expiration timestamp.

### OIDC discovery, authorization code, userinfo, and logout

OIDC routes are implemented by `App\Http\Controllers\Api\V1\OidcController`; these are normal web-middleware routes at the root (not `/api/v1`). Discovery issuer and endpoint URLs derive from `config('app.url')`.

| Method/path | Request/response and behavior |
| --- | --- |
| `GET /.well-known/openid-configuration` (`oidc.discovery`) | Public JSON discovery with issuer, authorization/token/userinfo/JWKS/logout endpoints; code response only; public/pairwise subjects; RS256; scopes `openid profile email phone`; client auth methods `client_secret_basic`, `client_secret_post`, `none`; S256; advertised claims. |
| `GET /oidc/jwks` (`oidc.jwks`) | Public `{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"…","n":"…","e":"…"}]}`. Only public RSA key components are returned. Active and still-valid nonretired keys are included. Requires a signing key to exist/be loadable; missing keys result in server error, not an empty setup flow. |
| `GET /oidc/authorize` (`oidc.authorize`) | Requires `auth:web`; query: `client_id` UUID, `redirect_uri` string max 2048 and exact allowlist match, `response_type=code`, `scope` string max 500, `state` and `nonce` strings max 255, `code_challenge` exactly 43 base64url chars, `code_challenge_method=S256`. Client must be enabled and authorized for `authorization_code`; `openid` is required and every requested scope must be allowed. Stores request in session, displays consent. Invalid redirect/scope returns plain 400; ineligible account 403; Laravel validation errors redirect back with session errors. Limit 20/min. |
| `POST /oidc/authorize/approve` (`oidc.approve`) | Requires authenticated web session, CSRF, limit 10/min. Form field `approve` is interpreted as boolean; session contains the validated authorization request. Missing/expired/mismatched session returns JSON 422. Approval creates a random one-use code expiring in five minutes and redirects to registered URI with `code` and original `state`. Denial redirects to same URI with `error=access_denied` and `state`. |
| `POST /oidc/token` (`oidc.token`) | JSON or form request: `grant_type=authorization_code`; optional `client_id` UUID and `client_secret` string max 255; `code` required string exactly 64 characters; `redirect_uri` required string max 2048; `code_verifier` required 43–128 chars matching `[A-Za-z0-9._~-]`. Client auth can be HTTP Basic or post fields. CSRF exemption is explicitly configured for this route; middleware is `web` plus 10/min throttle. Success `200`: `{"access_token":"<token>","token_type":"Bearer","expires_in":600,"id_token":"<signed-jwt>","scope":"openid profile"}` (lifetime is configurable; default access 10 min, ID token 5 min); response has `Cache-Control: no-store` and `Pragma: no-cache`. Errors: `401` `invalid_client`; `400` `invalid_grant` for invalid code, verifier, redirect binding, replay, or unavailable account; validation failure 422. Authorization code is consumed only after valid PKCE verifier. |
| `GET /oidc/userinfo` (`oidc.userinfo`) | Send `Authorization: Bearer <oidc_access_token>`; limit 30/min. `200` returns `sub`, plus scope-selected claims: profile gives `name`, `preferred_username`; email gives `email`, `email_verified`; phone gives `phone_number`, `phone_number_verified`. `401` JSON `{"error":"invalid_token"}` for missing, invalid, expired, revoked, disabled-client, or unavailable-account token. |
| `POST /oidc/logout` (`oidc.logout`) | Requires authenticated web session and CSRF; limit 10/min. Form/JSON optional `client_id` UUID, `post_logout_redirect_uri` max 2048, `state` max 255. If a redirect URI is supplied, client ID is required and URI must exactly match client's configured post-logout allowlist; invalid redirect returns plain 400. Success revokes all the signed-in user's OIDC access tokens and invalidates web session/CSRF token. Returns `Signed out.` 200 if no redirect; otherwise redirects to allowlisted URI, preserving optional state. |

OIDC client settings are attached to existing Passport clients; management is via CLI `oidc:client:configure`, not an HTTP route. Supported scopes/claims and client redirect allowlists are enforced in `OidcController`. Authorization codes are one-use; ID tokens are RS256-signed. No OIDC refresh-token endpoint is registered. Browser OIDC authorization requires the VisionWeb web session; the token and userinfo endpoints are protocol client calls.

## 6. Authentication and security middleware

| Middleware/configuration | Routes / effect |
| --- | --- |
| `auth:api` | Protected API group; Passport bearer-token authentication. Invalid credentials yield JSON 401. |
| `RequireActiveAccount` | Runs after `auth:api`; blocks inactive or email-unverified accounts with 403, revokes the current Passport access/refresh pair, and records security/audit events. |
| `RequireMfaChallenge` | Runs before password-login controller. If supplied credentials match an active/verified, unlocked TOTP user and no valid trusted device is presented, creates a hashed five-minute login MFA challenge and returns 202 without issuing an access token. It reads `trusted_device_token` from request input. |
| `security.throttle:N,1` | Alias for `RecordRateLimitEvent`, a `ThrottleRequests` subclass. N requests per one-minute decay window on routes as listed. On rejection, logs route-only context to security and audit records, then returns standard 429. |
| `RecordPassportTokenFailures` | Prepended global middleware. On OAuth `/oauth/token` 4xx grant/client failures, records only the grant type and safe request metadata. |
| `web` | Session/cookie and CSRF behavior for web routes. `bootstrap/app.php` exempts only `oidc/token` from CSRF because it is a client protocol endpoint. |
| JSON exception negotiation | `bootstrap/app.php` renders exceptions as JSON for `api/*` paths or requests with `Accept: application/json`; browser validation normally flashes errors/redirects back. |
| Account security | Password login lockout occurs after five failures for 15 minutes. API, email resend, verification, MFA, passkey, and web login throttles are route-specific. Login/MFA verification codes and OAuth/OIDC codes are one-use where implemented. |

## 7. Complete user flows and route sequences

### New account and login

1. `POST /api/v1/auth/register` with profile/password fields.
2. User receives an email containing the verification token. If needed, call `POST /api/v1/auth/email/resend` with the email.
3. `POST /api/v1/auth/email/verify` with email and token; account becomes active.
4. `POST /api/v1/auth/login`. Store returned Passport bearer token securely. If response is MFA 202, call `/api/v1/auth/login/2fa` with challenge and TOTP/recovery code, then use returned token.
5. Use `GET /api/v1/auth/me` to fetch public identity; call logout or logout-all when ending sessions.

### Phone verification

1. Authenticate, then `POST /api/v1/auth/phone/verify/request`.
2. Read code from the user's account email, then `POST /api/v1/auth/phone/verify` with `code`.
3. This does not send SMS or WhatsApp. A purchased provider is not wired to these routes.

### Password recovery

1. `POST /api/v1/auth/forgot-password` with email; response stays generic.
2. Follow emailed reset link to `GET /reset-password?token=…&email=…`; page removes token from the visible URL and submits to API.
3. Or call `POST /api/v1/auth/reset-password` directly with token, new password, and confirmation.

### MFA and trusted device

1. Authenticated client calls `/api/v1/auth/mfa/totp/setup`; enroll secret/URI in authenticator app.
2. Call `/api/v1/auth/mfa/totp/confirm` with a current six-digit code; save the returned recovery codes securely.
3. Login generates a challenge; call `/api/v1/auth/login/2fa`. Set `trust_device=true` only if the client can safely protect the returned one-time device token; then send it as `trusted_device_token` in future password-login requests.
4. List/revoke trusted devices under `/api/v1/auth/trusted-devices`; disabling TOTP revokes all trusted devices.

### Passkeys

1. Authenticated user requests `/api/v1/auth/passkeys/registration/options`, passes `public_key` to browser WebAuthn create operation, then posts serialized credential to `/registration/{challengeId}/verify`.
2. For login, call public `/api/v1/auth/passkeys/authentication/options`, execute browser WebAuthn get operation, then post assertion to `/authentication/{challengeId}/verify`.
3. If TOTP is enabled, complete the returned challenge at `/api/v1/auth/login/2fa`; otherwise use the issued bearer token. List/revoke passkeys using protected endpoints.

### OAuth and OIDC SSO

- Passport authorization-code: create/obtain a registered OAuth client outside these HTTP routes; send browser to `/oauth/authorize` with exact redirect and PKCE `S256`; user signs in at `/login`, consents, and client exchanges returned code at `/oauth/token`.
- Passport device flow: client posts to `/oauth/device/code`, user opens returned verification URI, enters user code at `/oauth/device`, signs in and approves, then device polls `/oauth/token` with device grant fields.
- OIDC: configure existing client metadata using CLI; fetch discovery/JWKS; redirect signed-in user through `/oidc/authorize`; POST approval; exchange code at `/oidc/token`; call `/oidc/userinfo` with returned bearer; end session through `/oidc/logout`.

## 8. Error handling, validation, throttling, and session behavior

- API validation errors are `422` JSON with a general `message` and `errors` map. API auth failures are JSON. OAuth/OIDC token errors use protocol error members rather than VisionWeb's standard `{message}` shape.
- Browser validation failures normally redirect back and store the Laravel error bag in session; login template displays the first error or controller-provided feedback. Protocol routes can instead return redirects, text 4xx, or JSON as explicitly noted above.
- Throttle syntax `N,1` is N requests in a one-minute window. `429` responses are generated by Laravel middleware; do not assume custom per-route retry policy beyond that.
- Verification limits from code: email verification token 30 minutes, phone code default 10 minutes configurable, login MFA challenge 5 minutes/five attempts, password reset 60-minute config, OAuth authorization code 10 minutes from Passport grant config, OIDC authorization code 5 minutes, WebAuthn challenge 5 minutes, trusted device 30 days.
- Web session cookies are HTTP-only by default, SameSite Lax by default, and secure by default in production unless explicitly overridden. Session login regenerates session ID; logout invalidates session and CSRF token.
- The effective local mailer currently resolves to `smtp` (`php artisan config:show mail.default`). This confirms the selected transport only; no SMTP credential values were inspected and no real inbox delivery was tested. Source proves notifications use Laravel mail, but actual inbox delivery remains unconfirmed until a verification message is received.

## 9. Route names, controllers, views, and implementation files

| Area | Main implementation |
| --- | --- |
| API route definitions and auto-prefix | `routes/api.php`, `bootstrap/app.php` |
| Registration/login/logout/email/phone verification | `app/Http/Controllers/Api/V1/Auth/AuthController.php` |
| Password recovery | `app/Http/Controllers/Api/V1/Auth/PasswordRecoveryController.php`, `app/Notifications/AuthPasswordResetNotification.php` |
| TOTP, login challenge, recovery codes, trusted devices | `app/Http/Controllers/Api/V1/Auth/MfaController.php`, `app/Http/Middleware/RequireMfaChallenge.php` |
| Browser login/logout | `app/Http/Controllers/Api/V1/Auth/WebSessionController.php`, `resources/views/auth/login.blade.php` |
| Passkeys | `app/Http/Controllers/Api/V1/WebAuthnController.php`, `app/Services/WebAuthnService.php`, `config/webauthn.php` |
| OIDC | `app/Http/Controllers/Api/V1/OidcController.php`, `resources/views/auth/oidc/consent.blade.php` |
| Account gate, throttles, token failures | `app/Http/Middleware/RequireActiveAccount.php`, `RecordRateLimitEvent.php`, `RecordPassportTokenFailures.php` |
| Route middleware and exception negotiation | `bootstrap/app.php` |
| Session reset page | `routes/web.php`, `resources/views/auth/password-reset.blade.php` |
| Passport page bindings | `app/Providers/AppServiceProvider.php`; `resources/views/auth/oauth/**` |
| Discovery and scheduled commands | `routes/web.php`, `routes/console.php` |
| Package route sources | `vendor/laravel/passport/routes/web.php`; Laravel filesystem and health route providers; Laravel Boost service provider |

Important named application routes: `login`, `login.store`, `logout`, `password.reset.form`, `oidc.discovery`, `oidc.jwks`, `oidc.authorize`, `oidc.approve`, `oidc.token`, `oidc.userinfo`, and `oidc.logout`. Passport names are listed in the route inventory.

## 10. Unresolved questions and confirmed implementation limitations

- No separate routes are registered from additional project route files. `routes/console.php` contains scheduled commands only.
- `GET /storage/{path}` and `PUT /storage/{path}` are Laravel-generated routes because the local disk has `serve=true`; the current local disk is private. They rely on temporary signed URLs, not an authenticated VisionWeb account. Do not use them as auth endpoints. Invalid signatures produce 403 outside production and 404 in production; file absence/path traversal returns 404. Upload uses a signed URL with `upload=true` and stores the raw request body.
- `/_boost/browser-logs` is package tooling, not a product route. Boost only runs in local environment or debug mode and the browser watcher is enabled by default; the route has no auth middleware and disables CSRF. It accepts a `logs` array (including sendBeacon text/plain JSON) and writes browser-log data to the browser log channel. Do not enable Boost/debug routes in an exposed production environment.
- `/up` is Laravel's health endpoint: JSON requests receive `{"status":"up"}` with 200 or `{"status":"down"}` with 500; HTML requests receive the framework health page. Health listeners determine what is checked. It is not an authentication check.
- Real mail inbox delivery is not confirmed while the effective mailer is `log`. Phone/SMS/WhatsApp codes are email-delivered by design at this stage; no actual SMS or WhatsApp delivery exists.
- Passport OAuth client provisioning is an operational CLI/database concern; this inventory exposes no project OAuth-client CRUD HTTP endpoints. OIDC client settings are configured with the `oidc:client:configure` command.
- Actual callback URL availability, reverse-proxy HTTPS behavior, production CORS/origin policy, mail provider connectivity, and physical-authenticator behavior depend on deployment/client infrastructure and are `Not confirmed from source code`.
- Laravel Boost and Passport package routes are version-dependent. Re-run `php artisan route:list --json` after dependency or route-provider changes; this document reflects the registered inventory inspected for Laravel 13 / Passport 13.10.0.
