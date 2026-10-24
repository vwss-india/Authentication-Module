# UI/UX audit

Scope: current browser routes, views, controllers, middleware, models, migrations, and related tests. No files were changed and no packages were installed.

## Normal User Portal

| Page or feature | Status | Actual implementation and gap |
|---|---|---|
| Home | Incomplete | GET / renders Laravel’s generic welcome view (/E:/xampp8.2/htdocs/projects/auth-vwss-2.0/resources/views/welcome.blade.php). It includes a Dashboard link, but there is no dashboard route. |
| Login | Implemented, minimal | GET/POST /login uses WebSessionController (/E:/xampp8.2/htdocs/projects/auth-vwss-2.0/app/Http/Controllers/Api/V1/Auth/WebSessionController.php) and login view (/E:/xampp8.2/htdocs/projects/auth-vwss-2.0/resources/views/auth/login.blade.php). It supports password login, MFA codes, CSRF, throttling, lockout, and feedback. The standalone page has no shared layout or navigation. Related coverage exists in WebSessionAuthTest. |
| Logout | Implemented | POST /logout requires auth:web, invalidates the session, regenerates the CSRF token, and redirects to /login. Covered by WebSessionAuthTest. |
| Registration | Missing as a browser page | Registration exists at POST /api/v1/auth/register, but there is no /register web route or registration view. |
| Email verification | Missing as a browser page | Verification and resend are API endpoints in AuthController; no verification page or browser flow exists. |
| Password recovery | Partially implemented | GET /reset-password renders password-reset view (/E:/xampp8.2/htdocs/projects/auth-vwss-2.0/resources/views/auth/password-reset.blade.php), which submits to the API reset endpoint and removes the token from the visible URL. There is no browser “forgot password” request page. |
| MFA | Missing as a browser management page | TOTP setup/status/disable, recovery-code management, and login challenge are API-backed. The login page accepts an MFA code after password submission; no security-settings UI exists. |
| Passkeys | Missing as a browser UI | Registration, authentication, listing, and revocation are implemented in WebAuthnController as API endpoints. There is no passkey management page. |
| Trusted devices | Missing as a browser UI | List, revoke, and revoke-all operations are API endpoints. No page exists. |
| Profile and sessions | Missing | /api/v1/auth/me is read-only. There is no profile page/update flow, browser session list, or session management page. API logout-all exists, but no user-facing interface for it. |

Account isolation: protected API routes use auth:api and RequireActiveAccount; MFA and passkey operations are scoped to the authenticated user. This supports own-account access for those API operations. It does not provide a browser portal or session/profile management UI.

## Master Admin Panel

| Capability | Status | Evidence and prerequisite |
|---|---|---|
| Admin dashboard/navigation | Absent | No admin routes, controller namespace, or admin views found. |
| User search/detail/status controls | Absent | No admin endpoints or UI for managing users. The status column supports account state, but is not an admin capability by itself. |
| Security monitoring | No admin UI | Security events, audit logs, and alerts have application-side models/processing, but no administrative routes or views were found. |
| Admin roles/permissions | Absent | No role or permission model/migration, admin guard, admin middleware, gate, or policy found. |

Role separation is not implemented: there is currently no Master Admin level or administrative interface to separate from normal users. The User fillable fields exclude role assignment, and the users migration has no role column, so ordinary registration does not appear to permit self-assignment of an admin role. That does not satisfy the requested admin boundary: before an admin panel exists, the project needs a server-enforced admin identity/authorization mechanism and protected admin endpoints. Hiding links alone would not be sufficient.

## Relevant routes, controllers, views, and middleware

- Browser authentication: /login, /logout, /reset-password, handled by WebSessionController or a closure in routes/web.php (/E:/xampp8.2/htdocs/projects/auth-vwss-2.0/routes/web.php).
- Browser OAuth/OIDC consent: Passport authorization and device pages, plus /oidc/authorize and /oidc/authorize/approve; rendered by the OAuth/OIDC consent views. These are protocol consent pages, not a general account portal.
- API-backed user security pages could use routes in routes/api.php (/E:/xampp8.2/htdocs/projects/auth-vwss-2.0/routes/api.php) and controllers AuthController, MfaController, and WebAuthnController.
- auth:web protects browser logout and OIDC authorization actions; API account routes use auth:api and RequireActiveAccount. Login and reset use security throttling; web forms use CSRF.
- Views are standalone HTML with little shared styling. resources/css/app.css imports Tailwind, while resources/js/app.js is effectively empty. No reusable portal or admin layout was found.
- Related tests include WebSessionAuthTest, AuthApiTest, MfaFlowTest, PasswordRecoveryTest, and WebAuthnFlowTest.

## Recommended hierarchy and design

Normal User Portal: Sign in / register → verification and recovery → account overview → Profile → Security settings (MFA, passkeys, trusted devices, sessions). Keep it focused on the signed-in user, with clear labels, keyboard-accessible controls, inline validation, loading/disabled states, and success/error feedback.

Master Admin Panel: Only after backend authorization exists: separate admin sign-in/access boundary → dashboard → user search/detail/status actions → security monitoring. Use a distinct navigation and layout, dense but readable data tables, clear destructive-action confirmations, and permission checks on every server action.

For both interfaces, use responsive layouts, consistent typography and spacing, reusable form/alert/button components, visible focus states, and accessible status messages. Do not reuse an ordinary user’s interface as an admin boundary.

## Phases and prerequisites

1. Build the normal-user browser pages on top of the existing API flows. Add a forgot-password request page and verification flow; MFA, passkeys, and trusted devices can use their existing API operations.
2. Add profile updates and browser session management only after the required backend endpoints and ownership checks exist.
3. Establish server-side admin identity, authorization policies, and protected user/security operations before building any admin UI.
4. Build the separate admin dashboard and management pages against those authorized operations.

Unresolved: the repository does not establish which admin actions or admin role-assignment process are intended. Those policies must be defined before admin work. Email delivery also depends on a configured mail transport; the reset page’s source alone does not confirm inbox delivery.