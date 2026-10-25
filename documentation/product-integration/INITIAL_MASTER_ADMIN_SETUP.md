# Initial Master Admin Setup

This document explains how to grant the first Master Admin role in the
VisionWeb Central Auth application.

> **Security note:** Run these steps only on the intended
> server/environment. Use a real, verified account controlled by the
> intended administrator. Do not share credentials, tokens, or secrets
> in tickets or chat.

## 1. Create and verify the account

1.  Register the administrator account through the application's normal
    registration flow, or use the approved account-provisioning process.
2.  Complete email verification for that account.
3.  Confirm the account can sign in successfully before granting
    administrative access.

The grant command is intended to promote an existing account; it is not
a substitute for account registration or verification.

## 2. Check the command's supported options

From the Central Auth project directory, run:

``` bash
php artisan help auth:admin:grant
```

Review the displayed arguments and options for the version deployed in
this environment before executing the grant. The command's help output
is the source of truth for the exact syntax.

## 3. Grant Master Admin access

Use the email address of the verified account and provide a meaningful
audit reason. For example, if the command help confirms these options:

``` bash
php artisan auth:admin:grant admin@example.com --reason="Initial master admin bootstrap"
```

If you need to grant an explicit permission list, use the permission
option documented by the command. Wildcard permissions are highly
privileged; use them only if the command explicitly supports them, the
deployment policy allows them, and the operator deliberately confirms
the required wildcard option.

Do not copy the example email literally. Replace it with the intended
administrator's verified account email.

## 4. Verify the result

1.  Check the command output for success or a clear error.
2.  Sign in as the promoted account in a private browser window.
3.  Confirm that the account can access the Master Admin area and only
    the expected administrative functions.
4.  Review the application's audit trail, if available, to confirm the
    grant and reason were recorded.
5.  Keep a secure record of who approved the grant, when it was
    performed, and why.

If the command reports that the account is missing, inactive, or
unverified, resolve that account state first. Do not bypass the
application's verification checks.

## 5. Operational safeguards

-   Use an individually assigned account; do not share a generic
    administrator login.
-   Grant only the permissions required for the administrator's duties.
-   Protect the last active Master Admin account. Do not revoke or
    downgrade it until another authorized Master Admin has been
    verified.
-   Do not put passwords, product secrets, OAuth client secrets, or
    access tokens in this document.
-   Run the grant command against the intended environment only; check
    the `.env` database configuration before running administrative
    commands.
-   If command behavior differs from this guide, follow the deployed
    command's `--help` output and update this document to match the
    verified implementation.

## 6. Troubleshooting

### Command not found

Run:

``` bash
php artisan list
php artisan help auth:admin:grant
```

If the command is not registered, confirm that the correct project
directory and deployed release are being used. Do not improvise a
database update to grant the role.

### Account cannot be promoted

Check that the account exists and has completed the required
verification/activation steps. Read the exact error returned by the
command and follow the application's enforced safeguards.

### Admin UI is unavailable after promotion

Confirm the deployment is using the expected database and environment,
then inspect the application logs. Do not disable authorization
middleware as a workaround.

------------------------------------------------------------------------

**Maintenance:** Keep this document aligned with the actual
`auth:admin:grant` command help and the production deployment procedure.
Before production use, validate the example against the command help
from the deployed release.
