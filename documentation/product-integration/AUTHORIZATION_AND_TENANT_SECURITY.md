# Authorization and tenant security

## Identity is only the first gate

The ID token proves a Central Auth authentication event for a client. It is not an entitlement, role, subscription or resource authorization token. `visionweb_product` only identifies the server-bound client product; it does not say which organizations, features, records or actions the user can access.

For every protected product operation, evaluate current authorization in this order:

1. Validate Central Auth identity/token and active account.
2. Resolve the product-local identity by `(issuer, sub)` and the requested tenant/resource in the product database.
3. Verify the Central Auth client is bound to the expected active product and token has `product_access`.
4. Obtain the Central Auth decision for the product's organization, feature and required permission.
5. In the product database, verify organization maps to the caller's local tenant and the resource belongs to that tenant.
6. Apply product-local role/permission and business rules to this action.
7. Deny if any input, dependency or decision is missing, stale, contradictory or unavailable. Do not silently fall back to login-only authorization.

## Central Auth's current decision

`ProductAccessService::decide` checks:

- User exists, is `active` and email verified.
- Product slug and organization UUID resolve to an active product and active organization belonging to that product.
- The user has an active membership and an organization-scoped role containing the exact requested permission.
- The organization has an active/trialing subscription whose start is current, end is null or future, plan is active and belongs to the same product.
- The subscription owner is active and email verified.
- Active member count does not exceed non-null plan seat limit.
- Both `access` and requested feature entitlements are enabled for the plan.

This decision does not create a product-local user, select a product-owned row, enforce resource ownership, or return a tenant-specific role object for reuse. Use `ProductAccessService` internally only in Central Auth. Separate products call the documented endpoint; they cannot reuse Central Auth middleware or connect to its database.

## Organization members and seats

An organization owner can assign an existing active Central Auth account with verified email to a role belonging to that same organization. The assignment requires an active subscription and available plan seat, and is audited. Staff uses the organization's subscription; a separate staff purchase is not automatically required. Each member still needs an active membership and explicit product-role permission. Owner assignment does not grant every permission.

The current access decision denies when active membership count is greater than the plan seat limit; assignment rejects adding a member once the limit has been reached. Define whether the owner occupies a seat in the product's plan and make the product catalog/role setup consistent. There is no general custom-role creation API documented for product clients; roles and permission keys are organization-scoped Central Auth data. Business roles and record permissions remain product-owned.

## Entitlements and usage limits

The endpoint requires enabled `access` and requested `feature` entitlement keys. `usage_limit` values are persisted/displayed, but current request authorization does not count or decrement usage. Products must not represent these values as enforced quotas. Decide a metering authority, atomic accounting model, quota reset/lifecycle and overage behavior before selling limits as guarantees.

Subscription statuses treated as usable by the current decision are `active` and `trialing`; suspended, canceled, expired or missing subscriptions deny. There is no payment provider integration implied by the existence of subscription records. Billing, webhook verification, renewal, reconciliation and payment records require separately configured/implemented provider work.

## Safe product-side decision pattern

The following is **pseudocode**. It demonstrates control placement; it is not an existing Central Auth middleware or tested client package:

```text
authenticated = validate_id_token_and_pending_login_transaction(request)
local_user = find_or_create_mapping(issuer, authenticated.sub)
resource = load_requested_resource_from_product_database(route_parameter)
tenant = product_tenant_for(local_user, resource.tenant_id)

if tenant is missing or resource.tenant_id != tenant.id:
    deny

# Server chooses these values from the matched product route and policy.
central = POST product_access_endpoint over TLS with bearer token:
    organization = tenant.central_auth_organization_uuid
    feature = server_defined_feature_for_route
    permission = server_defined_permission_for_action

if central.access is not true:
    deny
if central.product != this_product_slug or central.organization != tenant.central_auth_organization_uuid:
    deny
if not product_local_policy_allows(local_user, resource, action):
    deny

allow
```

Never accept organization, feature or permission strings from the browser as the final authorization input. Bind them to route/resource server-side. Do not cache allow decisions indefinitely: membership, subscription, entitlement and token revocation can change. If caching is required, define a short TTL and invalidation/revocation strategy; fail closed on expired cache or Central Auth unavailability.

## Tenant and resource ownership

Every product query must include the authorized tenant constraint, including background jobs, exports, downloads, websocket subscriptions and admin/support operations. A UUID is an identifier, not an authorization check. Verify both the user's tenant membership and `resource.tenant_id` on each operation. Avoid fetching globally then checking ownership only in a view. Add negative tests for cross-tenant IDs, guessed UUIDs, role changes, removed memberships, account suspension, plan expiry, disabled product/feature and token revocation.

Central Auth does not inspect product business databases and cannot assert that a booking, invoice, sale, file or account belongs to the authorized organization. Do not claim it does.

## Decision endpoint contract

Request: two independent credentials plus decision input. Send the user's opaque Central Auth access token as `Authorization: Bearer ...`; send the product server credential reference and one-time-issued secret in `X-VisionWeb-Product-Credential` and `X-VisionWeb-Product-Secret`; send JSON `organization` UUID, `feature` key and `permission` key; optional `product` is a consistency hint. The server credential resolves to one OIDC client and one product. The token's persisted client ID and product ID must match those bindings. This custom contract uses the stored `oauth_client_id` as the effective audience for the opaque token; the opaque token itself has no JWT `aud` claim.

Results: `200 {access:true, product, organization, feature, permission}`, `403` for missing scope, product/client audience mismatch, product hint mismatch or access denial, and `401` for missing/invalid/expired/revoked server credential or user token. No sensitive token or credential is echoed. Successful server credential use updates `last_used_at`; auth failures are recorded without secret values.

The separate server credential and audience binding are implemented. Remaining boundary: this custom shared-secret contract does not provide mTLS, signed requests, per-caller rate quotas, standardized introspection or a service identity independent of secret possession. Use TLS, keep the secret only in backend secret storage, rotate with overlap, fail closed on errors and set short decision timeouts. Product identity by an end-user token alone is not proof that the HTTP caller is the intended product API.
