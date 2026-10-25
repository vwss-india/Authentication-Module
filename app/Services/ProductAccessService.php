<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\DB;

class ProductAccessService
{
    /**
     * @return array{allowed: bool, reason: string, organization_id: ?int, subscription_id: ?int}
     */
    public function decide(User $user, string $productSlug, string $organizationPublicId, string $feature, string $permission): array
    {
        $identity = User::query()->whereKey($user->id)->first(['id', 'status', 'email_verified_at']);
        if (! $identity || $identity->status !== 'active' || ! $identity->email_verified_at) {
            return $this->denied('identity_inactive');
        }

        $organization = DB::table('product_organizations as organizations')
            ->join('products', 'products.id', '=', 'organizations.product_id')
            ->where('organizations.public_id', $organizationPublicId)
            ->where('organizations.status', 'active')
            ->where('products.slug', $productSlug)
            ->where('products.status', 'active')
            ->first(['organizations.id', 'organizations.owner_user_id', 'products.id as product_id']);
        if (! $organization) {
            return $this->denied('product_or_organization_unavailable');
        }

        $membership = DB::table('product_memberships as memberships')
            ->join('product_roles as roles', function ($join): void {
                $join->on('roles.id', '=', 'memberships.product_role_id')
                    ->on('roles.organization_id', '=', 'memberships.organization_id');
            })
            ->join('product_role_permissions as permissions', 'permissions.product_role_id', '=', 'roles.id')
            ->where('memberships.organization_id', $organization->id)
            ->where('memberships.user_id', $identity->id)
            ->where('memberships.status', 'active')
            ->where('permissions.permission_key', $permission)
            ->first(['memberships.id']);
        if (! $membership) {
            return $this->denied('membership_or_permission_denied', (int) $organization->id);
        }

        $subscription = DB::table('product_subscriptions as subscriptions')
            ->join('product_plans as plans', 'plans.id', '=', 'subscriptions.plan_id')
            ->where('subscriptions.organization_id', $organization->id)
            ->where('plans.product_id', $organization->product_id)
            ->where('plans.status', 'active')
            ->whereIn('subscriptions.status', ['active', 'trialing'])
            ->where('subscriptions.starts_at', '<=', now())
            ->where(function ($query): void {
                $query->whereNull('subscriptions.ends_at')->orWhere('subscriptions.ends_at', '>', now());
            })
            ->orderByDesc('subscriptions.starts_at')
            ->first(['subscriptions.id', 'subscriptions.status', 'subscriptions.ends_at', 'plans.id as plan_id', 'plans.seat_limit']);
        if (! $subscription) {
            return $this->denied('subscription_inactive', (int) $organization->id);
        }

        $owner = User::query()->whereKey($organization->owner_user_id)
            ->first(['id', 'status', 'email_verified_at']);
        if (! $owner || $owner->status !== 'active' || ! $owner->email_verified_at) {
            return $this->denied('subscription_owner_inactive', (int) $organization->id, (int) $subscription->id);
        }

        if ($subscription->seat_limit !== null) {
            $activeSeats = DB::table('product_memberships')->where('organization_id', $organization->id)
                ->where('status', 'active')->count();
            if ($activeSeats > (int) $subscription->seat_limit) {
                return $this->denied('subscription_seat_limit_exceeded', (int) $organization->id, (int) $subscription->id);
            }
        }

        $entitlements = DB::table('product_entitlements')->where('plan_id', $subscription->plan_id)
            ->whereIn('feature_key', array_unique(['access', $feature]))
            ->where('enabled', true)->pluck('feature_key')->all();
        if (count($entitlements) !== count(array_unique(['access', $feature]))) {
            return $this->denied('feature_not_entitled', (int) $organization->id, (int) $subscription->id);
        }

        return [
            'allowed' => true,
            'reason' => 'authorized',
            'organization_id' => (int) $organization->id,
            'subscription_id' => (int) $subscription->id,
        ];
    }

    /**
     * @return array{allowed: false, reason: string, organization_id: ?int, subscription_id: ?int}
     */
    private function denied(string $reason, ?int $organizationId = null, ?int $subscriptionId = null): array
    {
        return [
            'allowed' => false,
            'reason' => $reason,
            'organization_id' => $organizationId,
            'subscription_id' => $subscriptionId,
        ];
    }
}
