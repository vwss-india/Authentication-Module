<?php

namespace App\Http\Controllers;

use App\Models\AuditLog;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\Response;

class ProductAccessController extends Controller
{
    public function manageMembers(Request $request, string $organizationPublicId): View
    {
        $organization = DB::table('product_organizations')->where('public_id', $organizationPublicId)
            ->where('owner_user_id', $request->user()->id)->firstOrFail();
        $members = DB::table('product_memberships as memberships')
            ->join('users', 'users.id', '=', 'memberships.user_id')
            ->join('product_roles as roles', 'roles.id', '=', 'memberships.product_role_id')
            ->where('memberships.organization_id', $organization->id)
            ->select(['users.public_id', 'users.name', 'users.email', 'users.status as account_status', 'users.email_verified_at',
                'memberships.status as membership_status', 'roles.id as role_id', 'roles.name as role_name'])
            ->orderBy('users.name')->paginate(25)->withQueryString();
        $roles = DB::table('product_roles')->where('organization_id', $organization->id)->orderBy('name')->get(['id', 'name']);

        return view('products.members', compact('organization', 'members', 'roles'));
    }

    public function assignMember(Request $request, string $organizationPublicId): Response
    {
        $data = $request->validate([
            'email' => ['required', 'email:rfc', 'max:254'],
            'product_role_id' => ['required', 'integer', 'min:1'],
        ]);
        $actor = $request->user();

        DB::transaction(function () use ($organizationPublicId, $data, $actor, $request): void {
            $organization = DB::table('product_organizations')->where('public_id', $organizationPublicId)
                ->where('owner_user_id', $actor->id)->lockForUpdate()->firstOrFail();
            abort_unless($organization->status === 'active', 403, 'This organization is not active.');
            $staff = DB::table('users')->whereRaw('LOWER(email) = ?', [mb_strtolower($data['email'])])
                ->where('status', 'active')->whereNotNull('email_verified_at')->first();
            abort_unless($staff, 422, 'Choose an existing active account with a verified email address.');
            abort_if((int) $staff->id === (int) $actor->id, 422, 'The organization owner already manages this organization.');
            $role = DB::table('product_roles')->where('id', $data['product_role_id'])
                ->where('organization_id', $organization->id)->first();
            abort_unless($role, 422, 'Choose a role belonging to this organization.');

            $subscription = DB::table('product_subscriptions as subscriptions')
                ->join('product_plans as plans', 'plans.id', '=', 'subscriptions.plan_id')
                ->where('subscriptions.organization_id', $organization->id)
                ->where('plans.product_id', $organization->product_id)->where('plans.status', 'active')
                ->whereIn('subscriptions.status', ['active', 'trialing'])->where('subscriptions.starts_at', '<=', now())
                ->where(fn ($query) => $query->whereNull('subscriptions.ends_at')->orWhere('subscriptions.ends_at', '>', now()))
                ->orderByDesc('subscriptions.starts_at')->lockForUpdate()
                ->first(['subscriptions.id', 'plans.seat_limit']);
            abort_unless($subscription, 422, 'An active subscription is required before assigning product members.');

            $membership = DB::table('product_memberships')->where('organization_id', $organization->id)
                ->where('user_id', $staff->id)->lockForUpdate()->first();
            $seatCount = DB::table('product_memberships')->where('organization_id', $organization->id)
                ->where('status', 'active')->count();
            if ((! $membership || $membership->status !== 'active') && $subscription->seat_limit !== null) {
                abort_if($seatCount >= (int) $subscription->seat_limit, 422, 'The current plan seat limit has been reached.');
            }

            $values = [
                'product_role_id' => $role->id, 'invited_by_user_id' => $actor->id,
                'status' => 'active', 'joined_at' => now(), 'updated_at' => now(),
            ];
            if ($membership) {
                DB::table('product_memberships')->where('id', $membership->id)->update($values);
            } else {
                DB::table('product_memberships')->insert([
                    'organization_id' => $organization->id, 'user_id' => $staff->id,
                    ...$values, 'created_at' => now(),
                ]);
            }

            AuditLog::recordEntry($request, $actor, 'product.membership.assigned', [
                'organization_public_id' => $organizationPublicId, 'member_public_id' => $staff->public_id,
                'role' => $role->name, 'subscription_id' => $subscription->id,
            ]);
        });

        return back()->with('status', 'Product membership assigned using the organization subscription.');
    }

    public function revokeMember(Request $request, string $organizationPublicId, string $memberPublicId): Response
    {
        abort_unless(Str::isUuid($organizationPublicId) && Str::isUuid($memberPublicId), 404);
        $organization = DB::table('product_organizations')->where('public_id', $organizationPublicId)
            ->where('owner_user_id', $request->user()->id)->firstOrFail();
        $member = DB::table('product_memberships as memberships')->join('users', 'users.id', '=', 'memberships.user_id')
            ->where('memberships.organization_id', $organization->id)->where('users.public_id', $memberPublicId)
            ->where('users.id', '<>', $request->user()->id)->first(['memberships.id', 'users.public_id']);
        abort_unless($member, 404);

        DB::transaction(function () use ($request, $organizationPublicId, $member): void {
            DB::table('product_memberships')->where('id', $member->id)->update(['status' => 'suspended', 'updated_at' => now()]);
            AuditLog::recordEntry($request, $request->user(), 'product.membership.revoked', [
                'organization_public_id' => $organizationPublicId, 'member_public_id' => $member->public_id,
            ]);
        });

        return back()->with('status', 'Product membership suspended.');
    }

    public function index(Request $request): View
    {
        $memberships = DB::table('product_memberships as memberships')
            ->join('product_organizations as organizations', 'organizations.id', '=', 'memberships.organization_id')
            ->join('products', 'products.id', '=', 'organizations.product_id')
            ->join('product_roles as roles', 'roles.id', '=', 'memberships.product_role_id')
            ->where('memberships.user_id', $request->user()->id)
            ->select([
                'memberships.organization_id', 'memberships.status as membership_status',
                'organizations.public_id as organization_public_id', 'organizations.name as organization_name',
                'organizations.status as organization_status', 'organizations.owner_user_id', 'products.slug as product_slug',
                'products.id as product_id', 'products.name as product_name', 'products.status as product_status', 'roles.name as role_name',
            ])->orderBy('products.name')->paginate(20)->withQueryString();

        $organizationIds = $memberships->getCollection()->pluck('organization_id')->all();
        $subscriptions = DB::table('product_subscriptions as subscriptions')
            ->join('product_plans as plans', 'plans.id', '=', 'subscriptions.plan_id')
            ->whereIn('subscriptions.organization_id', $organizationIds)
            ->orderByDesc('subscriptions.starts_at')
            ->get([
                'subscriptions.*', 'plans.name as plan_name', 'plans.seat_limit',
                'plans.product_id as plan_product_id',
            ])->groupBy('organization_id')->map(fn ($rows) => $rows->first());
        $planIds = $subscriptions->pluck('plan_id')->unique()->values()->all();
        $entitlements = DB::table('product_entitlements')->whereIn('plan_id', $planIds)
            ->where('enabled', true)->orderBy('feature_key')->get(['plan_id', 'feature_key', 'usage_limit'])
            ->groupBy('plan_id');

        $memberships->getCollection()->transform(function (object $membership) use ($subscriptions, $entitlements): object {
            $subscription = $subscriptions->get($membership->organization_id);
            $membership->subscription = $subscription;
            $membership->features = $subscription ? ($entitlements->get($subscription->plan_id) ?? collect()) : collect();
            $membership->subscription_is_current = $subscription
                && (int) $subscription->plan_product_id === (int) $membership->product_id
                && in_array($subscription->status, ['active', 'trialing'], true)
                && Carbon::parse($subscription->starts_at)->lessThanOrEqualTo(now())
                && (! $subscription->ends_at || Carbon::parse($subscription->ends_at)->isFuture());

            return $membership;
        });

        $ownedOrganizations = DB::table('product_organizations as organizations')
            ->join('products', 'products.id', '=', 'organizations.product_id')
            ->where('organizations.owner_user_id', $request->user()->id)
            ->select(['organizations.public_id', 'organizations.name as organization_name', 'organizations.status', 'products.name as product_name'])
            ->orderBy('products.name')->paginate(20, ['*'], 'owned_page')->withQueryString();

        return view('products.index', compact('memberships', 'ownedOrganizations'));
    }

    public function adminCatalog(): View
    {
        $products = DB::table('products')->orderBy('name')->paginate(25, ['*'], 'products_page');
        $subscriptions = DB::table('product_subscriptions as subscriptions')
            ->join('product_organizations as organizations', 'organizations.id', '=', 'subscriptions.organization_id')
            ->join('products', 'products.id', '=', 'organizations.product_id')
            ->join('product_plans as plans', 'plans.id', '=', 'subscriptions.plan_id')
            ->leftJoin('users as owners', 'owners.id', '=', 'organizations.owner_user_id')
            ->select([
                'subscriptions.id', 'subscriptions.status', 'subscriptions.starts_at', 'subscriptions.renews_at',
                'subscriptions.ends_at', 'products.name as product_name', 'plans.name as plan_name',
                'organizations.name as organization_name', 'owners.email as owner_email',
            ])->orderByDesc('subscriptions.starts_at')->paginate(50, ['*'], 'subscriptions_page');

        return view('admin.products', compact('products', 'subscriptions'));
    }
}
