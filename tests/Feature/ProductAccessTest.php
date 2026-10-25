<?php

namespace Tests\Feature;

use App\Models\User;
use App\Services\ProductAccessService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use Tests\TestCase;

class ProductAccessTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
    }

    public function test_owner_subscription_authorizes_assigned_staff_without_a_separate_staff_subscription(): void
    {
        $fixture = $this->fixture();
        $service = app(ProductAccessService::class);

        $this->assertTrue($service->decide($fixture['owner'], 'sample', $fixture['organization_public_id'], 'invoices', 'invoice.read')['allowed']);
        $decision = $service->decide($fixture['staff'], 'sample', $fixture['organization_public_id'], 'invoices', 'invoice.read');
        $this->assertTrue($decision['allowed']);
        $this->assertSame($fixture['subscription_id'], $decision['subscription_id']);
        $this->assertDatabaseCount('product_subscriptions', 1);
    }

    public function test_membership_permission_subscription_entitlement_and_tenant_must_all_allow_access(): void
    {
        $fixture = $this->fixture();
        $service = app(ProductAccessService::class);

        DB::table('product_subscriptions')->where('id', $fixture['subscription_id'])->update([
            'status' => 'expired', 'ends_at' => now()->subMinute(),
        ]);
        $this->assertSame('subscription_inactive', $service->decide($fixture['staff'], 'sample', $fixture['organization_public_id'], 'invoices', 'invoice.read')['reason']);

        DB::table('product_subscriptions')->where('id', $fixture['subscription_id'])->update([
            'status' => 'active', 'ends_at' => now()->addDay(),
        ]);
        DB::table('product_entitlements')->where('plan_id', $fixture['plan_id'])->where('feature_key', 'invoices')->delete();
        $this->assertSame('feature_not_entitled', $service->decide($fixture['staff'], 'sample', $fixture['organization_public_id'], 'invoices', 'invoice.read')['reason']);

        DB::table('product_entitlements')->insert([
            'plan_id' => $fixture['plan_id'], 'feature_key' => 'invoices', 'enabled' => true,
            'usage_limit' => null, 'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('product_memberships')->where('id', $fixture['staff_membership_id'])->update(['status' => 'suspended']);
        $this->assertSame('membership_or_permission_denied', $service->decide($fixture['staff'], 'sample', $fixture['organization_public_id'], 'invoices', 'invoice.read')['reason']);

        DB::table('product_memberships')->where('id', $fixture['staff_membership_id'])->update(['status' => 'active']);
        DB::table('product_role_permissions')->where('product_role_id', $fixture['staff_role_id'])->delete();
        $this->assertSame('membership_or_permission_denied', $service->decide($fixture['staff'], 'sample', $fixture['organization_public_id'], 'invoices', 'invoice.read')['reason']);
        $this->assertSame('product_or_organization_unavailable', $service->decide($fixture['staff'], 'other-product', $fixture['organization_public_id'], 'invoices', 'invoice.read')['reason']);
        $this->assertSame('product_or_organization_unavailable', $service->decide($fixture['staff'], 'sample', (string) Str::uuid(), 'invoices', 'invoice.read')['reason']);
    }

    public function test_inactive_identity_or_subscription_owner_cannot_authorize_members(): void
    {
        $fixture = $this->fixture();
        $fixture['staff']->forceFill(['status' => 'suspended'])->save();
        $service = app(ProductAccessService::class);
        $this->assertSame('identity_inactive', $service->decide($fixture['staff'], 'sample', $fixture['organization_public_id'], 'invoices', 'invoice.read')['reason']);

        $fixture['staff']->forceFill(['status' => 'active'])->save();
        $fixture['owner']->forceFill(['status' => 'disabled'])->save();
        $this->assertSame('subscription_owner_inactive', $service->decide($fixture['staff'], 'sample', $fixture['organization_public_id'], 'invoices', 'invoice.read')['reason']);
    }

    public function test_seat_limit_applies_to_owner_and_assigned_staff_under_one_subscription(): void
    {
        $fixture = $this->fixture(seats: 2);
        $extra = $this->activeUser('third-staff@example.test');
        DB::table('product_memberships')->insert([
            'organization_id' => $fixture['organization_id'], 'user_id' => $extra->id,
            'product_role_id' => $fixture['staff_role_id'], 'invited_by_user_id' => $fixture['owner']->id,
            'status' => 'active', 'joined_at' => now(), 'created_at' => now(), 'updated_at' => now(),
        ]);

        $decision = app(ProductAccessService::class)->decide($fixture['staff'], 'sample', $fixture['organization_public_id'], 'invoices', 'invoice.read');
        $this->assertSame('subscription_seat_limit_exceeded', $decision['reason']);
    }

    public function test_product_access_middleware_allows_valid_members_and_records_denied_decisions(): void
    {
        $fixture = $this->fixture();
        Route::get('/_product-gate/{organization}', fn () => response()->json(['allowed' => true]))
            ->middleware(['auth:api', 'active.account', 'product.access:sample,invoice.read,invoices']);

        Passport::actingAs($fixture['staff']);
        $this->getJson('/_product-gate/'.$fixture['organization_public_id'])->assertOk()->assertJson(['allowed' => true]);
        DB::table('product_subscriptions')->where('id', $fixture['subscription_id'])->update(['status' => 'suspended']);
        $this->getJson('/_product-gate/'.$fixture['organization_public_id'])->assertForbidden();
        $this->assertDatabaseHas('security_events', [
            'user_id' => $fixture['staff']->id, 'event_type' => 'product.access', 'result' => 'blocked',
        ]);
    }

    public function test_user_product_overview_shows_only_persisted_membership_data(): void
    {
        $fixture = $this->fixture();
        $this->actingAs($fixture['staff'])->get('/account/products')->assertOk()
            ->assertSee('Sample Product')->assertSee('Sample Organization')->assertSee('invoices');
        $other = $this->activeUser('unrelated@example.test');
        $this->actingAs($other)->get('/account/products')->assertOk()->assertSee('No product memberships');
    }

    public function test_owner_can_assign_and_suspend_existing_staff_using_the_organization_subscription(): void
    {
        $fixture = $this->fixture(seats: 3);
        $newStaff = $this->activeUser('new-staff@example.test');
        $owner = $fixture['owner'];
        $assignUrl = route('products.members.assign', $fixture['organization_public_id']);

        $this->actingAs($owner)->get(route('products.members', $fixture['organization_public_id']))
            ->assertOk()->assertSee('Assign an existing account')->assertSee('assigned-staff@example.test');
        $this->post($assignUrl, ['email' => $newStaff->email, 'product_role_id' => $fixture['staff_role_id']])
            ->assertRedirect();
        $membershipId = DB::table('product_memberships')->where('user_id', $newStaff->id)->value('id');
        $this->assertNotNull($membershipId);
        $this->assertDatabaseCount('product_subscriptions', 1);
        $this->assertDatabaseHas('audit_logs', ['action' => 'product.membership.assigned']);

        $owner->forceFill(['status' => 'active'])->save();
        $this->delete(route('products.members.revoke', [$fixture['organization_public_id'], $newStaff->public_id]))
            ->assertRedirect();
        $this->assertDatabaseHas('product_memberships', ['id' => $membershipId, 'status' => 'suspended']);

        $outsider = $this->activeUser('organization-outsider@example.test');
        $this->actingAs($outsider)->get(route('products.members', $fixture['organization_public_id']))->assertNotFound();
    }

    public function test_owner_assignment_enforces_seat_limit_and_verified_account_requirement(): void
    {
        $fixture = $this->fixture(seats: 2);
        $unverifiedStaff = User::factory()->create(['email' => 'unverified-staff@example.test', 'status' => 'active', 'email_verified_at' => null]);
        $url = route('products.members.assign', $fixture['organization_public_id']);

        $this->actingAs($fixture['owner'])->post($url, [
            'email' => $unverifiedStaff->email, 'product_role_id' => $fixture['staff_role_id'],
        ])->assertUnprocessable();
        $thirdStaff = $this->activeUser('third-staff-assign@example.test');
        $this->post($url, ['email' => $thirdStaff->email, 'product_role_id' => $fixture['staff_role_id']])->assertUnprocessable();
        $this->assertDatabaseMissing('product_memberships', ['user_id' => $thirdStaff->id]);
    }

    /** @return array<string, mixed> */
    private function fixture(?int $seats = 5): array
    {
        $owner = $this->activeUser('product-owner@example.test');
        $staff = $this->activeUser('assigned-staff@example.test');
        $now = now();
        $productId = DB::table('products')->insertGetId([
            'slug' => 'sample', 'name' => 'Sample Product', 'status' => 'active', 'created_at' => $now, 'updated_at' => $now,
        ]);
        $planId = DB::table('product_plans')->insertGetId([
            'product_id' => $productId, 'slug' => 'team', 'name' => 'Team Plan', 'status' => 'active',
            'seat_limit' => $seats, 'billing_interval' => 'monthly', 'created_at' => $now, 'updated_at' => $now,
        ]);
        $organizationPublicId = (string) Str::uuid();
        $organizationId = DB::table('product_organizations')->insertGetId([
            'public_id' => $organizationPublicId, 'product_id' => $productId, 'owner_user_id' => $owner->id,
            'name' => 'Sample Organization', 'status' => 'active', 'created_at' => $now, 'updated_at' => $now,
        ]);
        $ownerRoleId = DB::table('product_roles')->insertGetId([
            'organization_id' => $organizationId, 'role_key' => 'sample.owner', 'name' => 'Owner',
            'created_at' => $now, 'updated_at' => $now,
        ]);
        $staffRoleId = DB::table('product_roles')->insertGetId([
            'organization_id' => $organizationId, 'role_key' => 'sample.cashier', 'name' => 'Cashier',
            'created_at' => $now, 'updated_at' => $now,
        ]);
        DB::table('product_role_permissions')->insert([
            ['product_role_id' => $ownerRoleId, 'permission_key' => 'invoice.read', 'created_at' => $now, 'updated_at' => $now],
            ['product_role_id' => $staffRoleId, 'permission_key' => 'invoice.read', 'created_at' => $now, 'updated_at' => $now],
        ]);
        DB::table('product_memberships')->insert([
            ['organization_id' => $organizationId, 'user_id' => $owner->id, 'product_role_id' => $ownerRoleId, 'invited_by_user_id' => null, 'status' => 'active', 'joined_at' => $now, 'created_at' => $now, 'updated_at' => $now],
            ['organization_id' => $organizationId, 'user_id' => $staff->id, 'product_role_id' => $staffRoleId, 'invited_by_user_id' => $owner->id, 'status' => 'active', 'joined_at' => $now, 'created_at' => $now, 'updated_at' => $now],
        ]);
        $subscriptionId = DB::table('product_subscriptions')->insertGetId([
            'organization_id' => $organizationId, 'plan_id' => $planId, 'status' => 'active',
            'starts_at' => $now->copy()->subDay(), 'renews_at' => $now->copy()->addDays(29),
            'ends_at' => $now->copy()->addDays(30), 'canceled_at' => null,
            'provider' => null, 'provider_subscription_id' => null, 'created_at' => $now, 'updated_at' => $now,
        ]);
        DB::table('product_entitlements')->insert([
            ['plan_id' => $planId, 'feature_key' => 'access', 'enabled' => true, 'usage_limit' => null, 'created_at' => $now, 'updated_at' => $now],
            ['plan_id' => $planId, 'feature_key' => 'invoices', 'enabled' => true, 'usage_limit' => 1000, 'created_at' => $now, 'updated_at' => $now],
        ]);

        return [
            'owner' => $owner, 'staff' => $staff, 'organization_id' => $organizationId,
            'organization_public_id' => $organizationPublicId, 'staff_role_id' => $staffRoleId,
            'staff_membership_id' => DB::table('product_memberships')->where('user_id', $staff->id)->value('id'),
            'plan_id' => $planId, 'subscription_id' => $subscriptionId,
        ];
    }

    private function activeUser(string $email): User
    {
        return User::factory()->create(['email' => $email, 'status' => 'active', 'email_verified_at' => now()]);
    }
}
