<?php

namespace Tests\Feature;

use App\Models\AuditLog;
use App\Models\CentralAdmin;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use Tests\TestCase;

class AdminAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
    }

    public function test_admin_browser_and_api_routes_reject_guests(): void
    {
        $this->get('/admin')->assertRedirect('/login');
        $this->getJson('/api/admin/v1/users')->assertUnauthorized();
    }

    public function test_normal_user_cannot_access_admin_browser_or_api_routes(): void
    {
        $user = $this->activeUser();

        $this->actingAs($user)->get('/admin')->assertForbidden();
        Passport::actingAs($user);
        $this->getJson('/api/admin/v1/users')->assertForbidden();
        $this->getJson('/api/admin/v1/oauth-clients')->assertForbidden();
        $this->assertDatabaseMissing('central_admins', ['user_id' => $user->id]);
    }

    public function test_only_an_active_grant_can_open_admin_routes(): void
    {
        $admin = $this->activeUser('admin@example.test');
        $this->grantAdmin($admin);

        $this->actingAs($admin)->get('/admin')->assertOk()->assertSee('Master Admin');
        Passport::actingAs($admin);
        $this->getJson('/api/admin/v1/users')->assertOk()->assertJsonStructure(['data']);

        DB::table('central_admins')->where('user_id', $admin->id)->update(['revoked_at' => now()]);
        $this->getJson('/api/admin/v1/users')->assertForbidden();
    }

    public function test_admin_permission_grants_restrict_browser_and_api_actions_independently(): void
    {
        $admin = $this->activeUser('limited-admin@example.test');
        CentralAdmin::query()->create([
            'user_id' => $admin->id,
            'grant_reason' => 'Restricted security investigator access',
            'permissions' => ['security.read'],
        ]);

        $this->actingAs($admin)->get('/admin/security/events')->assertOk();
        $this->get('/admin/users')->assertForbidden();
        Passport::actingAs($admin);
        $this->getJson('/api/admin/v1/users')->assertForbidden();
        $this->getJson('/api/admin/v1/security/events')->assertOk();
        $this->assertDatabaseHas('security_events', [
            'user_id' => $admin->id,
            'event_type' => 'admin.permission',
            'result' => 'blocked',
        ]);
    }

    public function test_console_bootstrap_grants_admin_and_records_audit_without_passwords(): void
    {
        $user = $this->activeUser('bootstrapped@example.test');

        $result = Artisan::call('auth:admin:grant', [
            'email' => $user->email,
            '--reason' => 'Initial deployment administrator',
            '--permissions' => '*',
            '--allow-wildcard' => true,
            '--force' => true,
        ]);

        $this->assertSame(0, $result);
        $this->assertDatabaseHas('central_admins', ['user_id' => $user->id, 'revoked_at' => null]);
        $this->assertDatabaseHas('audit_logs', ['action' => 'admin.privilege.granted']);
        $this->assertDatabaseHas('security_events', [
            'user_id' => $user->id,
            'event_type' => 'admin.privilege.granted',
            'result' => 'success',
        ]);
        $this->assertStringNotContainsString($user->password, (string) DB::table('audit_logs')->value('details'));
    }

    public function test_console_grant_requires_a_valid_reason_permission_and_explicit_wildcard_flag(): void
    {
        $user = $this->activeUser('validated-grant@example.test');

        $arguments = [
            'email' => $user->email,
            '--reason' => 'Approved operator grant',
            '--permissions' => '*',
            '--force' => true,
        ];
        $this->assertSame(1, Artisan::call('auth:admin:grant', $arguments));
        $this->assertDatabaseMissing('central_admins', ['user_id' => $user->id]);

        $this->assertSame(1, Artisan::call('auth:admin:grant', [
            ...$arguments, '--permissions' => 'users.read', '--reason' => 'No',
        ]));
        $this->assertSame(1, Artisan::call('auth:admin:grant', [
            ...$arguments, '--permissions' => 'unknown.permission',
        ]));

        $this->assertSame(0, Artisan::call('auth:admin:grant', [
            ...$arguments, '--permissions' => 'users.read,security.read',
        ]));
        $this->assertDatabaseHas('central_admins', [
            'user_id' => $user->id,
            'permissions' => json_encode(['users.read', 'security.read']),
        ]);
    }

    public function test_console_refuses_to_revoke_the_last_active_admin_and_audits_revocation(): void
    {
        $firstAdmin = $this->activeUser('first-admin@example.test');
        $secondAdmin = $this->activeUser('second-admin@example.test');
        $this->grantAdmin($firstAdmin);

        $arguments = [
            'email' => $firstAdmin->email,
            '--reason' => 'Operator rotation',
            '--force' => true,
        ];
        $this->assertSame(1, Artisan::call('auth:admin:revoke', $arguments));
        $this->assertDatabaseHas('central_admins', ['user_id' => $firstAdmin->id, 'revoked_at' => null]);

        $this->grantAdmin($secondAdmin);
        $this->assertSame(0, Artisan::call('auth:admin:revoke', $arguments));
        $this->assertDatabaseHas('central_admins', ['user_id' => $firstAdmin->id]);
        $this->assertNotNull(DB::table('central_admins')->where('user_id', $firstAdmin->id)->value('revoked_at'));
        $this->assertDatabaseHas('audit_logs', ['action' => 'admin.privilege.revoked']);
    }

    public function test_admin_can_search_accounts_and_suspend_them_with_audited_session_revocation(): void
    {
        $admin = $this->activeUser('operator@example.test');
        $user = $this->activeUser('subject@example.test');
        $this->grantAdmin($admin);
        DB::table('sessions')->insert([
            'id' => 'subject-session', 'user_id' => $user->id, 'ip_address' => '127.0.0.1',
            'user_agent' => 'test', 'payload' => base64_encode('session'), 'last_activity' => now()->timestamp,
        ]);
        DB::table('trusted_devices')->insert([
            'public_id' => (string) Str::uuid(), 'user_id' => $user->id, 'name' => 'test device',
            'token_hash' => Hash::make('opaque-token'), 'ip_address' => '127.0.0.1', 'user_agent' => 'test',
            'last_used_at' => now(), 'expires_at' => now()->addDay(), 'revoked_at' => null,
            'created_at' => now(), 'updated_at' => now(),
        ]);

        $this->actingAs($admin)->get('/admin/users?q=subject%40example.test')
            ->assertOk()->assertSee('subject@example.test')->assertDontSee('operator@example.test');
        $this->actingAs($admin)->post(route('admin.users.status', $user), [
            'status' => 'suspended', 'reason' => 'Confirmed account compromise', 'confirmed' => '1',
        ])->assertRedirect(route('admin.users.show', $user));

        $this->assertDatabaseHas('users', ['id' => $user->id, 'status' => 'suspended']);
        $this->assertDatabaseMissing('sessions', ['id' => 'subject-session']);
        $this->assertNotNull(DB::table('trusted_devices')->where('user_id', $user->id)->value('revoked_at'));
        $this->assertDatabaseHas('security_events', ['user_id' => $user->id, 'event_type' => 'admin.user.status_changed']);
        $this->assertSame(true, AuditLog::verifyChain()['valid']);
    }

    public function test_admin_cannot_change_own_status_or_manage_another_admin_from_user_controls(): void
    {
        $admin = $this->activeUser('admin-one@example.test');
        $otherAdmin = $this->activeUser('admin-two@example.test');
        $this->grantAdmin($admin);
        $this->grantAdmin($otherAdmin);

        $this->actingAs($admin)->post(route('admin.users.status', $admin), [
            'status' => 'disabled', 'reason' => 'self action attempt', 'confirmed' => '1',
        ])->assertUnprocessable();
        $this->post(route('admin.users.status', $otherAdmin), [
            'status' => 'disabled', 'reason' => 'admin action attempt', 'confirmed' => '1',
        ])->assertUnprocessable();
    }

    public function test_admin_can_review_and_revoke_oauth_clients_without_exposing_secrets(): void
    {
        $admin = $this->activeUser('oauth-admin@example.test');
        $this->grantAdmin($admin);
        $clientId = (string) Str::uuid();
        DB::table('oauth_clients')->insert([
            'id' => $clientId, 'owner_type' => null, 'owner_id' => null, 'name' => 'Local Relying Party',
            'secret' => 'hashed-secret-value', 'provider' => null, 'redirect_uris' => '["https://client.test/callback"]',
            'grant_types' => '["authorization_code"]', 'revoked' => false, 'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('oidc_client_metadata')->insert([
            'oauth_client_id' => $clientId, 'client_type' => 'confidential', 'application_type' => 'web',
            'subject_type' => 'pairwise', 'allowed_scopes' => '["openid","profile"]',
            'post_logout_redirect_uris' => '[]', 'allowed_origins' => '[]', 'require_pkce' => true,
            'require_consent' => true, 'enabled' => true, 'created_at' => now(), 'updated_at' => now(),
        ]);
        $tokenId = Str::random(80);
        DB::table('oauth_access_tokens')->insert([
            'id' => $tokenId, 'user_id' => $admin->id, 'client_id' => $clientId, 'name' => 'Test',
            'scopes' => '[]', 'revoked' => false, 'created_at' => now(), 'updated_at' => now(), 'expires_at' => now()->addDay(),
        ]);
        DB::table('oauth_refresh_tokens')->insert([
            'id' => Str::random(80), 'access_token_id' => $tokenId, 'revoked' => false, 'expires_at' => now()->addDay(),
        ]);
        DB::table('oidc_access_tokens')->insert([
            'user_id' => $admin->id, 'oauth_client_id' => $clientId, 'token_hash' => hash('sha256', 'opaque-oidc-token'),
            'scopes' => '["openid"]', 'expires_at' => now()->addDay(), 'revoked_at' => null,
            'created_at' => now(), 'updated_at' => now(),
        ]);

        $this->actingAs($admin)->get(route('admin.clients'))->assertOk()
            ->assertSee('Local Relying Party')->assertDontSee('hashed-secret-value');
        $this->post(route('admin.clients.revoke', $clientId), [
            'reason' => 'Client configuration compromise', 'confirmed' => '1',
        ])->assertRedirect();

        $this->assertDatabaseHas('oauth_clients', ['id' => $clientId, 'revoked' => true]);
        $this->assertDatabaseHas('oidc_client_metadata', ['oauth_client_id' => $clientId, 'enabled' => false]);
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $tokenId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_refresh_tokens', ['access_token_id' => $tokenId, 'revoked' => true]);
        $this->assertNotNull(DB::table('oidc_access_tokens')->value('revoked_at'));
        $this->assertDatabaseHas('audit_logs', ['action' => 'admin.oauth_client.revoked']);
    }

    private function activeUser(string $email = 'ordinary@example.test'): User
    {
        return User::factory()->create([
            'email' => $email,
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
    }

    private function grantAdmin(User $user): void
    {
        CentralAdmin::query()->create([
            'user_id' => $user->id,
            'grant_reason' => 'Test provisioning',
            'permissions' => ['*'],
        ]);
    }
}
