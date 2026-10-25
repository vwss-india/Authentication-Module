<?php

namespace Tests\Feature;

use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tests\TestCase;

class AccountSecurityWebTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();

        $clientId = (string) Str::uuid();
        DB::table('oauth_clients')->insert([
            'id' => $clientId, 'owner_type' => null, 'owner_id' => null, 'name' => 'Test Personal Access Client',
            'secret' => Hash::make(Str::random(40)), 'provider' => 'users', 'redirect_uris' => '[]',
            'grant_types' => '["personal_access"]', 'revoked' => false, 'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('oauth_personal_access_clients')->insert([
            'client_id' => $clientId, 'created_at' => now(), 'updated_at' => now(),
        ]);
    }

    public function test_authenticated_user_can_reach_security_settings_and_mfa_actions_use_the_web_session(): void
    {
        $user = $this->activeUser();
        $this->actingAs($user);

        $this->get('/account/security/settings')->assertOk()
            ->assertSee('Authenticator app')->assertSee('Passkeys')->assertSee('Connected applications');
        $this->getJson('/account/security/actions/mfa/status')->assertOk()
            ->assertJson(['totp_enabled' => false, 'unused_recovery_codes' => 0]);
        $this->postJson('/account/security/actions/mfa/setup')->assertOk()
            ->assertJsonStructure(['secret', 'provisioning_uri']);
    }

    public function test_passkey_one_time_api_token_is_converted_to_a_regenerated_browser_session_and_revoked(): void
    {
        $user = $this->activeUser();
        $token = $user->createToken('VisionWeb Browser Session');

        $this->withToken($token->accessToken)->postJson(route('login.passkey.session'))
            ->assertOk()->assertJson(['message' => 'Passkey sign-in complete.']);

        $this->assertAuthenticatedAs($user, 'web');
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $token->token->id, 'revoked' => true]);
        $this->assertDatabaseHas('security_events', ['user_id' => $user->id, 'event_type' => 'auth.web_passkey_login']);
    }

    public function test_passkey_browser_session_exchange_rejects_other_token_names(): void
    {
        $user = $this->activeUser();
        $token = $user->createToken('Ordinary API Token');

        $this->withToken($token->accessToken)->postJson(route('login.passkey.session'))->assertUnauthorized();
        $this->assertGuest('web');
    }

    public function test_profile_and_password_updates_are_validated_and_audited(): void
    {
        $user = $this->activeUser();

        $this->actingAs($user)->post('/account/profile', [
            'name' => 'Updated Name', 'username' => 'updated_user', 'phone' => '+15551234567',
        ])->assertRedirect();
        $this->assertDatabaseHas('users', ['id' => $user->id, 'name' => 'Updated Name', 'phone_verified_at' => null]);
        $this->assertDatabaseHas('audit_logs', ['action' => 'account.profile.updated']);

        $this->post('/account/password', [
            'current_password' => 'wrong-password',
            'password' => 'A-strong-new-password-2030',
            'password_confirmation' => 'A-strong-new-password-2030',
        ])->assertSessionHasErrors('current_password');
        $this->post('/account/password', [
            'current_password' => 'password',
            'password' => 'A-strong-new-password-2030',
            'password_confirmation' => 'A-strong-new-password-2030',
        ])->assertRedirect();
        $this->assertTrue(Hash::check('A-strong-new-password-2030', $user->fresh()->password));
        $this->assertDatabaseHas('audit_logs', ['action' => 'auth.password_changed']);
    }

    public function test_session_management_uses_an_opaque_reference_and_revokes_only_owners_other_session(): void
    {
        config(['session.driver' => 'database']);
        $user = $this->activeUser();
        $other = $this->activeUser('another@example.test');
        $this->actingAs($user);
        $currentSessionId = session()->getId();
        $otherSessionId = 'opaque-other-session-id';
        DB::table('sessions')->insert([
            'id' => $otherSessionId, 'user_id' => $user->id, 'ip_address' => '192.0.2.5',
            'user_agent' => 'Browser Test', 'payload' => base64_encode('session'), 'last_activity' => now()->timestamp,
        ]);
        DB::table('sessions')->insert([
            'id' => 'other-user-session', 'user_id' => $other->id, 'ip_address' => '192.0.2.6',
            'user_agent' => 'Other Browser', 'payload' => base64_encode('session'), 'last_activity' => now()->timestamp,
        ]);
        $reference = hash_hmac('sha256', $otherSessionId, (string) config('app.key'));

        $this->get('/account/security/settings')->assertOk()->assertSee($reference)->assertDontSee($otherSessionId);
        $this->delete(route('security.sessions.revoke', $reference))->assertRedirect();
        $this->assertDatabaseMissing('sessions', ['id' => $otherSessionId]);
        $this->assertDatabaseHas('sessions', ['id' => 'other-user-session', 'user_id' => $other->id]);
        $this->assertNotSame('', $currentSessionId);
    }

    public function test_connected_application_revocation_is_scoped_to_the_current_user(): void
    {
        $user = $this->activeUser();
        $other = $this->activeUser('other-grant@example.test');
        $clientId = (string) Str::uuid();
        DB::table('oauth_clients')->insert([
            'id' => $clientId, 'owner_type' => null, 'owner_id' => null, 'name' => 'VisionWeb Test Client',
            'secret' => null, 'provider' => null, 'redirect_uris' => '[]', 'grant_types' => '[]',
            'revoked' => false, 'created_at' => now(), 'updated_at' => now(),
        ]);
        foreach ([$user, $other] as $owner) {
            $tokenId = Str::random(80);
            DB::table('oauth_access_tokens')->insert([
                'id' => $tokenId, 'user_id' => $owner->id, 'client_id' => $clientId,
                'name' => 'test', 'scopes' => '[]', 'revoked' => false,
                'created_at' => now(), 'updated_at' => now(), 'expires_at' => now()->addDay(),
            ]);
            DB::table('oauth_refresh_tokens')->insert([
                'id' => Str::random(80), 'access_token_id' => $tokenId, 'revoked' => false, 'expires_at' => now()->addDay(),
            ]);
        }

        $this->actingAs($user)->delete(route('security.apps.revoke', $clientId))->assertRedirect();
        $this->assertDatabaseHas('oauth_access_tokens', ['user_id' => $user->id, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_access_tokens', ['user_id' => $other->id, 'revoked' => false]);
        $this->assertTrue(AuditLog::verifyChain()['valid']);
    }

    private function activeUser(string $email = 'account-security@example.test'): User
    {
        return User::factory()->create([
            'email' => $email,
            'password' => 'password',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
    }
}
