<?php

namespace Tests\Feature;

use App\Models\User;
use App\Notifications\AuthPasswordResetNotification;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Tests\TestCase;

class PasswordRecoveryTest extends TestCase
{
    use RefreshDatabase;

    public function test_unknown_email_receives_generic_response_without_notification(): void
    {
        Notification::fake();

        $response = $this->postJson(
            '/api/v1/auth/forgot-password',
            ['email' => 'unknown@example.com']
        );

        $response
            ->assertStatus(202)
            ->assertExactJson([
                'message' => 'If an eligible account exists, password reset instructions will be sent.',
            ]);

        Notification::assertNothingSent();
    }

    public function test_active_account_receives_password_reset_notification(): void
    {
        Notification::fake();

        $user = User::factory()->create([
            'email' => 'active@example.com',
            'status' => 'active',
        ]);

        $response = $this->postJson(
            '/api/v1/auth/forgot-password',
            ['email' => $user->email]
        );

        $response
            ->assertStatus(202)
            ->assertExactJson([
                'message' => 'If an eligible account exists, password reset instructions will be sent.',
            ]);

        Notification::assertSentTo(
            $user,
            AuthPasswordResetNotification::class
        );

        $this->assertDatabaseHas('password_reset_tokens', [
            'email' => $user->email,
        ]);
    }

    public function test_inactive_account_does_not_receive_password_reset_notification(): void
    {
        Notification::fake();

        $user = User::factory()->create([
            'email' => 'inactive@example.com',
            'status' => 'inactive',
        ]);

        $response = $this->postJson(
            '/api/v1/auth/forgot-password',
            ['email' => $user->email]
        );

        $response
            ->assertStatus(202)
            ->assertExactJson([
                'message' => 'If an eligible account exists, password reset instructions will be sent.',
            ]);

        Notification::assertNothingSent();

        $this->assertDatabaseMissing('password_reset_tokens', [
            'email' => $user->email,
        ]);
    }

    public function test_valid_reset_token_changes_password_and_records_security_event(): void
    {
        $user = User::factory()->create([
            'email' => 'reset@example.com',
            'status' => 'active',
            'password' => 'Old-password-before-reset-2026',
        ]);

        $token = $this->requestResetToken($user);
        $newPassword = 'New-strong-password-2026';

        $response = $this->submitPasswordReset(
            $user,
            $token,
            $newPassword
        );

        $response
            ->assertOk()
            ->assertExactJson([
                'message' => 'Password reset successfully. Please sign in again.',
            ]);

        $user->refresh();

        $this->assertTrue(Hash::check($newPassword, $user->password));

        $this->assertFalse(
            Hash::check('Old-password-before-reset-2026', $user->password)
        );

        $this->assertNotNull($user->password_changed_at);

        $this->assertDatabaseHas('security_events', [
            'user_id' => $user->id,
            'event_type' => 'password_reset',
            'result' => 'success',
        ]);

        $this->assertDatabaseMissing('password_reset_tokens', [
            'email' => $user->email,
        ]);
    }

    public function test_invalid_reset_token_is_rejected(): void
    {
        $user = User::factory()->create([
            'email' => 'invalid-token@example.com',
            'status' => 'active',
        ]);

        $this->submitPasswordReset(
            $user,
            'invalid-reset-token',
            'New-strong-password-2026'
        )
            ->assertStatus(422)
            ->assertJson([
                'message' => 'The password reset token is invalid or expired.',
            ]);
    }

    public function test_expired_reset_token_is_rejected(): void
    {
        $user = User::factory()->create([
            'email' => 'expired-token@example.com',
            'status' => 'active',
        ]);

        $token = $this->requestResetToken($user);

        // The configured password reset expiry is 60 minutes.
        $this->travel(61)->minutes();

        $this->submitPasswordReset(
            $user,
            $token,
            'New-strong-password-2026'
        )
            ->assertStatus(422)
            ->assertJson([
                'message' => 'The password reset token is invalid or expired.',
            ]);
    }

    public function test_reset_token_cannot_be_used_twice(): void
    {
        $user = User::factory()->create([
            'email' => 'single-use@example.com',
            'status' => 'active',
        ]);

        Notification::fake();

        $token = $this->requestResetToken($user);

        $this->submitPasswordReset(
            $user,
            $token,
            'First-new-password-2026'
        )->assertOk();

        $this->submitPasswordReset(
            $user,
            $token,
            'Second-new-password-2026'
        )
            ->assertStatus(422)
            ->assertJson([
                'message' => 'The password reset token is invalid or expired.',
            ]);

        $user->refresh();

        $this->assertTrue(
            Hash::check('First-new-password-2026', $user->password)
        );

        $eventContext = DB::table('security_events')
            ->where('user_id', $user->id)
            ->where('event_type', 'password_reset')
            ->where('result', 'success')
            ->value('context');
        $this->assertSame(['method' => 'email_token'], json_decode($eventContext, true));
        $this->assertDatabaseHas('audit_logs', ['action' => 'auth.password_reset.success']);
    }

    public function test_inactive_account_cannot_reset_password_with_valid_token(): void
    {
        $oldPassword = 'Old-password-before-reset-2026';

        $user = User::factory()->create([
            'email' => 'inactive-reset@example.com',
            'status' => 'inactive',
            'password' => $oldPassword,
        ]);

        $token = Password::broker('users')
            ->createToken($user);

        $this->submitPasswordReset(
            $user,
            $token,
            'New-strong-password-2026'
        )
            ->assertStatus(422)
            ->assertJsonValidationErrors(['email']);

        $user->refresh();

        $this->assertTrue(
            Hash::check($oldPassword, $user->password)
        );

        $this->assertDatabaseMissing('security_events', [
            'user_id' => $user->id,
            'event_type' => 'password_reset',
            'result' => 'success',
        ]);
    }

    public function test_password_reset_invalidates_database_sessions(): void
    {
        $user = User::factory()->create([
            'email' => 'sessions-reset@example.com',
            'status' => 'active',
        ]);

        $sessionId = Str::random(40);

        DB::table('sessions')->insert([
            'id' => $sessionId,
            'user_id' => $user->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'PasswordRecoveryTest',
            'payload' => base64_encode('test-session'),
            'last_activity' => now()->timestamp,
        ]);

        Notification::fake();

        $token = $this->requestResetToken($user);

        $this->submitPasswordReset(
            $user,
            $token,
            'New-strong-password-2026'
        )->assertOk();

        $this->assertDatabaseMissing('sessions', [
            'id' => $sessionId,
        ]);
    }

    public function test_password_reset_revokes_trusted_devices(): void
    {
        $user = User::factory()->create([
            'email' => 'trusted-device-reset@example.com',
            'status' => 'active',
        ]);

        DB::table('trusted_devices')->insert([
            'public_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'name' => 'Previously trusted browser',
            'token_hash' => hash('sha256', 'trusted-device-secret'),
            'ip_address' => '127.0.0.1',
            'user_agent' => 'PasswordRecoveryTest',
            'last_used_at' => now(),
            'expires_at' => now()->addDays(30),
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $token = $this->requestResetToken($user);

        $this->submitPasswordReset(
            $user,
            $token,
            'New-strong-password-2026'
        )->assertOk();

        $this->assertNotNull(
            DB::table('trusted_devices')
                ->where('user_id', $user->id)
                ->value('revoked_at')
        );
    }

    public function test_password_reset_invalidates_pending_mfa_login_challenges(): void
    {
        $user = User::factory()->create([
            'email' => 'pending-mfa-reset@example.com',
            'status' => 'active',
        ]);
        $secret = 'JBSWY3DPEHPK3PXP';
        $challengeToken = bin2hex(random_bytes(32));

        $methodId = DB::table('mfa_methods')->insertGetId([
            'public_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'type' => 'totp',
            'label' => 'Authenticator app',
            'secret_encrypted' => Crypt::encryptString($secret),
            'verified_at' => now(),
            'last_used_at' => null,
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $challengeId = DB::table('verification_challenges')->insertGetId([
            'user_id' => $user->id,
            'channel' => 'totp',
            'purpose' => 'login_mfa',
            'destination' => $user->email,
            'token_hash' => hash('sha256', $challengeToken),
            'attempts' => 0,
            'expires_at' => now()->addMinutes(5),
            'consumed_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $token = $this->requestResetToken($user);

        $this->submitPasswordReset(
            $user,
            $token,
            'New-strong-password-2026'
        )->assertOk();

        $this->assertNotNull(
            DB::table('verification_challenges')
                ->where('id', $challengeId)
                ->value('consumed_at')
        );

        $this->postJson('/api/v1/auth/login/2fa', [
            'challenge_token' => $challengeToken,
            'code' => app('pragmarx.google2fa')->getCurrentOtp($secret),
        ])->assertUnprocessable();

        $this->assertDatabaseMissing('oauth_access_tokens', [
            'user_id' => $user->id,
        ]);
    }

    public function test_password_reset_revokes_access_and_refresh_tokens(): void
    {
        $user = User::factory()->create([
            'email' => 'oauth-reset@example.com',
            'status' => 'active',
        ]);

        $clientId = (string) Str::uuid();
        $accessTokenId = str_repeat('a', 80);
        $refreshTokenId = str_repeat('r', 80);

        DB::table('oauth_clients')->insert([
            'id' => $clientId,
            'owner_type' => null,
            'owner_id' => null,
            'name' => 'PasswordRecoveryTestClient',
            'secret' => null,
            'provider' => null,
            'redirect_uris' => '[]',
            'grant_types' => '[]',
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('oauth_access_tokens')->insert([
            'id' => $accessTokenId,
            'user_id' => $user->id,
            'client_id' => $clientId,
            'name' => 'test-access-token',
            'scopes' => '[]',
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
            'expires_at' => now()->addHour(),
        ]);

        DB::table('oauth_refresh_tokens')->insert([
            'id' => $refreshTokenId,
            'access_token_id' => $accessTokenId,
            'revoked' => false,
            'expires_at' => now()->addDays(30),
        ]);

        Notification::fake();

        $token = $this->requestResetToken($user);

        $this->submitPasswordReset(
            $user,
            $token,
            'New-strong-password-2026'
        )->assertOk();

        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $accessTokenId,
            'revoked' => true,
        ]);

        $this->assertDatabaseHas('oauth_refresh_tokens', [
            'id' => $refreshTokenId,
            'revoked' => true,
        ]);
    }

    public function test_reset_request_requires_a_valid_email(): void
    {
        $this->postJson(
            '/api/v1/auth/forgot-password',
            ['email' => 'not-an-email']
        )
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['email']);
    }

    public function test_reset_requires_matching_strong_password_confirmation(): void
    {
        $user = User::factory()->create([
            'email' => 'validation@example.com',
            'status' => 'active',
        ]);

        $this->submitPasswordReset(
            $user,
            'some-token',
            'New-strong-password-2026',
            'different-password'
        )
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['password']);
    }

    public function test_sixth_forgot_password_request_from_one_ip_is_rate_limited(): void
    {
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->postJson('/api/v1/auth/forgot-password', [
                'email' => 'unknown-throttled@example.com',
            ])->assertStatus(202);
        }

        $this->postJson('/api/v1/auth/forgot-password', [
            'email' => 'unknown-throttled@example.com',
        ])->assertTooManyRequests();
    }

    public function test_sixth_password_reset_request_from_one_ip_is_rate_limited(): void
    {
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->postJson('/api/v1/auth/reset-password', [
                'email' => 'unknown-throttled@example.com',
                'token' => 'invalid-reset-token',
                'password' => 'Strong-password-after-reset-2026',
                'password_confirmation' => 'Strong-password-after-reset-2026',
            ])->assertUnprocessable();
        }

        $this->postJson('/api/v1/auth/reset-password', [
            'email' => 'unknown-throttled@example.com',
            'token' => 'invalid-reset-token',
            'password' => 'Strong-password-after-reset-2026',
            'password_confirmation' => 'Strong-password-after-reset-2026',
        ])->assertTooManyRequests();
    }

    private function requestResetToken(User $user): string
    {
        return Password::broker('users')
            ->createToken($user);
    }

    private function submitPasswordReset(
        User $user,
        string $token,
        string $password,
        ?string $confirmation = null
    ) {
        return $this->postJson(
            '/api/v1/auth/reset-password',
            [
                'email' => $user->email,
                'token' => $token,
                'password' => $password,
                'password_confirmation' => $confirmation ?? $password,
            ]
        );
    }
}
