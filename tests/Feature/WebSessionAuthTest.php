<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tests\TestCase;

class WebSessionAuthTest extends TestCase
{
    use RefreshDatabase;

    public function test_verified_user_can_sign_in_and_sign_out_through_a_web_session(): void
    {
        $user = User::factory()->create([
            'email' => 'web-user@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        $this->get('/login')->assertOk()->assertSee('Sign in');

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
        ])->assertRedirect('/');

        $this->assertAuthenticatedAs($user, 'web');

        $this->post('/logout')->assertRedirect('/login');
        $this->assertGuest('web');
        $this->assertDatabaseHas('security_events', [
            'user_id' => $user->id,
            'event_type' => 'auth.web_logout',
            'result' => 'success',
        ]);
    }

    public function test_mfa_enabled_user_must_complete_totp_before_web_authentication(): void
    {
        $user = User::factory()->create([
            'email' => 'web-mfa@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $secret = app('pragmarx.google2fa')->generateSecretKey();
        $this->createTotpMethod($user, $secret);

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
        ])->assertOk()->assertSee('Authenticator or recovery code');

        $this->assertGuest('web');

        $code = app('pragmarx.google2fa')->getCurrentOtp($secret);
        $this->post('/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
            'code' => $code,
        ])->assertRedirect('/');

        $this->assertAuthenticatedAs($user, 'web');
        $this->assertDatabaseHas('security_events', [
            'user_id' => $user->id,
            'event_type' => 'auth.web_mfa_challenge',
            'result' => 'success',
        ]);
    }

    public function test_recovery_code_can_be_used_once_for_web_session_authentication(): void
    {
        $user = User::factory()->create([
            'email' => 'web-recovery@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $secret = app('pragmarx.google2fa')->generateSecretKey();
        $methodId = $this->createTotpMethod($user, $secret);
        $recoveryCode = 'WEB-RECOVERY-CODE';
        DB::table('mfa_recovery_codes')->insert([
            'mfa_method_id' => $methodId,
            'code_hash' => Hash::make($recoveryCode),
            'used_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
        ])->assertOk();
        $this->post('/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
            'code' => $recoveryCode,
        ])->assertRedirect('/');
        $this->assertAuthenticatedAs($user, 'web');
        $this->assertNotNull(DB::table('mfa_recovery_codes')->value('used_at'));

        $this->post('/logout');
        $this->post('/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
        ])->assertOk();
        $this->post('/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
            'code' => $recoveryCode,
        ])->assertUnprocessable();
        $this->assertGuest('web');
    }

    public function test_active_lockout_is_rejected_before_web_password_verification(): void
    {
        $user = User::factory()->create([
            'email' => 'web-locked@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
            'failed_login_attempts' => 5,
            'locked_until' => now()->addMinutes(10),
        ]);

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
        ])->assertStatus(423);

        $this->assertEqualsWithDelta(
            now()->addMinutes(10)->timestamp,
            $user->fresh()->locked_until->timestamp,
            2
        );
        $this->assertGuest('web');
    }

    public function test_expired_lockout_allows_a_valid_web_login_and_resets_attempts(): void
    {
        $user = User::factory()->create([
            'email' => 'web-expired-lock@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
            'failed_login_attempts' => 5,
            'locked_until' => now()->subSecond(),
        ]);

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
        ])->assertRedirect('/');

        $this->assertSame(0, $user->fresh()->failed_login_attempts);
        $this->assertNull($user->fresh()->locked_until);
        $this->assertAuthenticatedAs($user, 'web');
    }

    private function createTotpMethod(User $user, string $secret): int
    {
        return DB::table('mfa_methods')->insertGetId([
            'public_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'type' => 'totp',
            'label' => 'Test authenticator',
            'secret_encrypted' => Crypt::encryptString($secret),
            'destination' => null,
            'is_primary' => true,
            'verified_at' => now(),
            'last_used_at' => null,
            'disabled_at' => null,
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
}
