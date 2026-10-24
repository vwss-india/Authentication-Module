<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use Tests\TestCase;

class MfaFlowTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        $clientId = (string) Str::uuid();

        DB::table('oauth_clients')->insert([
            'id' => $clientId,
            'owner_type' => null,
            'owner_id' => null,
            'name' => 'MfaFlowTest Personal Access Client',
            'secret' => Hash::make(Str::random(40)),
            'provider' => 'users',
            'redirect_uris' => json_encode([]),
            'grant_types' => json_encode(['personal_access']),
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('oauth_personal_access_clients')->insert([
            'client_id' => $clientId,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    public function test_password_login_returns_mfa_challenge_for_enabled_account(): void
    {
        $user = $this->activeUser();
        $this->enableTotpForTest($user, 'JBSWY3DPEHPK3PXP');

        $response = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'CorrectPassword123!',
        ]);

        $response->assertStatus(202)
            ->assertJsonPath('mfa_required', true)
            ->assertJsonStructure(['challenge_token', 'expires_in'])
            ->assertJsonMissingPath('access_token');

        $this->assertDatabaseHas('verification_challenges', [
            'user_id' => $user->id,
            'purpose' => 'login_mfa',
            'channel' => 'totp',
        ]);
    }

    public function test_mfa_completion_does_not_authenticate_an_inactive_account(): void
    {
        $user = $this->activeUser();
        $secret = 'JBSWY3DPEHPK3PXP';
        $this->enableTotpForTest($user, $secret);

        $login = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'CorrectPassword123!',
        ]);

        $login->assertStatus(202);
        DB::table('users')->where('id', $user->id)->update(['status' => 'inactive']);

        $this->postJson('/api/v1/auth/login/2fa', [
            'challenge_token' => $login->json('challenge_token'),
            'code' => app('pragmarx.google2fa')->getCurrentOtp($secret),
        ])->assertForbidden()->assertJsonMissingPath('access_token');

        $this->assertDatabaseMissing('oauth_access_tokens', [
            'user_id' => $user->id,
        ]);
    }

    public function test_mfa_attempt_limit_applies_across_login_challenges(): void
    {
        $user = $this->activeUser();
        $secret = 'JBSWY3DPEHPK3PXP';
        $this->enableTotpForTest($user, $secret);

        $firstLogin = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'CorrectPassword123!',
        ]);
        $secondLogin = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'CorrectPassword123!',
        ]);

        $firstLogin->assertStatus(202);
        $secondLogin->assertStatus(202);

        $invalidCode = '000000';
        $google2fa = app('pragmarx.google2fa');

        while ($google2fa->verifyKey($secret, $invalidCode, 1)) {
            $invalidCode = str_pad(
                (string) (((int) $invalidCode + 1) % 1_000_000),
                6,
                '0',
                STR_PAD_LEFT
            );
        }

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.10'])
                ->postJson('/api/v1/auth/login/2fa', [
                    'challenge_token' => $firstLogin->json('challenge_token'),
                    'code' => $invalidCode,
                ])
                ->assertUnprocessable();
        }

        $user->refresh();

        $this->assertSame(5, $user->failed_login_attempts);
        $this->assertNotNull($user->locked_until);
        $this->assertTrue($user->locked_until->isFuture());

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.11'])
            ->postJson('/api/v1/auth/login/2fa', [
                'challenge_token' => $secondLogin->json('challenge_token'),
                'code' => $google2fa->getCurrentOtp($secret),
            ])
            ->assertStatus(423)
            ->assertJsonMissingPath('access_token');

        $this->assertDatabaseMissing('oauth_access_tokens', [
            'user_id' => $user->id,
        ]);
    }

    public function test_trusted_device_login_updates_its_ip_and_returns_a_token(): void
    {
        $user = $this->activeUser();
        $this->enableTotpForTest($user, 'JBSWY3DPEHPK3PXP');
        $trustedDeviceToken = bin2hex(random_bytes(32));

        $deviceId = DB::table('trusted_devices')->insertGetId([
            'public_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'name' => 'Trusted browser',
            'token_hash' => hash('sha256', $trustedDeviceToken),
            'ip_address' => '192.0.2.1',
            'user_agent' => 'MfaFlowTest',
            'last_used_at' => now()->subDay(),
            'expires_at' => now()->addDays(30),
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'CorrectPassword123!',
            'trusted_device_token' => $trustedDeviceToken,
        ]);

        $response->assertOk()->assertJsonStructure(['access_token']);

        $this->assertNotNull(
            DB::table('trusted_devices')->where('id', $deviceId)->value('last_used_at')
        );
        $this->assertSame(
            '127.0.0.1',
            DB::table('trusted_devices')->where('id', $deviceId)->value('ip_address')
        );
    }

    public function test_totp_setup_confirmation_generates_hashed_recovery_codes(): void
    {
        $user = $this->activeUser();
        Passport::actingAs($user);

        $setup = $this->postJson('/api/v1/auth/mfa/totp/setup');

        $setup->assertOk()
            ->assertJsonStructure(['secret', 'provisioning_uri']);

        $secret = $setup->json('secret');
        $code = app('pragmarx.google2fa')->getCurrentOtp($secret);

        $confirm = $this->postJson('/api/v1/auth/mfa/totp/confirm', [
            'code' => $code,
        ]);

        $confirm->assertOk()
            ->assertJsonCount(10, 'recovery_codes');

        $method = DB::table('mfa_methods')
            ->where('user_id', $user->id)
            ->where('type', 'totp')
            ->whereNotNull('verified_at')
            ->whereNull('revoked_at')
            ->first();

        $this->assertNotNull($method);
        $this->assertNotEmpty($method->public_id);

        $this->assertSame(
            10,
            DB::table('mfa_recovery_codes')
                ->where('mfa_method_id', $method->id)
                ->whereNull('used_at')
                ->count()
        );

        $storedHash = DB::table('mfa_recovery_codes')
            ->where('mfa_method_id', $method->id)
            ->value('code_hash');

        $this->assertNotSame(
            $confirm->json('recovery_codes.0'),
            $storedHash
        );

        $this->assertTrue(
            Hash::check($confirm->json('recovery_codes.0'), $storedHash)
        );
    }

    public function test_totp_setup_rejects_an_invalid_confirmation_code(): void
    {
        $user = $this->activeUser();
        Passport::actingAs($user);

        $setup = $this->postJson('/api/v1/auth/mfa/totp/setup')->assertOk();
        $secret = $setup->json('secret');
        $invalidCode = '000000';
        $google2fa = app('pragmarx.google2fa');

        while ($google2fa->verifyKey($secret, $invalidCode, 1)) {
            $invalidCode = str_pad(
                (string) (((int) $invalidCode + 1) % 1_000_000),
                6,
                '0',
                STR_PAD_LEFT
            );
        }

        $this->postJson('/api/v1/auth/mfa/totp/confirm', [
            'code' => $invalidCode,
        ])->assertUnprocessable();

        $this->assertDatabaseHas('mfa_methods', [
            'user_id' => $user->id,
            'type' => 'totp',
            'verified_at' => null,
            'revoked_at' => null,
        ]);
        $this->assertDatabaseMissing('mfa_recovery_codes', [
            'mfa_method_id' => DB::table('mfa_methods')
                ->where('user_id', $user->id)
                ->value('id'),
        ]);
    }

    public function test_totp_disable_requires_authentication(): void
    {
        $this->postJson('/api/v1/auth/mfa/totp/disable', [
            'password' => 'CorrectPassword123!',
            'code' => '123456',
        ])->assertUnauthorized();
    }

    public function test_totp_disable_rejects_an_invalid_code_without_disabling_mfa(): void
    {
        $user = $this->activeUser();
        $secret = 'JBSWY3DPEHPK3PXP';
        $this->enableTotpForTest($user, $secret);
        Passport::actingAs($user);

        $invalidCode = '000000';
        $google2fa = app('pragmarx.google2fa');

        while ($google2fa->verifyKey($secret, $invalidCode, 1)) {
            $invalidCode = str_pad(
                (string) (((int) $invalidCode + 1) % 1_000_000),
                6,
                '0',
                STR_PAD_LEFT
            );
        }

        $this->postJson('/api/v1/auth/mfa/totp/disable', [
            'password' => 'CorrectPassword123!',
            'code' => $invalidCode,
        ])->assertUnprocessable();

        $this->assertNotNull(DB::table('mfa_methods')
            ->where('user_id', $user->id)
            ->where('type', 'totp')
            ->value('verified_at'));
        $this->assertNull(DB::table('mfa_methods')
            ->where('user_id', $user->id)
            ->where('type', 'totp')
            ->value('revoked_at'));

        $eventContext = DB::table('security_events')
            ->where('user_id', $user->id)
            ->where('event_type', 'auth.mfa.disable_failed')
            ->value('context');
        $this->assertSame([], json_decode($eventContext, true));
        $this->assertDatabaseHas('audit_logs', ['action' => 'auth.mfa.disable_failed.rejected']);
    }

    public function test_recovery_code_regeneration_invalidates_old_codes_and_new_codes_are_single_use(): void
    {
        $user = $this->activeUser();
        $secret = 'JBSWY3DPEHPK3PXP';
        $this->enableTotpForTest($user, $secret);
        Passport::actingAs($user);

        $method = DB::table('mfa_methods')
            ->where('user_id', $user->id)
            ->where('type', 'totp')
            ->first();
        $oldRecoveryCode = 'OLD1CODE2TEST';

        $oldRecoveryHash = Hash::make($oldRecoveryCode);

        DB::table('mfa_recovery_codes')->insert([
            'mfa_method_id' => $method->id,
            'code_hash' => $oldRecoveryHash,
            'used_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $regenerated = $this->postJson('/api/v1/auth/mfa/recovery-codes/regenerate', [
            'password' => 'CorrectPassword123!',
            'code' => app('pragmarx.google2fa')->getCurrentOtp($secret),
        ])->assertOk()->assertJsonCount(10, 'recovery_codes');

        $newRecoveryCode = $regenerated->json('recovery_codes.0');
        $this->assertDatabaseMissing('mfa_recovery_codes', [
            'mfa_method_id' => $method->id,
            'code_hash' => $oldRecoveryHash,
        ]);
        $this->assertSame(
            10,
            DB::table('mfa_recovery_codes')
                ->where('mfa_method_id', $method->id)
                ->whereNull('used_at')
                ->count()
        );

        $login = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'CorrectPassword123!',
        ])->assertStatus(202);
        $challengeToken = $login->json('challenge_token');

        $this->postJson('/api/v1/auth/login/2fa', [
            'challenge_token' => $challengeToken,
            'code' => $oldRecoveryCode,
        ])->assertUnprocessable();

        $this->postJson('/api/v1/auth/login/2fa', [
            'challenge_token' => $challengeToken,
            'code' => $newRecoveryCode,
        ])->assertOk();

        $this->postJson('/api/v1/auth/login/2fa', [
            'challenge_token' => $challengeToken,
            'code' => $newRecoveryCode,
        ])->assertUnprocessable();
    }

    public function test_recovery_code_can_complete_mfa_login_only_once(): void
    {
        $user = $this->activeUser();
        $this->enableTotpForTest($user, 'JBSWY3DPEHPK3PXP');

        $method = DB::table('mfa_methods')
            ->where('user_id', $user->id)
            ->where('type', 'totp')
            ->whereNotNull('verified_at')
            ->whereNull('revoked_at')
            ->first();

        $this->assertNotNull($method);

        $recoveryCode = 'A1B2C3D4E5F6';

        DB::table('mfa_recovery_codes')->insert([
            'mfa_method_id' => $method->id,
            'code_hash' => Hash::make($recoveryCode),
            'used_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $login = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'CorrectPassword123!',
        ]);

        $login->assertStatus(202);
        $challengeToken = $login->json('challenge_token');

        $complete = $this->postJson('/api/v1/auth/login/2fa', [
            'challenge_token' => $challengeToken,
            'code' => $recoveryCode,
            'trust_device' => true,
            'device_name' => 'MFA test browser',
        ]);

        $complete->assertOk()
            ->assertJsonStructure(['access_token', 'trusted_device_token']);

        $this->assertSame(
            1,
            DB::table('mfa_recovery_codes')
                ->where('mfa_method_id', $method->id)
                ->whereNotNull('used_at')
                ->count()
        );

        $this->assertDatabaseHas('trusted_devices', [
            'user_id' => $user->id,
            'revoked_at' => null,
        ]);

        $reuse = $this->postJson('/api/v1/auth/login/2fa', [
            'challenge_token' => $challengeToken,
            'code' => $recoveryCode,
        ]);

        $reuse->assertStatus(422);
    }

    public function test_revoked_trusted_device_no_longer_bypasses_mfa(): void
    {
        $user = $this->activeUser();
        $this->enableTotpForTest($user, 'JBSWY3DPEHPK3PXP');
        $trustedDeviceToken = bin2hex(random_bytes(32));

        $deviceId = DB::table('trusted_devices')->insertGetId([
            'public_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'name' => 'Revoked browser',
            'token_hash' => hash('sha256', $trustedDeviceToken),
            'ip_address' => '192.0.2.1',
            'user_agent' => 'MfaFlowTest',
            'last_used_at' => now(),
            'expires_at' => now()->addDays(30),
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        Passport::actingAs($user);

        $this->deleteJson('/api/v1/auth/trusted-devices/'.$deviceId)
            ->assertOk();

        $this->assertNotNull(DB::table('trusted_devices')
            ->where('id', $deviceId)
            ->where('user_id', $user->id)
            ->value('revoked_at'));

        Auth::forgetGuards();

        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'CorrectPassword123!',
            'trusted_device_token' => $trustedDeviceToken,
        ])->assertStatus(202)->assertJsonPath('mfa_required', true);
    }

    public function test_user_cannot_revoke_another_users_trusted_device(): void
    {
        $requestingUser = $this->activeUser();
        $deviceOwner = $this->activeUser();
        $deviceId = DB::table('trusted_devices')->insertGetId([
            'public_id' => (string) Str::uuid(),
            'user_id' => $deviceOwner->id,
            'name' => 'Another account browser',
            'token_hash' => hash('sha256', bin2hex(random_bytes(32))),
            'ip_address' => '192.0.2.20',
            'user_agent' => 'MfaFlowTest',
            'last_used_at' => now(),
            'expires_at' => now()->addDays(30),
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        Passport::actingAs($requestingUser);

        $this->deleteJson('/api/v1/auth/trusted-devices/'.$deviceId)
            ->assertNotFound();

        $this->assertDatabaseHas('trusted_devices', [
            'id' => $deviceId,
            'user_id' => $deviceOwner->id,
            'revoked_at' => null,
        ]);
        $this->assertDatabaseMissing('security_events', [
            'user_id' => $requestingUser->id,
            'event_type' => 'auth.trusted_device.revoked',
        ]);
    }

    public function test_expired_trusted_device_is_hidden_and_cannot_bypass_mfa(): void
    {
        $user = $this->activeUser();
        $this->enableTotpForTest($user, 'JBSWY3DPEHPK3PXP');
        $trustedDeviceToken = bin2hex(random_bytes(32));

        DB::table('trusted_devices')->insert([
            'public_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'name' => 'Expired browser',
            'token_hash' => hash('sha256', $trustedDeviceToken),
            'ip_address' => '192.0.2.1',
            'user_agent' => 'MfaFlowTest',
            'last_used_at' => now()->subDays(31),
            'expires_at' => now()->subSecond(),
            'revoked_at' => null,
            'created_at' => now()->subDays(31),
            'updated_at' => now()->subDays(31),
        ]);

        Passport::actingAs($user);

        $this->getJson('/api/v1/auth/trusted-devices')
            ->assertOk()
            ->assertJsonCount(0, 'devices');

        Auth::forgetGuards();

        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'CorrectPassword123!',
            'trusted_device_token' => $trustedDeviceToken,
        ])->assertStatus(202)->assertJsonPath('mfa_required', true);
    }

    private function activeUser(): User
    {
        $user = User::factory()->create();

        $user->forceFill([
            'password' => 'CorrectPassword123!',
            'status' => 'active',
            'email_verified_at' => now(),
            'failed_login_attempts' => 0,
            'locked_until' => null,
        ])->save();

        return $user->fresh();
    }

    private function enableTotpForTest(User $user, string $secret): void
    {
        DB::table('mfa_methods')->insert([
            'public_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'type' => 'totp',
            'label' => 'Test authenticator',
            'secret_encrypted' => Crypt::encryptString($secret),
            'verified_at' => now(),
            'last_used_at' => null,
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
}
