<?php

namespace Tests\Feature;

use App\Models\User;
use App\Notifications\AuthEmailVerificationNotification;
use App\Notifications\AuthPhoneVerificationNotification;
use DateInterval;
use DateTimeInterface;
use Defuse\Crypto\Crypto;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\Passport;
use ReflectionProperty;
use Tests\TestCase;

class AuthApiTest extends TestCase
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
            'name' => 'AuthApiTest Personal Access Client',
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

    public function test_registration_creates_pending_user_and_sends_verification(): void
    {
        Notification::fake();

        $response = $this->postJson('/api/v1/auth/register', [
            'name' => 'Test User',
            'email' => 'new-user@example.com',
            'password' => 'Strong-password-2026',
            'password_confirmation' => 'Strong-password-2026',
        ]);

        $response->assertCreated()
            ->assertJsonPath('user.status', 'pending')
            ->assertJsonMissingPath('user.password');

        $user = User::where('email', 'new-user@example.com')->firstOrFail();

        $this->assertNull($user->email_verified_at);
        $this->assertTrue(Hash::check(
            'Strong-password-2026',
            $user->password
        ));

        $this->assertDatabaseHas('verification_challenges', [
            'user_id' => $user->id,
            'channel' => 'email',
            'purpose' => 'email_verification',
        ]);

        Notification::assertSentTo(
            $user,
            AuthEmailVerificationNotification::class,
            fn (AuthEmailVerificationNotification $notification): bool => $notification->via($user) === ['mail']
        );
    }

    public function test_registration_rejects_duplicate_email(): void
    {
        User::factory()->create([
            'email' => 'existing@example.com',
            'status' => 'pending',
        ]);

        $this->postJson('/api/v1/auth/register', [
            'name' => 'Duplicate User',
            'email' => 'existing@example.com',
            'password' => 'Strong-password-2026',
            'password_confirmation' => 'Strong-password-2026',
        ])->assertUnprocessable();
    }

    public function test_email_verification_activates_user_and_token_cannot_be_reused(): void
    {
        Notification::fake();

        $this->postJson('/api/v1/auth/register', [
            'name' => 'Verify User',
            'email' => 'verify@example.com',
            'password' => 'Strong-password-2026',
            'password_confirmation' => 'Strong-password-2026',
        ])->assertCreated();

        $user = User::where('email', 'verify@example.com')->firstOrFail();
        $token = null;

        Notification::assertSentTo(
            $user,
            AuthEmailVerificationNotification::class,
            function (AuthEmailVerificationNotification $notification) use (&$token): bool {
                $property = new ReflectionProperty(
                    AuthEmailVerificationNotification::class,
                    'token'
                );

                $token = $property->getValue($notification);

                return true;
            }
        );

        $this->assertNotNull($token);

        $this->postJson('/api/v1/auth/email/verify', [
            'email' => $user->email,
            'token' => $token,
        ])->assertOk()
            ->assertJsonPath('user.status', 'active');

        $this->assertNotNull($user->fresh()->email_verified_at);

        $this->postJson('/api/v1/auth/email/verify', [
            'email' => $user->email,
            'token' => $token,
        ])->assertUnprocessable();
    }

    public function test_email_verification_token_expires_after_thirty_minutes(): void
    {
        Notification::fake();

        $this->postJson('/api/v1/auth/register', [
            'name' => 'Expired Verify User',
            'email' => 'expired-verify@example.com',
            'password' => 'Strong-password-2026',
            'password_confirmation' => 'Strong-password-2026',
        ])->assertCreated();

        $user = User::where('email', 'expired-verify@example.com')->firstOrFail();
        $token = Notification::sent($user, AuthEmailVerificationNotification::class)
            ->first()
            ->token;

        $this->travel(31)->minutes();

        $this->postJson('/api/v1/auth/email/verify', [
            'email' => $user->email,
            'token' => $token,
        ])->assertUnprocessable();

        $this->assertNull($user->fresh()->email_verified_at);
        $this->assertSame('pending', $user->fresh()->status);
    }

    public function test_resending_email_verification_invalidates_the_previous_token(): void
    {
        Notification::fake();

        $this->postJson('/api/v1/auth/register', [
            'name' => 'Resend Verify User',
            'email' => 'resend-verify@example.com',
            'password' => 'Strong-password-2026',
            'password_confirmation' => 'Strong-password-2026',
        ])->assertCreated();

        $user = User::where('email', 'resend-verify@example.com')->firstOrFail();
        $firstToken = Notification::sent($user, AuthEmailVerificationNotification::class)
            ->first()
            ->token;

        $this->postJson('/api/v1/auth/email/resend', [
            'email' => $user->email,
        ])->assertStatus(202);

        $tokens = Notification::sent($user, AuthEmailVerificationNotification::class);
        $this->assertCount(2, $tokens);
        $secondToken = $tokens->last()->token;

        $this->assertNotSame($firstToken, $secondToken);

        $this->postJson('/api/v1/auth/email/verify', [
            'email' => $user->email,
            'token' => $firstToken,
        ])->assertUnprocessable();

        $this->postJson('/api/v1/auth/email/verify', [
            'email' => $user->email,
            'token' => $secondToken,
        ])->assertOk()->assertJsonPath('user.status', 'active');
    }

    public function test_five_invalid_email_verification_attempts_consume_the_token(): void
    {
        Notification::fake();

        $this->postJson('/api/v1/auth/register', [
            'name' => 'Attempt Limit User',
            'email' => 'attempt-limit@example.com',
            'password' => 'Strong-password-2026',
            'password_confirmation' => 'Strong-password-2026',
        ])->assertCreated();

        $user = User::where('email', 'attempt-limit@example.com')->firstOrFail();
        $token = Notification::sent($user, AuthEmailVerificationNotification::class)
            ->first()
            ->token;

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->postJson('/api/v1/auth/email/verify', [
                'email' => $user->email,
                'token' => 'incorrect-verification-token',
            ])->assertUnprocessable();
        }

        $this->postJson('/api/v1/auth/email/verify', [
            'email' => $user->email,
            'token' => $token,
        ])->assertUnprocessable();

        $challenge = DB::table('verification_challenges')
            ->where('user_id', $user->id)
            ->where('purpose', 'email_verification')
            ->first();

        $this->assertSame(5, $challenge->attempts);
        $this->assertNotNull($challenge->consumed_at);
        $this->assertNull($user->fresh()->email_verified_at);
    }

    public function test_fourth_verification_resend_request_from_one_ip_is_rate_limited(): void
    {
        $user = User::factory()->create([
            'email' => 'resend-limit@example.com',
            'status' => 'pending',
            'email_verified_at' => null,
        ]);

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $this->postJson('/api/v1/auth/email/resend', [
                'email' => $user->email,
            ])->assertStatus(202);
        }

        $this->postJson('/api/v1/auth/email/resend', [
            'email' => $user->email,
        ])->assertTooManyRequests();

        $this->assertSame(
            3,
            DB::table('verification_challenges')
                ->where('user_id', $user->id)
                ->where('purpose', 'email_verification')
                ->count()
        );
    }

    public function test_pending_user_cannot_sign_in(): void
    {
        $user = User::factory()->create([
            'email' => 'pending@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'pending',
            'email_verified_at' => null,
        ]);

        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
        ])->assertForbidden();
    }

    public function test_phone_verification_code_is_sent_by_email_and_can_only_be_used_once(): void
    {
        Notification::fake();

        $user = User::factory()->create([
            'phone' => '+15551234567',
            'phone_verified_at' => null,
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        Passport::actingAs($user);

        $this->postJson('/api/v1/auth/phone/verify/request')
            ->assertAccepted()
            ->assertJsonMissingPath('code');

        $notification = Notification::sent($user, AuthPhoneVerificationNotification::class)->first();

        $this->assertNotNull($notification);
        $this->assertSame(['mail'], $notification->via($user));
        $this->assertDatabaseHas('verification_challenges', [
            'user_id' => $user->id,
            'channel' => 'email',
            'purpose' => 'phone_verification',
            'destination' => $user->phone,
            'attempts' => 0,
            'consumed_at' => null,
        ]);

        $this->postJson('/api/v1/auth/phone/verify', ['code' => $notification->code])
            ->assertOk()
            ->assertJsonPath('user.phone', $user->phone)
            ->assertJsonStructure(['user' => ['phone_verified_at']]);

        $this->assertNotNull($user->fresh()->phone_verified_at);
        $this->assertDatabaseMissing('verification_challenges', [
            'user_id' => $user->id,
            'purpose' => 'phone_verification',
            'consumed_at' => null,
        ]);

        $this->postJson('/api/v1/auth/phone/verify', ['code' => $notification->code])
            ->assertUnprocessable();
    }

    public function test_passport_device_authorization_displays_a_user_code_form(): void
    {
        $this->get('/oauth/device')
            ->assertOk()
            ->assertSee('Authorize a device')
            ->assertSee('name="user_code"', false)
            ->assertSee(route('passport.device.authorizations.authorize'), false);
    }

    public function test_passport_authorization_code_request_displays_consent_to_signed_in_user(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $clientId = $this->createOAuthClient(
            'Authorization consent client',
            ['authorization_code', 'refresh_token']
        );
        $codeVerifier = Str::random(64);
        $codeChallenge = rtrim(strtr(
            base64_encode(hash('sha256', $codeVerifier, true)),
            '+/',
            '-_'
        ), '=');

        $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query([
                'client_id' => $clientId,
                'redirect_uri' => 'https://client.example/callback',
                'response_type' => 'code',
                'state' => 'state-value',
                'code_challenge' => $codeChallenge,
                'code_challenge_method' => 'S256',
            ]))
            ->assertOk()
            ->assertSee('Authorize Authorization consent client')
            ->assertSee('Approve')
            ->assertSee('Deny')
            ->assertSee(route('passport.authorizations.approve'), false);
    }

    public function test_passport_authorization_code_with_pkce_exchanges_once_for_tokens(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $clientId = $this->createOAuthClient(
            'Authorization exchange client',
            ['authorization_code', 'refresh_token']
        );
        $codeVerifier = Str::random(64);
        $codeChallenge = rtrim(strtr(
            base64_encode(hash('sha256', $codeVerifier, true)),
            '+/',
            '-_'
        ), '=');

        $authorizationPage = $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query([
                'client_id' => $clientId,
                'redirect_uri' => 'https://client.example/callback',
                'response_type' => 'code',
                'state' => 'state-value',
                'code_challenge' => $codeChallenge,
                'code_challenge_method' => 'S256',
            ]))
            ->assertOk()
            ->assertSee('name="auth_token"', false);
        preg_match('/name="auth_token" value="([^"]+)"/', $authorizationPage->getContent(), $authTokenMatch);

        $approval = $this->post(route('passport.authorizations.approve'), [
            'auth_token' => $authTokenMatch[1] ?? null,
        ]);
        $approval->assertRedirect();
        $redirectQuery = parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY);
        parse_str((string) $redirectQuery, $redirectParameters);

        $this->assertSame('state-value', $redirectParameters['state'] ?? null);
        $authorizationCode = $redirectParameters['code'] ?? null;
        $this->assertIsString($authorizationCode);

        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'redirect_uri' => 'https://client.example/callback',
            'code' => $authorizationCode,
            'code_verifier' => $codeVerifier,
        ])->assertOk()
            ->assertJsonStructure(['access_token', 'expires_in', 'refresh_token', 'token_type']);

        $this->assertNotEmpty($tokenResponse->json('access_token'));
        $this->assertNotEmpty($tokenResponse->json('refresh_token'));

        $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'redirect_uri' => 'https://client.example/callback',
            'code' => $authorizationCode,
            'code_verifier' => $codeVerifier,
        ])->assertBadRequest()
            ->assertJsonPath('error', 'invalid_grant');
    }

    public function test_passport_device_authorization_approves_a_device_and_issues_tokens(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $client = app(ClientRepository::class)
            ->createDeviceAuthorizationGrantClient('Device authorization test client', false);

        $deviceResponse = $this->post('/oauth/device/code', [
            'client_id' => $client->id,
        ])->assertOk()
            ->assertJsonStructure(['device_code', 'user_code', 'verification_uri', 'expires_in', 'interval']);
        $deviceCode = $deviceResponse->json('device_code');
        $userCode = $deviceResponse->json('user_code');

        $authorizationPage = $this->actingAs($user)
            ->get(route('passport.device.authorizations.authorize', ['user_code' => $userCode]))
            ->assertOk()
            ->assertSee('Authorize Device authorization test client')
            ->assertSee('name="auth_token"', false);
        preg_match('/name="auth_token" value="([^"]+)"/', $authorizationPage->getContent(), $authTokenMatch);

        $this->post(route('passport.device.authorizations.approve'), [
            'state' => Str::random(20),
            'client_id' => $client->id,
            'auth_token' => $authTokenMatch[1] ?? null,
        ])->assertRedirect(route('passport.device'));

        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
            'client_id' => $client->id,
            'device_code' => $deviceCode,
        ])->assertOk()
            ->assertJsonStructure(['access_token', 'expires_in', 'refresh_token', 'token_type']);

        $this->assertNotEmpty($tokenResponse->json('access_token'));

        $this->postJson('/oauth/token', [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
            'client_id' => $client->id,
            'device_code' => $deviceCode,
        ])->assertBadRequest()
            ->assertJsonPath('error', 'invalid_grant');
    }

    public function test_phone_verification_resend_invalidates_the_previous_code(): void
    {
        Notification::fake();

        $user = User::factory()->create([
            'phone' => '+15551234567',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        Passport::actingAs($user);

        $this->postJson('/api/v1/auth/phone/verify/request')->assertAccepted();
        $firstCode = Notification::sent($user, AuthPhoneVerificationNotification::class)->first()->code;
        $this->postJson('/api/v1/auth/phone/verify/request')->assertAccepted();
        $secondCode = Notification::sent($user, AuthPhoneVerificationNotification::class)->last()->code;

        $this->assertNotSame($firstCode, $secondCode);
        $this->postJson('/api/v1/auth/phone/verify', ['code' => $firstCode])
            ->assertUnprocessable();
        $this->postJson('/api/v1/auth/phone/verify', ['code' => $secondCode])
            ->assertOk();
    }

    public function test_phone_verification_code_expires_after_configured_period(): void
    {
        Notification::fake();
        config(['auth.phone_verification_expire_minutes' => 10]);

        $user = User::factory()->create([
            'phone' => '+15551234567',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        Passport::actingAs($user);
        $this->postJson('/api/v1/auth/phone/verify/request')->assertAccepted();
        $code = Notification::sent($user, AuthPhoneVerificationNotification::class)->first()->code;

        $this->travel(11)->minutes();

        $this->postJson('/api/v1/auth/phone/verify', ['code' => $code])
            ->assertUnprocessable();
        $this->assertNull($user->fresh()->phone_verified_at);
    }

    public function test_five_invalid_phone_verification_attempts_consume_the_code(): void
    {
        Notification::fake();

        $user = User::factory()->create([
            'phone' => '+15551234567',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        Passport::actingAs($user);
        $this->postJson('/api/v1/auth/phone/verify/request')->assertAccepted();
        $challenge = DB::table('verification_challenges')
            ->where('user_id', $user->id)
            ->where('purpose', 'phone_verification')
            ->first();

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->postJson('/api/v1/auth/phone/verify', ['code' => '000000'])
                ->assertUnprocessable();
        }

        $this->assertDatabaseHas('verification_challenges', [
            'id' => $challenge->id,
            'attempts' => 5,
        ]);
        $this->assertNotNull(DB::table('verification_challenges')->where('id', $challenge->id)->value('consumed_at'));
        $this->assertNull($user->fresh()->phone_verified_at);
    }

    public function test_fifth_failed_login_starts_a_fifteen_minute_lockout(): void
    {
        $user = User::factory()->create([
            'email' => 'lockout@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $response = $this->postJson('/api/v1/auth/login', [
                'email' => $user->email,
                'password' => 'Incorrect-password-2026',
            ]);
        }

        $response->assertUnauthorized();

        $user->refresh();

        $this->assertSame(5, $user->failed_login_attempts);
        $this->assertNotNull($user->locked_until);
        $this->assertTrue($user->locked_until->isFuture());
        $this->assertEqualsWithDelta(
            now()->addMinutes(15)->timestamp,
            $user->locked_until->timestamp,
            2
        );
    }

    public function test_active_lockout_rejects_login_without_extending_it(): void
    {
        $lockedUntil = now()->addMinutes(10)->startOfSecond();

        $user = User::factory()->create([
            'email' => 'already-locked@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
            'failed_login_attempts' => 5,
            'locked_until' => $lockedUntil,
        ]);

        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'Incorrect-password-2026',
        ])->assertStatus(423);

        $user->refresh();

        $this->assertSame(5, $user->failed_login_attempts);
        $this->assertSame($lockedUntil->timestamp, $user->locked_until->timestamp);
        $this->assertDatabaseHas('security_events', [
            'user_id' => $user->id,
            'event_type' => 'auth.login',
            'result' => 'blocked',
        ]);
    }

    public function test_expired_lockout_starts_a_fresh_attempt_window_and_allows_login(): void
    {
        $user = User::factory()->create([
            'email' => 'expired-lockout@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
            'failed_login_attempts' => 5,
            'locked_until' => now()->subSecond(),
        ]);

        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'Incorrect-password-2026',
        ])->assertUnauthorized();

        $user->refresh();

        $this->assertSame(1, $user->failed_login_attempts);
        $this->assertNull($user->locked_until);

        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
        ])->assertOk()->assertJsonStructure(['access_token']);

        $user->refresh();

        $this->assertSame(0, $user->failed_login_attempts);
        $this->assertNull($user->locked_until);
    }

    public function test_valid_login_issues_an_expiring_passport_access_token(): void
    {
        $user = User::factory()->create([
            'email' => 'passport-login@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        $this->assertInstanceOf(OAuthenticatable::class, $user);

        $response = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'Strong-password-2026',
        ])->assertOk()
            ->assertJsonStructure(['access_token', 'expires_at']);

        $accessToken = DB::table('oauth_access_tokens')
            ->where('user_id', $user->id)
            ->first();

        $this->assertNotNull($accessToken);
        $this->assertNotNull($accessToken->expires_at);
        $this->assertTrue(now()->lt($accessToken->expires_at));
        $this->assertNotEmpty($response->json('expires_at'));
    }

    public function test_expired_passport_access_token_is_rejected(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $originalLifetime = Passport::$personalAccessTokensExpireIn;
        $expiredLifetime = new DateInterval('PT1S');
        $expiredLifetime->invert = 1;

        try {
            Passport::personalAccessTokensExpireIn($expiredLifetime);
            $token = $user->createToken('expiring-test-device');
        } finally {
            Passport::$personalAccessTokensExpireIn = $originalLifetime;
        }

        $this->withToken($token->accessToken)
            ->getJson('/api/v1/auth/me')
            ->assertUnauthorized();
    }

    public function test_client_credentials_grant_issues_expiring_token_and_revoked_client_is_rejected(): void
    {
        $clientSecret = Str::random(40);
        $clientId = $this->createOAuthClient(
            'Client credentials test client',
            ['client_credentials'],
            $clientSecret
        );

        $response = $this->post('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ])->assertOk()
            ->assertJsonStructure(['access_token', 'expires_in', 'token_type'])
            ->assertJsonMissingPath('refresh_token');

        $accessToken = DB::table('oauth_access_tokens')
            ->where('client_id', $clientId)
            ->first();

        $this->assertNotNull($accessToken);
        $this->assertNull($accessToken->user_id);
        $this->assertNotNull($accessToken->expires_at);
        $this->assertTrue(now()->lt($accessToken->expires_at));
        $this->assertNotEmpty($response->json('access_token'));

        $this->post('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => Str::random(40),
        ])->assertUnauthorized()
            ->assertJsonPath('error', 'invalid_client');
    }

    public function test_oauth_token_endpoint_rejects_revoked_client_credentials(): void
    {
        $clientSecret = Str::random(40);
        $clientId = $this->createOAuthClient(
            'Revoked client credentials test client',
            ['client_credentials'],
            $clientSecret
        );

        DB::table('oauth_clients')
            ->where('id', $clientId)
            ->update(['revoked' => true]);

        $this->post('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ])->assertUnauthorized()
            ->assertJsonPath('error', 'invalid_client');

        $failureContext = DB::table('security_events')
            ->where('event_type', 'oauth.token')
            ->where('result', 'failure')
            ->value('context');
        $this->assertSame(['grant_type' => 'client_credentials'], json_decode($failureContext, true));
        $auditDetails = DB::table('audit_logs')
            ->where('action', 'oauth.token.failure')
            ->value('details');
        $this->assertStringNotContainsString($clientSecret, $failureContext);
        $this->assertStringNotContainsString($clientSecret, $auditDetails);
        $this->assertDatabaseHas('audit_logs', ['action' => 'oauth.token.failure']);
    }

    public function test_password_grant_is_not_enabled_for_oauth_clients(): void
    {
        $clientSecret = Str::random(40);
        $clientId = $this->createOAuthClient(
            'Legacy grant test client',
            ['client_credentials'],
            $clientSecret
        );

        $this->post('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'username' => 'user@example.com',
            'password' => 'not-a-real-password',
        ])->assertBadRequest()
            ->assertJsonPath('error', 'unsupported_grant_type');
    }

    public function test_refresh_token_rotation_revokes_previous_access_and_refresh_tokens(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $clientId = $this->createOAuthClient(
            'Refresh token test client',
            ['authorization_code', 'refresh_token']
        );
        $fixture = $this->createRefreshTokenFixture(
            $user,
            $clientId,
            now()->addDays(30)
        );
        $otherClientId = $this->createOAuthClient(
            'Other refresh token test client',
            ['authorization_code', 'refresh_token']
        );

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $otherClientId,
            'refresh_token' => $fixture['token'],
        ])->assertBadRequest()
            ->assertJsonPath('error', 'invalid_grant');

        $response = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $clientId,
            'refresh_token' => $fixture['token'],
        ])->assertOk()
            ->assertJsonStructure(['access_token', 'expires_in', 'refresh_token', 'token_type']);

        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $fixture['access_token_id'],
            'revoked' => true,
        ]);
        $this->assertDatabaseHas('oauth_refresh_tokens', [
            'id' => $fixture['refresh_token_id'],
            'revoked' => true,
        ]);

        $replacementAccessToken = DB::table('oauth_access_tokens')
            ->where('client_id', $clientId)
            ->where('id', '<>', $fixture['access_token_id'])
            ->first();

        $this->assertNotNull($replacementAccessToken);
        $this->assertFalse((bool) $replacementAccessToken->revoked);
        $this->assertTrue(now()->lt($replacementAccessToken->expires_at));
        $replacementRefreshToken = DB::table('oauth_refresh_tokens')
            ->where('access_token_id', $replacementAccessToken->id)
            ->first();

        $this->assertNotNull($replacementRefreshToken);
        $this->assertFalse((bool) $replacementRefreshToken->revoked);
        $this->assertTrue(now()->lt($replacementRefreshToken->expires_at));
        $this->assertDatabaseHas('oauth_refresh_tokens', [
            'access_token_id' => $replacementAccessToken->id,
            'revoked' => false,
        ]);
        $this->assertNotEmpty($response->json('refresh_token'));

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $clientId,
            'refresh_token' => $fixture['token'],
        ])->assertBadRequest()
            ->assertJsonPath('error', 'invalid_grant');
    }

    public function test_expired_refresh_token_is_rejected_without_revoking_existing_tokens(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $clientId = $this->createOAuthClient(
            'Expired refresh test client',
            ['authorization_code', 'refresh_token']
        );
        $fixture = $this->createRefreshTokenFixture(
            $user,
            $clientId,
            now()->subSecond()
        );

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $clientId,
            'refresh_token' => $fixture['token'],
        ])->assertBadRequest()
            ->assertJsonPath('error', 'invalid_grant');

        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $fixture['access_token_id'],
            'revoked' => false,
        ]);
        $this->assertDatabaseHas('oauth_refresh_tokens', [
            'id' => $fixture['refresh_token_id'],
            'revoked' => false,
        ]);
        $this->assertSame(
            1,
            DB::table('oauth_access_tokens')
                ->where('client_id', $clientId)
                ->count()
        );
    }

    public function test_revoked_refresh_token_is_rejected_without_issuing_access_token(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $clientId = $this->createOAuthClient(
            'Revoked refresh test client',
            ['authorization_code', 'refresh_token']
        );
        $fixture = $this->createRefreshTokenFixture(
            $user,
            $clientId,
            now()->addDays(30),
            revoked: true
        );

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $clientId,
            'refresh_token' => $fixture['token'],
        ])->assertBadRequest()
            ->assertJsonPath('error', 'invalid_grant');

        $this->assertSame(
            1,
            DB::table('oauth_access_tokens')
                ->where('client_id', $clientId)
                ->count()
        );
    }

    public function test_invalid_password_is_rejected_and_recorded(): void
    {
        $user = User::factory()->create([
            'email' => 'active@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'Incorrect-password-2026',
        ])->assertUnauthorized();

        $this->assertSame(1, $user->fresh()->failed_login_attempts);

        $this->assertDatabaseHas('security_events', [
            'user_id' => $user->id,
            'event_type' => 'auth.login',
            'result' => 'failure',
        ]);

        $eventContext = DB::table('security_events')
            ->where('user_id', $user->id)
            ->where('event_type', 'auth.login')
            ->value('context');
        $this->assertSame(['reason' => 'invalid_credentials'], json_decode($eventContext, true));
        $auditDetails = DB::table('audit_logs')
            ->where('action', 'auth.login.failure')
            ->value('details');
        $this->assertStringNotContainsString('Incorrect-password-2026', $eventContext);
        $this->assertStringNotContainsString('Incorrect-password-2026', $auditDetails);
        $this->assertDatabaseHas('audit_logs', ['action' => 'auth.login.failure']);
    }

    public function test_sixth_login_attempt_from_one_ip_is_rate_limited(): void
    {
        $user = User::factory()->create([
            'email' => 'throttled-login@example.com',
            'password' => 'Strong-password-2026',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->postJson('/api/v1/auth/login', [
                'email' => $user->email,
                'password' => 'Incorrect-password-2026',
            ])->assertUnauthorized();
        }

        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'Incorrect-password-2026',
        ])->assertTooManyRequests();

        $this->assertDatabaseHas('security_events', [
            'event_type' => 'security.rate_limited',
            'result' => 'blocked',
        ]);
        $this->assertDatabaseHas('audit_logs', [
            'action' => 'security.rate_limited.blocked',
        ]);
    }

    public function test_me_requires_authentication(): void
    {
        $this->getJson('/api/v1/auth/me')->assertUnauthorized();
    }

    public function test_me_returns_public_user_for_authenticated_request(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        Passport::actingAs($user);

        $this->getJson('/api/v1/auth/me')
            ->assertOk()
            ->assertJsonPath('user.public_id', $user->public_id)
            ->assertJsonMissingPath('user.password');
    }

    public function test_inactive_user_cannot_use_an_existing_access_token(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $token = $user->createToken('test-device');

        DB::table('oauth_refresh_tokens')->insert([
            'id' => (string) Str::uuid(),
            'access_token_id' => $token->token->id,
            'revoked' => false,
            'expires_at' => now()->addDays(30),
        ]);

        $user->forceFill(['status' => 'inactive'])->save();

        $this->withToken($token->accessToken)
            ->getJson('/api/v1/auth/me')
            ->assertForbidden();

        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $token->token->id,
            'revoked' => true,
        ]);
        $this->assertDatabaseHas('oauth_refresh_tokens', [
            'access_token_id' => $token->token->id,
            'revoked' => true,
        ]);
        $this->assertDatabaseHas('security_events', [
            'user_id' => $user->id,
            'event_type' => 'auth.inactive_account_access',
            'result' => 'blocked',
        ]);
    }

    public function test_unverified_user_cannot_use_an_existing_access_token(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $token = $user->createToken('test-device');
        $user->forceFill(['email_verified_at' => null])->save();

        $this->withToken($token->accessToken)
            ->getJson('/api/v1/auth/me')
            ->assertForbidden();

        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $token->token->id,
            'revoked' => true,
        ]);
    }

    public function test_logout_all_revokes_the_users_access_and_refresh_tokens(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        $first = $user->createToken('test-device-one');
        $second = $user->createToken('test-device-two');

        $firstId = $first->token->id;
        $secondId = $second->token->id;

        DB::table('sessions')->insert([
            'id' => 'logout-all-session',
            'user_id' => $user->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'test-agent',
            'payload' => 'test-payload',
            'last_activity' => now()->timestamp,
        ]);
        DB::table('oidc_access_tokens')->insert([
            'user_id' => $user->id,
            'oauth_client_id' => DB::table('oauth_clients')->value('id'),
            'token_hash' => hash('sha256', 'test-oidc-token'),
            'scopes' => json_encode(['openid']),
            'expires_at' => now()->addMinutes(10),
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('oauth_refresh_tokens')->insert([
            'id' => (string) Str::uuid(),
            'access_token_id' => $firstId,
            'revoked' => false,
            'expires_at' => now()->addDays(30),
        ]);

        Passport::actingAs($user);

        $this->postJson('/api/v1/auth/logout-all')
            ->assertOk();

        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $firstId,
            'revoked' => true,
        ]);

        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $secondId,
            'revoked' => true,
        ]);

        $this->assertDatabaseMissing('sessions', ['id' => 'logout-all-session']);
        $this->assertNotNull(DB::table('oidc_access_tokens')
            ->where('user_id', $user->id)
            ->value('revoked_at'));

        $this->assertDatabaseHas('oauth_refresh_tokens', [
            'access_token_id' => $firstId,
            'revoked' => true,
        ]);
    }

    public function test_logout_revokes_only_the_current_access_and_refresh_tokens(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        $first = $user->createToken('test-device-one');
        $second = $user->createToken('test-device-two');

        foreach ([$first, $second] as $token) {
            DB::table('oauth_refresh_tokens')->insert([
                'id' => (string) Str::uuid(),
                'access_token_id' => $token->token->id,
                'revoked' => false,
                'expires_at' => now()->addDays(30),
            ]);
        }

        $this->withToken($first->accessToken)
            ->postJson('/api/v1/auth/logout')
            ->assertOk();

        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $first->token->id,
            'revoked' => true,
        ]);
        $this->assertDatabaseHas('oauth_refresh_tokens', [
            'access_token_id' => $first->token->id,
            'revoked' => true,
        ]);
        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $second->token->id,
            'revoked' => false,
        ]);
        $this->assertDatabaseHas('oauth_refresh_tokens', [
            'access_token_id' => $second->token->id,
            'revoked' => false,
        ]);

        Auth::forgetGuards();

        $this->withToken($first->accessToken)
            ->getJson('/api/v1/auth/me')
            ->assertUnauthorized();

        Auth::forgetGuards();

        $this->withToken($second->accessToken)
            ->getJson('/api/v1/auth/me')
            ->assertOk();
    }

    private function createOAuthClient(
        string $name,
        array $grantTypes,
        ?string $plainSecret = null
    ): string {
        $clientId = (string) Str::uuid();

        DB::table('oauth_clients')->insert([
            'id' => $clientId,
            'owner_type' => null,
            'owner_id' => null,
            'name' => $name,
            'secret' => $plainSecret === null ? null : Hash::make($plainSecret),
            'provider' => 'users',
            'redirect_uris' => json_encode(['https://client.example/callback']),
            'grant_types' => json_encode($grantTypes),
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $clientId;
    }

    /**
     * @return array{token: string, access_token_id: string, refresh_token_id: string}
     */
    private function createRefreshTokenFixture(
        User $user,
        string $clientId,
        DateTimeInterface $expiresAt,
        bool $revoked = false
    ): array {
        $accessTokenId = bin2hex(random_bytes(40));
        $refreshTokenId = bin2hex(random_bytes(40));

        DB::table('oauth_access_tokens')->insert([
            'id' => $accessTokenId,
            'user_id' => $user->id,
            'client_id' => $clientId,
            'name' => 'Refresh token test fixture',
            'scopes' => json_encode([]),
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
            'expires_at' => now()->addDays(30),
        ]);

        DB::table('oauth_refresh_tokens')->insert([
            'id' => $refreshTokenId,
            'access_token_id' => $accessTokenId,
            'revoked' => $revoked,
            'expires_at' => $expiresAt,
        ]);

        $encryptedToken = Crypto::encryptWithPassword(
            json_encode([
                'client_id' => $clientId,
                'refresh_token_id' => $refreshTokenId,
                'access_token_id' => $accessTokenId,
                'user_id' => (string) $user->id,
                'scopes' => [],
                'expire_time' => $expiresAt->getTimestamp(),
            ], JSON_THROW_ON_ERROR),
            Passport::tokenEncryptionKey(app('encrypter'))
        );

        return [
            'token' => $encryptedToken,
            'access_token_id' => $accessTokenId,
            'refresh_token_id' => $refreshTokenId,
        ];
    }
}
