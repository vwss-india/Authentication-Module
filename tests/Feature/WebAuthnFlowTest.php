<?php

namespace Tests\Feature;

use App\Http\Middleware\RecordRateLimitEvent;
use App\Models\User;
use App\Services\WebAuthnService;
use CBOR\Encoder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Symfony\Component\Uid\Uuid;
use Tests\TestCase;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorData;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\TrustPath\EmptyTrustPath;

class WebAuthnFlowTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config([
            'webauthn.rp_id' => 'localhost',
            'webauthn.allowed_origins' => ['http://localhost'],
        ]);
    }

    public function test_authentication_options_create_a_short_lived_opaque_challenge(): void
    {
        $response = $this->postJson('/api/v1/auth/passkeys/authentication/options')
            ->assertOk()
            ->assertJsonPath('public_key.rpId', 'localhost')
            ->assertJsonPath('public_key.userVerification', 'required');

        $challenge = DB::table('webauthn_challenges')->where('public_id', $response->json('challenge_id'))->first();
        $this->assertNotNull($challenge);
        $this->assertNull($challenge->user_id);
        $this->assertSame('authentication', $challenge->ceremony);
        $this->assertTrue(now()->lt($challenge->expires_at));
        $this->assertStringNotContainsString($response->json('public_key.challenge'), $challenge->options_encrypted);
    }

    public function test_invalid_registration_response_consumes_challenge_and_cannot_be_replayed(): void
    {
        $user = User::factory()->create(['status' => 'active']);
        $this->actingAs($user, 'api');

        $challengeId = $this->postJson('/api/v1/auth/passkeys/registration/options')
            ->assertOk()
            ->json('challenge_id');

        $this->call('POST', "/api/v1/auth/passkeys/registration/{$challengeId}/verify", [], [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{"type":"public-key"}')
            ->assertUnprocessable();

        $this->assertNotNull(DB::table('webauthn_challenges')->where('public_id', $challengeId)->value('consumed_at'));

        $this->call('POST', "/api/v1/auth/passkeys/registration/{$challengeId}/verify", [], [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{"type":"public-key"}')
            ->assertUnprocessable();

        $this->assertDatabaseCount('webauthn_credentials', 0);
    }

    public function test_expired_authentication_challenge_is_rejected(): void
    {
        $challengeId = $this->postJson('/api/v1/auth/passkeys/authentication/options')
            ->assertOk()
            ->json('challenge_id');
        DB::table('webauthn_challenges')->where('public_id', $challengeId)->update(['expires_at' => now()->subSecond()]);

        $this->call('POST', "/api/v1/auth/passkeys/authentication/{$challengeId}/verify", [], [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{"type":"public-key"}')
            ->assertUnauthorized();

        $this->assertNull(DB::table('webauthn_challenges')->where('public_id', $challengeId)->value('consumed_at'));
    }

    public function test_users_can_only_list_and_revoke_their_own_passkeys(): void
    {
        $owner = User::factory()->create(['status' => 'active']);
        $otherUser = User::factory()->create(['status' => 'active']);
        $credentialId = rtrim(strtr(base64_encode('credential-id'), '+/', '-_'), '=');
        $credential = CredentialRecord::create(
            'credential-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            new EmptyTrustPath,
            Uuid::fromString('00000000-0000-0000-0000-000000000001'),
            'public-key-bytes',
            $owner->public_id,
            0,
        );
        $publicId = (string) Str::uuid();

        DB::table('webauthn_credentials')->insert([
            'public_id' => $publicId,
            'user_id' => $owner->id,
            'credential_id' => $credentialId,
            'public_key' => app(WebAuthnService::class)->serializer()->serialize($credential, 'json'),
            'sign_count' => 0,
            'name' => 'My passkey',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($otherUser, 'api')
            ->getJson('/api/v1/auth/passkeys')
            ->assertOk()
            ->assertJsonCount(0, 'data');
        $this->deleteJson("/api/v1/auth/passkeys/{$publicId}")->assertNotFound();
        $this->assertNull(DB::table('webauthn_credentials')->where('public_id', $publicId)->value('revoked_at'));

        $this->actingAs($owner, 'api')
            ->getJson('/api/v1/auth/passkeys')
            ->assertOk()
            ->assertJsonPath('data.0.name', 'My passkey');
        $this->deleteJson("/api/v1/auth/passkeys/{$publicId}")->assertOk();
        $this->getJson('/api/v1/auth/passkeys')->assertOk()->assertJsonCount(0, 'data');
    }

    public function test_configured_webauthn_ceremony_rejects_an_unregistered_origin(): void
    {
        $challenge = random_bytes(32);
        $record = $this->credentialRecord();
        $response = $this->assertionResponse($challenge, 'https://attacker.example');
        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            rpId: 'localhost',
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        );

        $this->expectException(AuthenticatorResponseVerificationException::class);
        app(WebAuthnService::class)->ceremonyFactory()->requestCeremony()
            ->process($record, $response, $options, null, 'localhost');
    }

    public function test_configured_webauthn_ceremony_rejects_a_mismatched_relying_party_hash(): void
    {
        $challenge = random_bytes(32);
        $record = $this->credentialRecord();
        $response = $this->assertionResponse($challenge, 'http://localhost', str_repeat("\0", 32));
        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            rpId: 'localhost',
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        );

        $this->expectException(AuthenticatorResponseVerificationException::class);
        app(WebAuthnService::class)->ceremonyFactory()->requestCeremony()
            ->process($record, $response, $options, null, 'localhost');
    }

    public function test_valid_discoverable_passkey_authentication_issues_token_and_rejects_replay(): void
    {
        $this->withoutMiddleware(RecordRateLimitEvent::class);

        $clientId = (string) Str::uuid();
        DB::table('oauth_clients')->insert([
            'id' => $clientId,
            'owner_type' => null,
            'owner_id' => null,
            'name' => 'WebAuthn test personal access client',
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

        $user = User::factory()->create(['status' => 'active']);
        $registrationOptions = $this->postJson('/api/v1/auth/passkeys/registration/options')
            ->assertUnauthorized();
        $this->actingAs($user, 'api');
        $registrationOptions = $this->postJson('/api/v1/auth/passkeys/registration/options')->assertOk();

        $keyOptions = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ];
        $opensslConfig = dirname(PHP_BINARY).DIRECTORY_SEPARATOR.'extras'.DIRECTORY_SEPARATOR.'ssl'.DIRECTORY_SEPARATOR.'openssl.cnf';
        if (is_file($opensslConfig)) {
            $keyOptions['config'] = $opensslConfig;
        }
        $privateKey = openssl_pkey_new($keyOptions);
        $this->assertNotFalse($privateKey);
        $keyDetails = openssl_pkey_get_details($privateKey);
        $credentialId = random_bytes(32);
        $credentialIdBase64 = $this->base64Url($credentialId);
        $cosePublicKey = (new Encoder)->encode([
            1 => 2,
            3 => -7,
            -1 => 1,
            -2 => $keyDetails['ec']['x'],
            -3 => $keyDetails['ec']['y'],
        ]);
        $authenticatorData = hash('sha256', 'localhost', true)
            .chr(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_UV | AuthenticatorData::FLAG_AT)
            .pack('N', 0)
            .random_bytes(16)
            .pack('n', strlen($credentialId))
            .$credentialId
            .$cosePublicKey;
        $attestationObject = (new Encoder)->encode([
            'fmt' => 'none',
            'attStmt' => [],
            'authData' => $authenticatorData,
        ]);
        $clientData = json_encode([
            'type' => 'webauthn.create',
            'challenge' => $registrationOptions->json('public_key.challenge'),
            'origin' => 'http://localhost',
        ], JSON_THROW_ON_ERROR);
        $registrationResponse = [
            'id' => $credentialIdBase64,
            'rawId' => $credentialIdBase64,
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => $this->base64Url($clientData),
                'attestationObject' => $this->base64Url($attestationObject),
                'transports' => ['internal'],
            ],
            'clientExtensionResults' => new \stdClass,
        ];

        $this->postWebAuthnResponse(
            "/api/v1/auth/passkeys/registration/{$registrationOptions->json('challenge_id')}/verify",
            $registrationResponse,
        )->assertCreated();

        $this->assertDatabaseHas('webauthn_credentials', [
            'user_id' => $user->id,
            'credential_id' => $credentialIdBase64,
            'sign_count' => 0,
        ]);

        $authenticationOptions = $this->postJson('/api/v1/auth/passkeys/authentication/options')->assertOk();
        $assertionClientData = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $authenticationOptions->json('public_key.challenge'),
            'origin' => 'http://localhost',
        ], JSON_THROW_ON_ERROR);
        $assertionAuthenticatorData = hash('sha256', 'localhost', true)
            .chr(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_UV)
            .pack('N', 1);
        openssl_sign(
            $assertionAuthenticatorData.hash('sha256', $assertionClientData, true),
            $signature,
            $privateKey,
            OPENSSL_ALGO_SHA256,
        );
        $assertionResponse = [
            'id' => $credentialIdBase64,
            'rawId' => $credentialIdBase64,
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => $this->base64Url($assertionClientData),
                'authenticatorData' => $this->base64Url($assertionAuthenticatorData),
                'signature' => $this->base64Url($signature),
                'userHandle' => $this->base64Url($user->public_id),
            ],
            'clientExtensionResults' => new \stdClass,
        ];
        $verificationUri = "/api/v1/auth/passkeys/authentication/{$authenticationOptions->json('challenge_id')}/verify";

        $this->postWebAuthnResponse($verificationUri, $assertionResponse)
            ->assertOk()
            ->assertJsonPath('user.email', $user->email)
            ->assertJsonMissingPath('user.password');

        $this->assertDatabaseHas('webauthn_credentials', [
            'credential_id' => $credentialIdBase64,
            'sign_count' => 1,
        ]);

        $totpSecret = 'JBSWY3DPEHPK3PXP';
        DB::table('mfa_methods')->insert([
            'public_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'type' => 'totp',
            'label' => 'Authenticator app',
            'secret_encrypted' => Crypt::encryptString($totpSecret),
            'is_primary' => true,
            'verified_at' => now(),
            'last_used_at' => null,
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $mfaAuthenticationOptions = $this->postJson('/api/v1/auth/passkeys/authentication/options')->assertOk();
        $mfaClientData = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $mfaAuthenticationOptions->json('public_key.challenge'),
            'origin' => 'http://localhost',
        ], JSON_THROW_ON_ERROR);
        $mfaAuthenticatorData = hash('sha256', 'localhost', true)
            .chr(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_UV)
            .pack('N', 2);
        openssl_sign(
            $mfaAuthenticatorData.hash('sha256', $mfaClientData, true),
            $mfaSignature,
            $privateKey,
            OPENSSL_ALGO_SHA256,
        );
        $mfaAssertion = [
            ...$assertionResponse,
            'response' => [
                'clientDataJSON' => $this->base64Url($mfaClientData),
                'authenticatorData' => $this->base64Url($mfaAuthenticatorData),
                'signature' => $this->base64Url($mfaSignature),
                'userHandle' => $this->base64Url($user->public_id),
            ],
        ];
        $mfaLogin = $this->postWebAuthnResponse(
            "/api/v1/auth/passkeys/authentication/{$mfaAuthenticationOptions->json('challenge_id')}/verify",
            $mfaAssertion,
        )->assertAccepted()
            ->assertJsonPath('mfa_required', true)
            ->assertJsonMissingPath('access_token');

        $this->postJson('/api/v1/auth/login/2fa', [
            'challenge_token' => $mfaLogin->json('challenge_token'),
            'code' => app('pragmarx.google2fa')->getCurrentOtp($totpSecret),
        ])->assertOk()->assertJsonStructure(['access_token', 'user']);
        $this->postWebAuthnResponse($verificationUri, $assertionResponse)->assertUnauthorized();

        $counterReplayOptions = $this->postJson('/api/v1/auth/passkeys/authentication/options')->assertOk();
        $counterReplayClientData = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $counterReplayOptions->json('public_key.challenge'),
            'origin' => 'http://localhost',
        ], JSON_THROW_ON_ERROR);
        $counterReplayAuthenticatorData = hash('sha256', 'localhost', true)
            .chr(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_UV)
            .pack('N', 1);
        openssl_sign(
            $counterReplayAuthenticatorData.hash('sha256', $counterReplayClientData, true),
            $counterReplaySignature,
            $privateKey,
            OPENSSL_ALGO_SHA256,
        );
        $counterReplayResponse = [
            ...$assertionResponse,
            'response' => [
                'clientDataJSON' => $this->base64Url($counterReplayClientData),
                'authenticatorData' => $this->base64Url($counterReplayAuthenticatorData),
                'signature' => $this->base64Url($counterReplaySignature),
                'userHandle' => $this->base64Url($user->public_id),
            ],
        ];

        $this->postWebAuthnResponse(
            "/api/v1/auth/passkeys/authentication/{$counterReplayOptions->json('challenge_id')}/verify",
            $counterReplayResponse,
        )->assertUnauthorized();

        $invalidSignatureOptions = $this->postJson('/api/v1/auth/passkeys/authentication/options')->assertOk();
        $invalidSignatureClientData = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $invalidSignatureOptions->json('public_key.challenge'),
            'origin' => 'http://localhost',
        ], JSON_THROW_ON_ERROR);
        $invalidSignatureAuthenticatorData = hash('sha256', 'localhost', true)
            .chr(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_UV)
            .pack('N', 2);
        $invalidSignatureResponse = [
            ...$assertionResponse,
            'response' => [
                'clientDataJSON' => $this->base64Url($invalidSignatureClientData),
                'authenticatorData' => $this->base64Url($invalidSignatureAuthenticatorData),
                'signature' => $this->base64Url(random_bytes(64)),
                'userHandle' => $this->base64Url($user->public_id),
            ],
        ];

        $this->postWebAuthnResponse(
            "/api/v1/auth/passkeys/authentication/{$invalidSignatureOptions->json('challenge_id')}/verify",
            $invalidSignatureResponse,
        )->assertUnauthorized();
        $this->assertDatabaseHas('webauthn_credentials', [
            'credential_id' => $credentialIdBase64,
            'sign_count' => 2,
        ]);
    }

    private function credentialRecord(): CredentialRecord
    {
        return CredentialRecord::create(
            'credential-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            new EmptyTrustPath,
            Uuid::fromString('00000000-0000-0000-0000-000000000001'),
            'public-key-bytes',
            'user-handle',
            0,
        );
    }

    private function assertionResponse(string $challenge, string $origin, ?string $rpIdHash = null): AuthenticatorAssertionResponse
    {
        $challengeBase64 = rtrim(strtr(base64_encode($challenge), '+/', '-_'), '=');
        $clientData = CollectedClientData::create('', [
            'type' => 'webauthn.get',
            'challenge' => $challengeBase64,
            'origin' => $origin,
        ]);
        $authenticatorData = AuthenticatorData::create(
            'authenticator-data',
            $rpIdHash ?? hash('sha256', 'localhost', true),
            chr(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_UV),
            0,
            null,
        );

        return AuthenticatorAssertionResponse::create($clientData, $authenticatorData, 'signature');
    }

    private function postWebAuthnResponse(string $uri, array $response): TestResponse
    {
        return $this->call(
            'POST',
            $uri,
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode($response, JSON_THROW_ON_ERROR),
        );
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
