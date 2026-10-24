<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use App\Services\WebAuthnService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

class WebAuthnController extends Controller
{
    public function __construct(private readonly WebAuthnService $webAuthn) {}

    public function registrationOptions(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $excluded = DB::table('webauthn_credentials')
            ->where('user_id', $user->id)
            ->whereNull('revoked_at')
            ->get(['credential_id', 'transports'])
            ->map(fn ($credential) => PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $this->decodeCredentialId($credential->credential_id),
                $credential->transports ? explode(',', $credential->transports) : [],
            ))
            ->all();

        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create(config('webauthn.rp_name'), config('webauthn.rp_id')),
            PublicKeyCredentialUserEntity::create($user->email, $user->public_id, $user->name),
            random_bytes(32),
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            excludeCredentials: $excluded,
            timeout: 60000,
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        );

        return $this->challengeResponse($request, $user, 'registration', $options);
    }

    public function verifyRegistration(Request $request, string $challengeId): JsonResponse
    {
        $request->validate(['name' => ['nullable', 'string', 'max:150']]);
        $user = $request->user();
        $serializer = $this->webAuthn->serializer();

        $result = $this->consumeChallenge($challengeId, 'registration', function (array $challenge) use ($request, $serializer, $user): bool {
            try {
                $options = $serializer->deserialize($challenge['options'], PublicKeyCredentialCreationOptions::class, 'json');
                if ($challenge['user_id'] !== $user->id || ! hash_equals($challenge['challenge_hash'], hash('sha256', $options->challenge))) {
                    return false;
                }
                $credential = $serializer->deserialize($request->getContent(), PublicKeyCredential::class, 'json');

                if (! $credential->response instanceof AuthenticatorAttestationResponse) {
                    return false;
                }

                $record = AuthenticatorAttestationResponseValidator::create(
                    $this->webAuthn->ceremonyFactory()->creationCeremony(),
                )->check($credential->response, $options, config('webauthn.rp_id'));

                if ($record->userHandle !== $user->public_id) {
                    return false;
                }

                $credentialId = $this->encodeCredentialId($record->publicKeyCredentialId);
                if (DB::table('webauthn_credentials')->where('credential_id', $credentialId)->exists()) {
                    return false;
                }

                $credentialName = $request->input('name');
                $now = now();

                DB::table('webauthn_credentials')->insert([
                    'public_id' => (string) Str::uuid(),
                    'user_id' => $user->id,
                    'credential_id' => $credentialId,
                    'public_key' => $serializer->serialize($record, 'json'),
                    'sign_count' => $record->counter,
                    'aaguid' => $record->aaguid->toRfc4122(),
                    'transports' => implode(',', $record->transports),
                    'name' => $credentialName,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);

                return true;
            } catch (Throwable) {
                return false;
            }
        });

        if (! $result) {
            $this->recordEvent($request, $user, 'webauthn.registration', 'failure');

            return response()->json(['message' => 'The passkey response is invalid or expired.'], 422);
        }

        $this->recordEvent($request, $user, 'webauthn.registration', 'success');

        return response()->json(['message' => 'Passkey registered.'], 201);
    }

    public function authenticationOptions(Request $request): JsonResponse
    {
        $options = PublicKeyCredentialRequestOptions::create(
            random_bytes(32),
            rpId: config('webauthn.rp_id'),
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            timeout: 60000,
        );

        return $this->challengeResponse($request, null, 'authentication', $options);
    }

    public function verifyAuthentication(Request $request, string $challengeId): JsonResponse
    {
        $serializer = $this->webAuthn->serializer();
        $authenticatedUser = null;

        $result = $this->consumeChallenge($challengeId, 'authentication', function (array $challenge) use ($request, $serializer, &$authenticatedUser): bool {
            try {
                $options = $serializer->deserialize($challenge['options'], PublicKeyCredentialRequestOptions::class, 'json');
                $credential = $serializer->deserialize($request->getContent(), PublicKeyCredential::class, 'json');

                if (! $credential->response instanceof AuthenticatorAssertionResponse) {
                    return false;
                }

                $credentialId = $this->encodeCredentialId($credential->rawId);
                $stored = DB::table('webauthn_credentials')
                    ->where('credential_id', $credentialId)
                    ->whereNull('revoked_at')
                    ->lockForUpdate()
                    ->first();

                if (! $stored) {
                    return false;
                }

                $user = User::query()->whereKey($stored->user_id)->lockForUpdate()->first();
                if (! $user || $user->status !== 'active' || ! $user->email_verified_at || ($user->locked_until && $user->locked_until->isFuture())) {
                    return false;
                }
                if (! hash_equals($challenge['challenge_hash'], hash('sha256', $options->challenge))) {
                    return false;
                }

                /** @var CredentialRecord $record */
                $record = $serializer->deserialize($stored->public_key, CredentialRecord::class, 'json');
                $updatedRecord = AuthenticatorAssertionResponseValidator::create(
                    $this->webAuthn->ceremonyFactory()->requestCeremony(),
                )->check($record, $credential->response, $options, config('webauthn.rp_id'), null);

                DB::table('webauthn_credentials')->where('id', $stored->id)->update([
                    'public_key' => $serializer->serialize($updatedRecord, 'json'),
                    'sign_count' => $updatedRecord->counter,
                    'last_used_at' => now(),
                    'updated_at' => now(),
                ]);

                $user->forceFill([
                    'failed_login_attempts' => 0,
                    'locked_until' => null,
                    'last_login_at' => now(),
                    'last_login_ip' => $request->ip(),
                ])->save();
                $authenticatedUser = $user;

                return true;
            } catch (Throwable) {
                return false;
            }
        });

        if (! $result || ! $authenticatedUser) {
            $this->recordEvent($request, null, 'webauthn.authentication', 'failure');

            return response()->json(['message' => 'The passkey response is invalid or expired.'], 401);
        }

        $hasTotp = DB::table('mfa_methods')
            ->where('user_id', $authenticatedUser->id)
            ->where('type', 'totp')
            ->whereNotNull('verified_at')
            ->whereNull('revoked_at')
            ->exists();

        if ($hasTotp) {
            $challengeToken = Str::random(64);
            $now = now();
            DB::table('verification_challenges')->insert([
                'user_id' => $authenticatedUser->id,
                'channel' => 'totp',
                'purpose' => 'login_mfa',
                'destination' => $authenticatedUser->email,
                'token_hash' => hash('sha256', $challengeToken),
                'attempts' => 0,
                'expires_at' => $now->copy()->addMinutes(5),
                'consumed_at' => null,
                'created_at' => $now,
                'updated_at' => $now,
            ]);

            $this->recordEvent($request, $authenticatedUser, 'webauthn.authentication', 'mfa_required');

            return response()->json([
                'mfa_required' => true,
                'challenge_token' => $challengeToken,
                'expires_in' => 300,
            ], 202);
        }

        $token = $authenticatedUser->createToken('VisionWeb Passkey');
        $this->recordEvent($request, $authenticatedUser, 'webauthn.authentication', 'success');

        return response()->json([
            'token_type' => 'Bearer',
            'access_token' => $token->accessToken,
            'expires_at' => $token->token->expires_at?->toISOString(),
            'user' => [
                'id' => $authenticatedUser->id,
                'public_id' => $authenticatedUser->public_id,
                'name' => $authenticatedUser->name,
                'email' => $authenticatedUser->email,
            ],
        ]);
    }

    public function credentials(Request $request): JsonResponse
    {
        return response()->json([
            'data' => DB::table('webauthn_credentials')
                ->where('user_id', $request->user()->id)
                ->whereNull('revoked_at')
                ->get(['public_id', 'name', 'transports', 'last_used_at', 'created_at']),
        ]);
    }

    public function revoke(Request $request, string $publicId): JsonResponse
    {
        $count = DB::table('webauthn_credentials')
            ->where('public_id', $publicId)
            ->where('user_id', $request->user()->id)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now(), 'updated_at' => now()]);

        if (! $count) {
            return response()->json(['message' => 'Passkey not found.'], 404);
        }

        $this->recordEvent($request, $request->user(), 'webauthn.credential_revoked', 'success');

        return response()->json(['message' => 'Passkey revoked.']);
    }

    private function challengeResponse(Request $request, ?User $user, string $ceremony, object $options): JsonResponse
    {
        $serializer = $this->webAuthn->serializer();
        $optionsJson = $serializer->serialize($options, 'json', [AbstractObjectNormalizer::SKIP_NULL_VALUES => true]);
        $challenge = $options->challenge;
        $challengeId = (string) Str::uuid();
        $now = now();

        DB::table('webauthn_challenges')->insert([
            'public_id' => $challengeId,
            'user_id' => $user?->id,
            'ceremony' => $ceremony,
            'challenge_hash' => hash('sha256', $challenge),
            'options_encrypted' => Crypt::encryptString($optionsJson),
            'expires_at' => $now->copy()->addMinutes(config('webauthn.challenge_expire_minutes', 5)),
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        return response()->json([
            'challenge_id' => $challengeId,
            'public_key' => json_decode($optionsJson, true, flags: JSON_THROW_ON_ERROR),
        ]);
    }

    private function consumeChallenge(string $challengeId, string $ceremony, callable $callback): bool
    {
        return DB::transaction(function () use ($challengeId, $ceremony, $callback): bool {
            $challenge = DB::table('webauthn_challenges')
                ->where('public_id', $challengeId)
                ->where('ceremony', $ceremony)
                ->lockForUpdate()
                ->first();

            if (! $challenge || $challenge->consumed_at || now()->greaterThanOrEqualTo($challenge->expires_at)) {
                return false;
            }

            DB::table('webauthn_challenges')->where('id', $challenge->id)->update([
                'consumed_at' => now(),
                'updated_at' => now(),
            ]);

            try {
                return $callback([
                    'options' => Crypt::decryptString($challenge->options_encrypted),
                    'challenge_hash' => $challenge->challenge_hash,
                    'user_id' => $challenge->user_id,
                ]);
            } catch (Throwable) {
                return false;
            }
        });
    }

    private function encodeCredentialId(string $credentialId): string
    {
        return rtrim(strtr(base64_encode($credentialId), '+/', '-_'), '=');
    }

    private function decodeCredentialId(string $credentialId): string
    {
        return base64_decode(strtr($credentialId, '-_', '+/'), true) ?: '';
    }

    private function recordEvent(Request $request, ?User $user, string $event, string $result): void
    {
        $context = [];
        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $user?->id,
            'event_type' => $event,
            'result' => $result,
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
            'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
            'context' => json_encode($context, JSON_THROW_ON_ERROR),
            'occurred_at' => now(),
        ]);
        AuditLog::recordEntry($request, $user, $event.'.'.$result, $context);
    }
}
