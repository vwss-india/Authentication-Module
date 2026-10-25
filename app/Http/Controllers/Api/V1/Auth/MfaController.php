<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Throwable;

class MfaController extends Controller
{
    private const MAX_CHALLENGE_ATTEMPTS = 5;

    private const RECOVERY_CODE_COUNT = 10;

    private const TRUSTED_DEVICE_DAYS = 30;

    public function status(Request $request): JsonResponse
    {
        $userId = $request->user()->id;

        $totpEnabled = DB::table('mfa_methods')
            ->where('user_id', $userId)
            ->where('type', 'totp')
            ->whereNotNull('verified_at')
            ->whereNull('revoked_at')
            ->exists();

        $unusedCodes = DB::table('mfa_recovery_codes as rc')
            ->join('mfa_methods as mm', 'mm.id', '=', 'rc.mfa_method_id')
            ->where('mm.user_id', $userId)
            ->where('mm.type', 'totp')
            ->whereNotNull('mm.verified_at')
            ->whereNull('mm.revoked_at')
            ->whereNull('rc.used_at')
            ->count();

        return response()->json([
            'totp_enabled' => $totpEnabled,
            'unused_recovery_codes' => $totpEnabled ? $unusedCodes : 0,
        ]);
    }

    public function setupTotp(Request $request): JsonResponse
    {
        $user = $request->user();

        $alreadyEnabled = DB::table('mfa_methods')
            ->where('user_id', $user->id)
            ->where('type', 'totp')
            ->whereNotNull('verified_at')
            ->whereNull('revoked_at')
            ->exists();

        if ($alreadyEnabled) {
            return response()->json([
                'message' => 'Two-factor authentication is already enabled.',
            ], 409);
        }

        $google2fa = app('pragmarx.google2fa');
        $secret = $google2fa->generateSecretKey();

        DB::transaction(function () use ($user, $secret): void {
            DB::table('mfa_methods')
                ->where('user_id', $user->id)
                ->where('type', 'totp')
                ->whereNull('verified_at')
                ->whereNull('revoked_at')
                ->delete();

            DB::table('mfa_methods')->insert([
                'public_id' => (string) Str::uuid(),
                'user_id' => $user->id,
                'type' => 'totp',
                'label' => 'Authenticator app',
                'secret_encrypted' => Crypt::encryptString($secret),
                'verified_at' => null,
                'last_used_at' => null,
                'revoked_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        });

        $this->recordEvent(
            $request,
            $user->id,
            'auth.mfa.setup_started',
            'success'
        );

        return response()->json([
            'message' => 'Scan the provisioning URI, then confirm with a current code.',
            'secret' => $secret,
            'provisioning_uri' => $google2fa->getQRCodeUrl(
                config('app.name', 'VisionWeb Central Auth'),
                $user->email,
                $secret
            ),
        ]);
    }

    public function confirmTotp(Request $request): JsonResponse
    {
        $data = $request->validate([
            'code' => ['required', 'digits:6'],
        ]);

        $userId = $request->user()->id;

        $result = DB::transaction(function () use ($userId, $data): array {
            $method = DB::table('mfa_methods')
                ->where('user_id', $userId)
                ->where('type', 'totp')
                ->whereNull('verified_at')
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->first();

            if (! $method) {
                return ['error' => 'setup_required'];
            }

            try {
                $secret = Crypt::decryptString($method->secret_encrypted);
            } catch (Throwable) {
                return ['error' => 'secret_unavailable'];
            }

            $verified = app('pragmarx.google2fa')->verifyKeyNewer(
                $secret,
                $data['code'],
                0,
                1
            );

            if ($verified === false) {
                return ['error' => 'invalid_code'];
            }

            DB::table('mfa_methods')
                ->where('id', $method->id)
                ->update([
                    'verified_at' => now(),
                    'last_used_counter' => $verified,
                    'last_used_at' => now(),
                    'updated_at' => now(),
                ]);

            DB::table('mfa_recovery_codes')
                ->where('mfa_method_id', $method->id)
                ->delete();

            $codes = $this->generateRecoveryCodes();

            foreach ($codes as $code) {
                DB::table('mfa_recovery_codes')->insert([
                    'mfa_method_id' => $method->id,
                    'code_hash' => Hash::make($code),
                    'used_at' => null,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
            }

            return ['codes' => $codes];
        });

        if (isset($result['error'])) {
            $this->recordEvent(
                $request,
                $userId,
                'auth.mfa.confirm_failed',
                'rejected',
                ['reason' => $result['error']]
            );

            return response()->json([
                'message' => match ($result['error']) {
                    'setup_required' => 'Start TOTP setup first.',
                    'secret_unavailable' => 'The pending authenticator setup is unavailable. Start setup again.',
                    default => 'The verification code is invalid.',
                },
            ], 422);
        }

        $this->recordEvent(
            $request,
            $userId,
            'auth.mfa.enabled',
            'success'
        );

        return response()->json([
            'message' => 'Two-factor authentication enabled.',
            'recovery_codes' => $result['codes'],
            'warning' => 'Save these codes securely. They will not be shown again.',
        ]);
    }

    public function completeLogin(Request $request): JsonResponse
    {
        $data = $request->validate([
            'challenge_token' => ['required', 'string', 'max:128'],
            'code' => ['required', 'string', 'max:128'],
            'device_name' => ['nullable', 'string', 'max:150'],
            'trust_device' => ['sometimes', 'boolean'],
        ]);

        $challengeHash = hash('sha256', $data['challenge_token']);

        $result = DB::transaction(function () use (

            $data,
            $challengeHash
        ): array {
            $challenge = DB::table('verification_challenges')
                ->where('token_hash', $challengeHash)
                ->where('purpose', 'login_mfa')
                ->where('channel', 'totp')
                ->lockForUpdate()
                ->first();

            if (
                ! $challenge ||
                $challenge->consumed_at !== null ||
                now()->greaterThanOrEqualTo($challenge->expires_at) ||
                (int) $challenge->attempts >= self::MAX_CHALLENGE_ATTEMPTS
            ) {
                return ['error' => 'challenge_invalid'];
            }

            $user = User::query()
                ->whereKey($challenge->user_id)
                ->lockForUpdate()
                ->first();

            if (! $user) {
                return ['error' => 'mfa_unavailable'];
            }

            if ($user->locked_until && $user->locked_until->isFuture()) {
                DB::table('verification_challenges')
                    ->where('id', $challenge->id)
                    ->update([
                        'consumed_at' => now(),
                        'updated_at' => now(),
                    ]);

                return [
                    'error' => 'account_locked',
                    'user_id' => $user->id,
                ];
            }

            if ($user->locked_until) {
                $user->forceFill([
                    'failed_login_attempts' => 0,
                    'locked_until' => null,
                ])->save();
            }

            $method = DB::table('mfa_methods')
                ->where('user_id', $challenge->user_id)
                ->where('type', 'totp')
                ->whereNotNull('verified_at')
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->first();

            if (! $method) {
                return ['error' => 'mfa_unavailable'];
            }

            $accepted = false;
            $recoveryUsed = false;

            if (preg_match('/^\d{6}$/', $data['code'])) {
                try {
                    $secret = Crypt::decryptString($method->secret_encrypted);

                    $lastUsedTimestamp = $method->last_used_at
                        ? strtotime((string) $method->last_used_at)
                        : 0;

                    $matchedTimestamp = app('pragmarx.google2fa')->verifyKeyNewer(
                        $secret,
                        $data['code'],
                        $lastUsedTimestamp ?: 0,
                        1
                    );

                    $accepted = $matchedTimestamp !== false;
                } catch (Throwable) {
                    $accepted = false;
                }

                if ($accepted) {
                    DB::table('mfa_methods')
                        ->where('id', $method->id)
                        ->update([
                            'last_used_at' => now(),
                            'updated_at' => now(),
                        ]);
                }
            } else {
                $recoveryRows = DB::table('mfa_recovery_codes')
                    ->where('mfa_method_id', $method->id)
                    ->whereNull('used_at')
                    ->lockForUpdate()
                    ->get();

                foreach ($recoveryRows as $recoveryRow) {
                    if (Hash::check($data['code'], $recoveryRow->code_hash)) {
                        $updated = DB::table('mfa_recovery_codes')
                            ->where('id', $recoveryRow->id)
                            ->whereNull('used_at')
                            ->update([
                                'used_at' => now(),
                                'updated_at' => now(),
                            ]);

                        if ($updated === 1) {
                            $accepted = true;
                            $recoveryUsed = true;
                        }

                        break;
                    }
                }
            }

            if (! $accepted) {
                $attempts = (int) $challenge->attempts + 1;
                $failedLoginAttempts = (int) $user->failed_login_attempts + 1;

                $user->forceFill([
                    'failed_login_attempts' => $failedLoginAttempts,
                    'locked_until' => $failedLoginAttempts >= self::MAX_CHALLENGE_ATTEMPTS
                        ? now()->addMinutes(15)
                        : $user->locked_until,
                ])->save();

                DB::table('verification_challenges')
                    ->where('id', $challenge->id)
                    ->update([
                        'attempts' => $attempts,
                        'consumed_at' => $attempts >= self::MAX_CHALLENGE_ATTEMPTS
                            ? now()
                            : null,
                        'updated_at' => now(),
                    ]);

                return ['error' => 'invalid_code'];
            }

            DB::table('verification_challenges')
                ->where('id', $challenge->id)
                ->update([
                    'consumed_at' => now(),
                    'updated_at' => now(),
                ]);

            return [
                'user_id' => $challenge->user_id,
                'recovery_used' => $recoveryUsed,
            ];
        });

        if (isset($result['error'])) {
            $isLocked = $result['error'] === 'account_locked';

            $this->recordEvent(
                $request,
                $result['user_id'] ?? null,
                'auth.mfa.challenge_failed',
                $isLocked ? 'blocked' : 'rejected',
                ['reason' => $result['error']]
            );

            return response()->json([
                'message' => match ($result['error']) {
                    'mfa_unavailable' => 'MFA is not available for this account.',
                    'challenge_invalid' => 'The challenge is invalid, expired, or already used.',
                    'account_locked' => 'Sign-in is temporarily unavailable. Try again later.',
                    default => 'The verification code is invalid. The challenge allows at most five attempts.',
                },
            ], $isLocked ? 423 : 422);
        }

        $user = User::findOrFail($result['user_id']);

        if ($user->status !== 'active' || ! $user->email_verified_at) {
            $this->recordEvent(
                $request,
                $user->id,
                'auth.mfa.challenge_failed',
                'blocked',
                ['reason' => 'account_not_active_or_unverified']
            );

            return response()->json([
                'message' => 'This account is not active or its email is not verified.',
            ], 403);
        }

        $user->forceFill([
            'failed_login_attempts' => 0,
            'locked_until' => null,
            'last_login_at' => now(),
            'last_login_ip' => $request->ip(),
        ])->save();

        $tokenResult = $user->createToken(
            Str::limit(
                $data['device_name'] ?? 'VisionWeb Central Auth',
                100,
                ''
            )
        );

        $response = [
            'message' => 'Login successful.',
            'token_type' => 'Bearer',
            'access_token' => $tokenResult->accessToken,
            'expires_at' => $tokenResult->token->expires_at,
            'user' => $this->publicUser($user),
        ];

        if (! empty($data['trust_device'])) {
            $rawDeviceToken = bin2hex(random_bytes(32));
            $deviceExpiresAt = now()->addDays(self::TRUSTED_DEVICE_DAYS);

            DB::table('trusted_devices')->insert([
                'public_id' => (string) Str::uuid(),
                'user_id' => $user->id,
                'name' => $data['device_name'] ?? 'Trusted device',
                'token_hash' => hash('sha256', $rawDeviceToken),
                'ip_address' => $request->ip(),
                'user_agent' => Str::limit(
                    (string) $request->userAgent(),
                    2000,
                    ''
                ),
                'last_used_at' => now(),
                'expires_at' => $deviceExpiresAt,
                'revoked_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            $response['trusted_device_token'] = $rawDeviceToken;
            $response['trusted_device_expires_at'] = $deviceExpiresAt->toISOString();
        }

        $this->recordEvent(
            $request,
            $user->id,
            'auth.mfa.challenge_succeeded',
            'success',
            ['recovery_code_used' => $result['recovery_used']]
        );

        return response()->json($response);
    }

    public function disableTotp(Request $request): JsonResponse
    {
        $data = $request->validate([
            'password' => ['required', 'string'],
            'code' => ['required', 'digits:6'],
        ]);

        $user = $request->user();

        if (! Hash::check($data['password'], $user->password)) {
            $this->recordEvent(
                $request,
                $user->id,
                'auth.mfa.disable_failed',
                'rejected'
            );

            return response()->json([
                'message' => 'The password is incorrect.',
            ], 422);
        }

        $result = DB::transaction(function () use ($user, $data): array {
            $method = DB::table('mfa_methods')
                ->where('user_id', $user->id)
                ->where('type', 'totp')
                ->whereNotNull('verified_at')
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->first();

            if (! $method) {
                return ['error' => 'not_enabled'];
            }

            try {
                $secret = Crypt::decryptString($method->secret_encrypted);

                $lastUsedCounter = (int) ($method->last_used_counter ?? 0);

                $valid = app('pragmarx.google2fa')->verifyKeyNewer(
                    $secret,
                    $data['code'],
                    $lastUsedCounter,
                    1
                );
            } catch (Throwable) {
                $valid = false;
            }

            if (! $valid) {
                return ['error' => 'invalid_code'];
            }

            DB::table('mfa_methods')
                ->where('user_id', $user->id)
                ->where('type', 'totp')
                ->whereNull('revoked_at')
                ->update([
                    'revoked_at' => now(),
                    'updated_at' => now(),
                ]);

            DB::table('mfa_recovery_codes')
                ->where('mfa_method_id', $method->id)
                ->whereNull('used_at')
                ->update([
                    'used_at' => now(),
                    'updated_at' => now(),
                ]);

            DB::table('trusted_devices')
                ->where('user_id', $user->id)
                ->whereNull('revoked_at')
                ->update([
                    'revoked_at' => now(),
                    'updated_at' => now(),
                ]);

            return ['success' => true];
        });

        if (isset($result['error'])) {
            $this->recordEvent(
                $request,
                $user->id,
                'auth.mfa.disable_failed',
                'rejected'
            );

            return response()->json([
                'message' => $result['error'] === 'not_enabled'
                    ? 'Two-factor authentication is not enabled.'
                    : 'The verification code is invalid or already used.',
            ], 422);
        }

        $this->recordEvent(
            $request,
            $user->id,
            'auth.mfa.disabled',
            'success'
        );

        return response()->json([
            'message' => 'Two-factor authentication disabled. All trusted devices were revoked.',
        ]);
    }

    public function regenerateRecoveryCodes(Request $request): JsonResponse
    {
        $data = $request->validate([
            'password' => ['required', 'string'],
            'code' => ['required', 'digits:6'],
        ]);

        $user = $request->user();

        if (! Hash::check($data['password'], $user->password)) {
            return response()->json([
                'message' => 'The password is incorrect.',
            ], 422);
        }

        $result = DB::transaction(function () use ($user, $data): array {
            $method = DB::table('mfa_methods')
                ->where('user_id', $user->id)
                ->where('type', 'totp')
                ->whereNotNull('verified_at')
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->first();

            if (! $method) {
                return ['error' => 'not_enabled'];
            }

            try {
                $secret = Crypt::decryptString($method->secret_encrypted);

                $lastTimestamp = $method->last_used_at
                    ? strtotime((string) $method->last_used_at)
                    : 0;

                $valid = app('pragmarx.google2fa')->verifyKeyNewer(
                    $secret,
                    $data['code'],
                    $lastTimestamp ?: 0,
                    1
                );
            } catch (Throwable) {
                $valid = false;
            }

            if (! $valid) {
                return ['error' => 'invalid_code'];
            }

            DB::table('mfa_recovery_codes')
                ->where('mfa_method_id', $method->id)
                ->delete();

            $codes = $this->generateRecoveryCodes();

            foreach ($codes as $code) {
                DB::table('mfa_recovery_codes')->insert([
                    'mfa_method_id' => $method->id,
                    'code_hash' => Hash::make($code),
                    'used_at' => null,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
            }

            DB::table('mfa_methods')
                ->where('id', $method->id)
                ->update([
                    'last_used_at' => now(),
                    'updated_at' => now(),
                ]);

            return ['codes' => $codes];
        });

        if (isset($result['error'])) {
            return response()->json([
                'message' => 'MFA is not enabled or the verification code is invalid.',
            ], 422);
        }

        $this->recordEvent(
            $request,
            $user->id,
            'auth.mfa.recovery_codes_regenerated',
            'success'
        );

        return response()->json([
            'message' => 'Recovery codes regenerated. Previous codes are no longer valid.',
            'recovery_codes' => $result['codes'],
        ]);
    }

    public function trustedDevices(Request $request): JsonResponse
    {
        $devices = DB::table('trusted_devices')
            ->where('user_id', $request->user()->id)
            ->whereNull('revoked_at')
            ->where('expires_at', '>', now())
            ->orderByDesc('last_used_at')
            ->get([
                'id',
                'public_id',
                'name',
                'ip_address',
                'user_agent',
                'last_used_at',
                'expires_at',
                'created_at',
            ]);

        return response()->json(['devices' => $devices]);
    }

    public function revokeTrustedDevice(Request $request, int $id): JsonResponse
    {
        $updated = DB::table('trusted_devices')
            ->where('id', $id)
            ->where('user_id', $request->user()->id)
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => now(),
                'updated_at' => now(),
            ]);

        if (! $updated) {
            return response()->json([
                'message' => 'Trusted device not found.',
            ], 404);
        }

        $this->recordEvent(
            $request,
            $request->user()->id,
            'auth.trusted_device.revoked',
            'success'
        );

        return response()->json([
            'message' => 'Trusted device revoked.',
        ]);
    }

    public function revokeAllTrustedDevices(Request $request): JsonResponse
    {
        $count = DB::table('trusted_devices')
            ->where('user_id', $request->user()->id)
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => now(),
                'updated_at' => now(),
            ]);

        $this->recordEvent(
            $request,
            $request->user()->id,
            'auth.trusted_devices.revoked_all',
            'success',
            ['count' => $count]
        );

        return response()->json([
            'message' => 'All trusted devices revoked.',
            'revoked_count' => $count,
        ]);
    }

    private function generateRecoveryCodes(): array
    {
        $codes = [];

        for ($i = 0; $i < self::RECOVERY_CODE_COUNT; $i++) {
            $codes[] = strtoupper(bin2hex(random_bytes(6)));
        }

        return $codes;
    }

    private function publicUser(User $user): array
    {
        return [
            'public_id' => $user->public_id,
            'name' => $user->name,
            'username' => $user->username,
            'email' => $user->email,
            'phone' => $user->phone,
            'status' => $user->status,
            'email_verified_at' => $user->email_verified_at,
        ];
    }

    private function recordEvent(
        Request $request,
        ?int $userId,
        string $eventType,
        string $result,
        array $context = []
    ): void {
        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $userId,
            'event_type' => $eventType,
            'result' => $result,
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit(
                (string) $request->userAgent(),
                1000,
                ''
            ),
            'request_id' => (string) Str::uuid(),
            'context' => json_encode($context),
            'occurred_at' => now(),
        ]);

        AuditLog::recordEntry($request, $userId ? User::query()->find($userId) : null, $eventType.'.'.$result, $context);
    }
}
