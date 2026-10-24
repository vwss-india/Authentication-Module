<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use App\Notifications\AuthEmailVerificationNotification;
use App\Notifications\AuthPhoneVerificationNotification;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function register(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:150'],
            'username' => [
                'nullable', 'string', 'max:80', 'alpha_dash',
                'unique:users,username',
            ],
            'email' => ['required', 'string', 'email', 'max:254', 'unique:users,email'],
            'phone' => ['nullable', 'string', 'max:20', 'unique:users,phone'],
            'password' => ['required', 'string', 'min:12', 'max:128', 'confirmed'],
        ]);

        $user = new User;
        $user->name = $data['name'];
        $user->username = $data['username'] ?? null;
        $user->email = mb_strtolower($data['email']);
        $user->phone = $data['phone'] ?? null;
        $user->password = $data['password'];
        // New accounts require email verification before sign-in.
        $user->status = 'pending';
        $user->save();

        $this->issueVerification($user);

        $this->event($request, $user, 'auth.register', 'success');

        return response()->json([
            'message' => 'Registration received. Verify your email before signing in.',
            'user' => $this->publicUser($user->fresh()),
        ], 201);
    }

    public function login(Request $request): JsonResponse
    {
        $data = $request->validate([
            'email' => ['required', 'string', 'email', 'max:254'],
            'password' => ['required', 'string', 'max:128'],
            'device_name' => ['nullable', 'string', 'max:100'],
        ]);

        $user = User::query()
            ->where('email', mb_strtolower($data['email']))
            ->first();

        if ($user && $user->locked_until) {
            if ($user->locked_until->isFuture()) {
                $this->event($request, $user, 'auth.login', 'blocked', [
                    'reason' => 'account_locked',
                ]);

                return response()->json([
                    'message' => 'Sign-in is temporarily unavailable. Try again later.',
                ], 423);
            }

            // An expired lockout starts a fresh attempt window.
            $user->forceFill([
                'failed_login_attempts' => 0,
                'locked_until' => null,
            ])->save();
        }

        if (! $user || ! Hash::check($data['password'], $user->password)) {
            if ($user) {
                $attempts = (int) $user->failed_login_attempts + 1;

                $user->forceFill([
                    'failed_login_attempts' => $attempts,
                    'locked_until' => $attempts >= 5
                        ? now()->addMinutes(15)
                        : $user->locked_until,
                ])->save();

                $this->event($request, $user, 'auth.login', 'failure', [
                    'reason' => 'invalid_credentials',
                ]);
            } else {
                // Do not disclose whether an email exists.
                $this->event($request, null, 'auth.login', 'failure', [
                    'reason' => 'invalid_credentials',
                ]);
            }

            return response()->json([
                'message' => 'The supplied credentials are invalid.',
            ], 401);
        }

        if ($user->status !== 'active' || ! $user->email_verified_at) {
            $this->event($request, $user, 'auth.login', 'blocked', [
                'reason' => 'account_not_active_or_unverified',
            ]);

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

        // Requires a configured Passport Personal Access Client.
        $token = $user->createToken(
            $data['device_name'] ?? 'VisionWeb Central Auth'
        );

        $this->event($request, $user, 'auth.login', 'success');

        return response()->json([
            'token_type' => 'Bearer',
            'access_token' => $token->accessToken,
            'expires_at' => $token->token->expires_at?->toISOString(),
            'user' => $this->publicUser($user->fresh()),
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        $user = $request->user();
        $token = $user?->token();

        if ($token) {
            DB::transaction(function () use ($token): void {
                DB::table('oauth_refresh_tokens')
                    ->where('access_token_id', $token->id)
                    ->where('revoked', false)
                    ->update(['revoked' => true]);

                $token->revoke();
            });
        }

        $this->event($request, $user, 'auth.logout', 'success');

        return response()->json([
            'message' => 'Signed out successfully.',
        ]);
    }

    public function logoutAll(Request $request): JsonResponse
    {
        $user = $request->user();

        DB::transaction(function () use ($user): void {
            $tokenIds = DB::table('oauth_access_tokens')
                ->where('user_id', $user->getAuthIdentifier())
                ->where('revoked', false)
                ->pluck('id');

            if ($tokenIds->isNotEmpty()) {
                DB::table('oauth_refresh_tokens')
                    ->whereIn('access_token_id', $tokenIds)
                    ->where('revoked', false)
                    ->update(['revoked' => true]);

                DB::table('oauth_access_tokens')
                    ->whereIn('id', $tokenIds)
                    ->update([
                        'revoked' => true,
                        'updated_at' => now(),
                    ]);
            }

            DB::table('oidc_access_tokens')
                ->where('user_id', $user->getAuthIdentifier())
                ->whereNull('revoked_at')
                ->update(['revoked_at' => now(), 'updated_at' => now()]);

            DB::table('sessions')
                ->where('user_id', $user->getAuthIdentifier())
                ->delete();
        });

        $this->event($request, $user, 'auth.logout_all', 'success');

        return response()->json([
            'message' => 'All sessions have been signed out.',
        ]);
    }

    public function me(Request $request): JsonResponse
    {
        return response()->json([
            'user' => $this->publicUser($request->user()),
        ]);
    }

    public function resendVerification(Request $request): JsonResponse
    {
        $data = $request->validate([
            'email' => ['required', 'string', 'email', 'max:254'],
        ]);

        $user = User::query()
            ->where('email', mb_strtolower($data['email']))
            ->where('status', 'pending')
            ->whereNull('email_verified_at')
            ->first();

        if ($user) {
            $this->issueVerification($user);
        }

        return response()->json([
            'message' => 'If an unverified account exists, verification instructions will be sent.',
        ], 202);
    }

    public function requestPhoneVerification(Request $request): JsonResponse
    {
        $user = $request->user();

        if (! $user->phone) {
            return response()->json([
                'message' => 'Add a phone number before requesting verification.',
            ], 422);
        }

        if ($user->phone_verified_at !== null) {
            return response()->json([
                'message' => 'This phone number is already verified.',
            ], 409);
        }

        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);

        DB::transaction(function () use ($user, $code): void {
            DB::table('verification_challenges')
                ->where('user_id', $user->id)
                ->where('purpose', 'phone_verification')
                ->whereNull('consumed_at')
                ->update([
                    'consumed_at' => now(),
                    'updated_at' => now(),
                ]);

            DB::table('verification_challenges')->insert([
                'user_id' => $user->id,
                'channel' => 'email',
                'purpose' => 'phone_verification',
                'destination' => $user->phone,
                'token_hash' => Hash::make($code),
                'attempts' => 0,
                'expires_at' => now()->addMinutes(
                    (int) config('auth.phone_verification_expire_minutes', 10)
                ),
                'consumed_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        });

        $user->notify(new AuthPhoneVerificationNotification($code));

        $this->event($request, $user, 'auth.phone_verification', 'requested', [
            'delivery_channel' => 'email',
        ]);

        return response()->json([
            'message' => 'Phone verification instructions were sent to your account email.',
        ], 202);
    }

    public function verifyPhone(Request $request): JsonResponse
    {
        $data = $request->validate([
            'code' => ['required', 'digits:6'],
        ]);

        $user = $request->user();

        if (! $user->phone || $user->phone_verified_at !== null) {
            return response()->json([
                'message' => 'The phone verification code is invalid or expired.',
            ], 422);
        }

        $challenge = DB::table('verification_challenges')
            ->where('user_id', $user->id)
            ->where('channel', 'email')
            ->where('purpose', 'phone_verification')
            ->where('destination', $user->phone)
            ->whereNull('consumed_at')
            ->where('expires_at', '>', now())
            ->where('attempts', '<', 5)
            ->orderByDesc('id')
            ->first();

        if (! $challenge || ! Hash::check($data['code'], $challenge->token_hash)) {
            if ($challenge) {
                $attempts = (int) $challenge->attempts + 1;

                DB::table('verification_challenges')
                    ->where('id', $challenge->id)
                    ->update([
                        'attempts' => $attempts,
                        'consumed_at' => $attempts >= 5 ? now() : null,
                        'updated_at' => now(),
                    ]);
            }

            $this->event($request, $user, 'auth.phone_verification', 'failure');

            return response()->json([
                'message' => 'The phone verification code is invalid or expired.',
            ], 422);
        }

        DB::transaction(function () use ($challenge, $user): void {
            $consumed = DB::table('verification_challenges')
                ->where('id', $challenge->id)
                ->whereNull('consumed_at')
                ->where('expires_at', '>', now())
                ->where('attempts', '<', 5)
                ->update([
                    'consumed_at' => now(),
                    'updated_at' => now(),
                ]);

            if ($consumed !== 1) {
                throw ValidationException::withMessages([
                    'code' => ['The phone verification code has already been used.'],
                ]);
            }

            $user->forceFill(['phone_verified_at' => now()])->save();
        });

        $this->event($request, $user, 'auth.phone_verification', 'success', [
            'delivery_channel' => 'email',
        ]);

        return response()->json([
            'message' => 'Phone number verified successfully.',
            'user' => $this->publicUser($user->fresh()),
        ]);
    }

    public function verifyEmail(Request $request): JsonResponse
    {
        $data = $request->validate([
            'email' => ['required', 'string', 'email', 'max:254'],
            'token' => ['required', 'string', 'max:128'],
        ]);

        $user = User::query()
            ->where('email', mb_strtolower($data['email']))
            ->where('status', 'pending')
            ->whereNull('email_verified_at')
            ->first();

        if (! $user) {
            return response()->json([
                'message' => 'The verification token is invalid or expired.',
            ], 422);
        }

        $challenge = DB::table('verification_challenges')
            ->where('user_id', $user->id)
            ->where('channel', 'email')
            ->where('purpose', 'email_verification')
            ->where('destination', $user->email)
            ->whereNull('consumed_at')
            ->where('expires_at', '>', now())
            ->where('attempts', '<', 5)
            ->orderByDesc('id')
            ->first();

        if (! $challenge || ! Hash::check($data['token'], $challenge->token_hash)) {
            if ($challenge) {
                $attempts = (int) $challenge->attempts + 1;

                DB::table('verification_challenges')
                    ->where('id', $challenge->id)
                    ->update([
                        'attempts' => $attempts,
                        'consumed_at' => $attempts >= 5 ? now() : null,
                        'updated_at' => now(),
                    ]);
            }

            $this->event($request, $user, 'auth.email_verification', 'failure');

            return response()->json([
                'message' => 'The verification token is invalid or expired.',
            ], 422);
        }

        DB::transaction(function () use ($challenge, $user): void {
            $consumed = DB::table('verification_challenges')
                ->where('id', $challenge->id)
                ->whereNull('consumed_at')
                ->where('attempts', '<', 5)
                ->update([
                    'consumed_at' => now(),
                    'updated_at' => now(),
                ]);

            if ($consumed !== 1) {
                throw ValidationException::withMessages([
                    'token' => ['The verification token has already been used.'],
                ]);
            }

            $user->forceFill([
                'email_verified_at' => now(),
                'status' => 'active',
            ])->save();
        });

        $this->event($request, $user, 'auth.email_verification', 'success');

        return response()->json([
            'message' => 'Email verified successfully. You can now sign in.',
            'user' => $this->publicUser($user->fresh()),
        ]);
    }

    private function issueVerification(User $user): void
    {
        $token = Str::random(64);

        DB::transaction(function () use ($user, $token): void {
            DB::table('verification_challenges')
                ->where('user_id', $user->id)
                ->where('purpose', 'email_verification')
                ->whereNull('consumed_at')
                ->update([
                    'consumed_at' => now(),
                    'updated_at' => now(),
                ]);

            DB::table('verification_challenges')->insert([
                'user_id' => $user->id,
                'channel' => 'email',
                'purpose' => 'email_verification',
                'destination' => $user->email,
                'token_hash' => Hash::make($token),
                'attempts' => 0,
                'expires_at' => now()->addMinutes(30),
                'consumed_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        });

        $user->notify(new AuthEmailVerificationNotification($token));
    }

    private function publicUser(?User $user): ?array
    {
        if (! $user) {
            return null;
        }

        return [
            'public_id' => $user->public_id,
            'name' => $user->name,
            'username' => $user->username,
            'email' => $user->email,
            'phone' => $user->phone,
            'status' => $user->status,
            'email_verified_at' => $user->email_verified_at?->toISOString(),
            'phone_verified_at' => $user->phone_verified_at?->toISOString(),
        ];
    }

    private function event(
        Request $request,
        ?User $user,
        string $type,
        string $result,
        array $context = [],
    ): void {
        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $user?->id,
            'event_type' => $type,
            'result' => $result,
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 1000),
            'request_id' => Str::limit(
                (string) $request->header('X-Request-ID'),
                100
            ) ?: null,
            'context' => json_encode($context, JSON_THROW_ON_ERROR),
            'occurred_at' => now(),
        ]);

        AuditLog::recordEntry($request, $user, $type.'.'.$result, $context);
    }
}
