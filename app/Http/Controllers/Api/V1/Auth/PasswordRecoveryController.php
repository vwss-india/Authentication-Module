<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class PasswordRecoveryController extends Controller
{
    public function forgot(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'string', 'email', 'max:254'],
        ]);

        // Do not reveal whether an account exists.
        $user = User::query()
            ->where('email', $validated['email'])
            ->where('status', 'active')
            ->first();

        if ($user !== null) {
            Password::broker('users')->sendResetLink([
                'email' => $user->email,
            ]);
        }

        return response()->json([
            'message' => 'If an eligible account exists, password reset instructions will be sent.',
        ], 202);
    }

    public function reset(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'string', 'email', 'max:254'],
            'token' => ['required', 'string', 'max:512'],
            'password' => [
                'required',
                'string',
                'min:12',
                'confirmed',
                'max:128',
            ],
        ]);

        $status = Password::broker('users')->reset(
            [
                'email' => $validated['email'],
                'token' => $validated['token'],

                // Required by Laravel's password broker.
                'password' => $validated['password'],
            ],
            function (User $user, string $password) use ($request): void {
                if ($user->status !== 'active') {
                    throw ValidationException::withMessages([
                        'email' => [
                            'Password reset is not available for this account.',
                        ],
                    ]);
                }

                DB::transaction(function () use (
                    $user,
                    $password,
                    $request
                ): void {
                    $user->forceFill([
                        'password' => $password,
                        'password_changed_at' => now(),
                        'force_password_change' => false,
                        'remember_token' => Str::random(60),
                    ])->save();

                    DB::table('verification_challenges')
                        ->where('user_id', $user->id)
                        ->where('purpose', 'login_mfa')
                        ->whereNull('consumed_at')
                        ->update([
                            'consumed_at' => now(),
                            'updated_at' => now(),
                        ]);

                    // Revoke existing active access tokens and their
                    // associated refresh tokens.
                    $accessTokenIds = DB::table('oauth_access_tokens')
                        ->where('user_id', $user->id)
                        ->where('revoked', false)
                        ->pluck('id');

                    if ($accessTokenIds->isNotEmpty()) {
                        DB::table('oauth_refresh_tokens')
                            ->whereIn('access_token_id', $accessTokenIds)
                            ->where('revoked', false)
                            ->update(['revoked' => true]);

                        DB::table('oauth_access_tokens')
                            ->whereIn('id', $accessTokenIds)
                            ->update([
                                'revoked' => true,
                                'updated_at' => now(),
                            ]);
                    }

                    // Invalidate database-backed sessions.
                    DB::table('sessions')
                        ->where('user_id', $user->id)
                        ->delete();

                    DB::table('trusted_devices')
                        ->where('user_id', $user->id)
                        ->whereNull('revoked_at')
                        ->update([
                            'revoked_at' => now(),
                            'updated_at' => now(),
                        ]);

                    // Record the security event without credentials,
                    // reset tokens, or passwords.
                    DB::table('security_events')->insert([
                        'event_id' => (string) Str::uuid(),
                        'user_id' => $user->id,
                        'event_type' => 'password_reset',
                        'result' => 'success',
                        'ip_address' => $request->ip(),
                        'user_agent' => Str::limit(
                            (string) $request->userAgent(),
                            1000
                        ),
                        'request_id' => null,
                        'context' => json_encode([
                            'method' => 'email_token',
                        ]),
                        'occurred_at' => now(),
                    ]);

                    AuditLog::recordEntry($request, $user, 'auth.password_reset.success', [
                        'method' => 'email_token',
                    ]);
                });
            }
        );

        if ($status !== Password::PASSWORD_RESET) {
            return response()->json([
                'message' => 'The password reset token is invalid or expired.',
            ], 422);
        }

        return response()->json([
            'message' => 'Password reset successfully. Please sign in again.',
        ]);
    }
}
