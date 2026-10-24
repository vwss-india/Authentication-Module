<?php

namespace App\Http\Middleware;

use App\Models\AuditLog;
use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class RequireMfaChallenge
{
    public function handle(Request $request, Closure $next): Response
    {
        $email = Str::lower(trim((string) $request->input('email', '')));
        $password = (string) $request->input('password', '');

        if ($email === '' || $password === '') {
            return $next($request);
        }

        $user = User::query()
            ->whereRaw('LOWER(email) = ?', [$email])
            ->first();

        // Existing AuthController continues handling normal login failures.
        if (
            ! $user ||
            ! Hash::check($password, $user->password) ||
            $user->status !== 'active' ||
            $user->email_verified_at === null ||
            ($user->locked_until !== null && $user->locked_until->isFuture())
        ) {
            return $next($request);
        }

        $hasTotp = DB::table('mfa_methods')
            ->where('user_id', $user->id)
            ->where('type', 'totp')
            ->whereNotNull('verified_at')
            ->whereNull('revoked_at')
            ->exists();

        if (! $hasTotp) {
            return $next($request);
        }

        $trustedToken = trim((string) $request->input('trusted_device_token', ''));

        if ($trustedToken !== '') {
            $device = DB::table('trusted_devices')
                ->where('user_id', $user->id)
                ->where('token_hash', hash('sha256', $trustedToken))
                ->whereNull('revoked_at')
                ->where('expires_at', '>', now())
                ->first();

            if ($device) {
                DB::table('trusted_devices')
                    ->where('id', $device->id)
                    ->update([
                        'last_used_at' => now(),
                        'ip_address' => $request->ip(),
                        'updated_at' => now(),
                    ]);

                return $next($request);
            }
        }

        $challengeToken = bin2hex(random_bytes(32));

        DB::table('verification_challenges')->insert([
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

        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'event_type' => 'auth.mfa.challenge_issued',
            'result' => 'success',
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
            'request_id' => (string) Str::uuid(),
            'context' => json_encode(['method' => 'totp']),
            'occurred_at' => now(),
        ]);

        AuditLog::recordEntry($request, $user, 'auth.mfa.challenge_issued.success', ['method' => 'totp']);

        return response()->json([
            'message' => 'Two-factor authentication is required.',
            'mfa_required' => true,
            'challenge_token' => $challengeToken,
            'expires_in' => 300,
        ], 202);
    }
}
