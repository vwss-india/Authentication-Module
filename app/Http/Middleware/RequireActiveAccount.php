<?php

namespace App\Http\Middleware;

use App\Models\AuditLog;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class RequireActiveAccount
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if ($user->status === 'active' && $user->email_verified_at !== null) {
            return $next($request);
        }

        $token = $user->token();

        if ($token) {
            DB::transaction(function () use ($token): void {
                DB::table('oauth_refresh_tokens')
                    ->where('access_token_id', $token->id)
                    ->where('revoked', false)
                    ->update(['revoked' => true]);

                $token->revoke();
            });
        }

        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'event_type' => 'auth.inactive_account_access',
            'result' => 'blocked',
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 1000),
            'request_id' => Str::limit(
                (string) $request->header('X-Request-ID'),
                100
            ) ?: null,
            'context' => json_encode([
                'status' => $user->status,
                'email_verified' => $user->email_verified_at !== null,
            ], JSON_THROW_ON_ERROR),
            'occurred_at' => now(),
        ]);

        AuditLog::recordEntry($request, $user, 'auth.inactive_account_access.blocked', [
            'status' => $user->status,
            'email_verified' => $user->email_verified_at !== null,
        ]);

        return response()->json([
            'message' => 'This account is not active or its email is not verified.',
        ], 403);
    }
}
