<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class RequireCentralAdmin
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();
        $grant = $user ? DB::table('central_admins')->where('user_id', $user->id)
            ->whereNull('revoked_at')->first(['permissions']) : null;

        if (
            ! $user
            || $user->status !== 'active'
            || ! $user->email_verified_at
            || ! $grant
        ) {
            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => $user?->id,
                'event_type' => 'admin.access',
                'result' => 'blocked',
                'ip_address' => $request->ip(),
                'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
                'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
                'context' => json_encode([
                    'route' => $request->route()?->uri(),
                    'method' => $request->method(),
                ], JSON_THROW_ON_ERROR),
                'occurred_at' => now(),
            ]);

            abort(403);
        }

        $request->attributes->set('central_admin_permissions', json_decode((string) $grant->permissions, true) ?: []);

        return $next($request);
    }
}
