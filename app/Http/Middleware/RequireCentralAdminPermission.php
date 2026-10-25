<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class RequireCentralAdminPermission
{
    public function handle(Request $request, Closure $next, string $permission): Response
    {
        $grant = DB::table('central_admins')->where('user_id', $request->user()->id)
            ->whereNull('revoked_at')->first(['permissions']);
        $permissions = $grant ? json_decode((string) $grant->permissions, true) : [];

        if (! is_array($permissions) || (! in_array('*', $permissions, true) && ! in_array($permission, $permissions, true))) {
            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => $request->user()->id,
                'event_type' => 'admin.permission',
                'result' => 'blocked',
                'ip_address' => $request->ip(),
                'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
                'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
                'context' => json_encode([
                    'permission' => $permission,
                    'route' => $request->route()?->uri(),
                    'method' => $request->method(),
                ], JSON_THROW_ON_ERROR),
                'occurred_at' => now(),
            ]);

            abort(403);
        }

        return $next($request);
    }
}
