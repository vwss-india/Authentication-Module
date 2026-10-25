<?php

namespace App\Http\Middleware;

use App\Services\ProductAccessService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class RequireProductAccess
{
    public function handle(Request $request, Closure $next, string $productSlug, string $permission, string $feature = 'access'): Response
    {
        $organizationPublicId = (string) $request->route('organization');
        $decision = app(ProductAccessService::class)->decide(
            $request->user(), $productSlug, $organizationPublicId, $feature, $permission
        );

        if (! $decision['allowed']) {
            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => $request->user()->id,
                'event_type' => 'product.access',
                'result' => 'blocked',
                'ip_address' => $request->ip(),
                'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
                'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
                'context' => json_encode([
                    'product' => $productSlug,
                    'organization' => $organizationPublicId,
                    'feature' => $feature,
                    'permission' => $permission,
                    'reason' => $decision['reason'],
                ], JSON_THROW_ON_ERROR),
                'occurred_at' => now(),
            ]);
            abort(403);
        }

        return $next($request);
    }
}
