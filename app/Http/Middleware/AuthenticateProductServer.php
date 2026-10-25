<?php

namespace App\Http\Middleware;

use App\Services\ProductServerCredentialService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateProductServer
{
    public function __construct(private readonly ProductServerCredentialService $credentials) {}

    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $productServer = $this->credentials->authenticate($request);

        if (! $productServer) {
            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => null,
                'event_type' => 'auth.product_server',
                'result' => 'failure',
                'ip_address' => $request->ip(),
                'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
                'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
                'context' => json_encode(['reason' => 'invalid_product_server_credentials'], JSON_THROW_ON_ERROR),
                'occurred_at' => now(),
            ]);

            return response()->json(['error' => 'invalid_product_server_credentials'], 401)
                ->header('Cache-Control', 'no-store')
                ->header('WWW-Authenticate', 'VisionWebProduct realm="central-auth"');
        }

        $request->attributes->set('product_server', $productServer);

        $response = $next($request);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
