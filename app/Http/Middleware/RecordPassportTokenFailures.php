<?php

namespace App\Http\Middleware;

use App\Models\AuditLog;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Passport\Exceptions\OAuthServerException;
use Symfony\Component\HttpFoundation\Response;

class RecordPassportTokenFailures
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $response = $next($request);

            if ($request->is('oauth/token') && $response->getStatusCode() >= 400) {
                $payload = json_decode($response->getContent(), true);

                if (in_array($payload['error'] ?? null, ['invalid_client', 'invalid_grant', 'unauthorized_client'], true)) {
                    $this->recordFailure($request);
                }
            }

            return $response;
        } catch (OAuthServerException $exception) {
            if (! $request->is('oauth/token')) {
                throw $exception;
            }

            $this->recordFailure($request);

            throw $exception;
        }
    }

    private function recordFailure(Request $request): void
    {
        $context = [
            'grant_type' => Str::limit((string) $request->input('grant_type'), 80, ''),
        ];
        $user = $request->user();

        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $user?->id,
            'event_type' => 'oauth.token',
            'result' => 'failure',
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
            'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
            'context' => json_encode($context, JSON_THROW_ON_ERROR),
            'occurred_at' => now(),
        ]);
        AuditLog::recordEntry($request, $user, 'oauth.token.failure', $context);
    }
}
