<?php

namespace App\Http\Middleware;

use App\Models\AuditLog;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class RecordRateLimitEvent extends ThrottleRequests
{
    protected function buildException($request, $key, $maxAttempts, $responseCallback = null)
    {
        $user = $request->user();
        $context = ['route' => $request->route()?->uri()];

        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $user?->id,
            'event_type' => 'security.rate_limited',
            'result' => 'blocked',
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
            'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
            'context' => json_encode($context, JSON_THROW_ON_ERROR),
            'occurred_at' => now(),
        ]);
        AuditLog::recordEntry($request, $user, 'security.rate_limited.blocked', $context);

        return parent::buildException($request, $key, $maxAttempts, $responseCallback);
    }
}
