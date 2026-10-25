<?php

namespace App\Http\Middleware;

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;

class ConfiguredTrustProxies extends TrustProxies
{
    /**
     * @return array<int, string>
     */
    protected function proxies(): array
    {
        return config('security.trusted_proxies', []);
    }

    protected function headers(): int
    {
        return Request::HEADER_X_FORWARDED_FOR
            | Request::HEADER_X_FORWARDED_HOST
            | Request::HEADER_X_FORWARDED_PORT
            | Request::HEADER_X_FORWARDED_PROTO;
    }
}
