<?php

$trustedProxiesRaw = trim((string) env('TRUSTED_PROXIES', ''));
$trustedProxies = array_values(array_filter(array_map('trim', explode(',', $trustedProxiesRaw))));
$trustedProxyWildcard = count(array_intersect($trustedProxies, ['*', '**'])) > 0;

return [
    'trusted_proxies_raw' => $trustedProxiesRaw,
    'trusted_proxies' => $trustedProxyWildcard ? [] : $trustedProxies,
    'trusted_proxies_wildcard' => $trustedProxyWildcard,
    'headers' => [
        'csp_enabled' => filter_var(
            env('SECURITY_CSP_ENABLED', ! in_array(env('APP_ENV', 'production'), ['local', 'testing'], true)),
            FILTER_VALIDATE_BOOLEAN,
        ),
    ],
];
