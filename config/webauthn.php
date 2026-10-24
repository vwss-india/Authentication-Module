<?php

$applicationUrl = rtrim((string) env('APP_URL', 'http://localhost'), '/');
$parsedApplicationUrl = parse_url($applicationUrl) ?: [];
$applicationHost = $parsedApplicationUrl['host'] ?? 'localhost';
$applicationOrigin = isset($parsedApplicationUrl['scheme'])
    ? $parsedApplicationUrl['scheme'].'://'.$applicationHost.(isset($parsedApplicationUrl['port']) ? ':'.$parsedApplicationUrl['port'] : '')
    : 'http://localhost';
$allowedOrigins = array_values(array_filter(array_map(
    'trim',
    explode(',', (string) env('WEBAUTHN_ALLOWED_ORIGINS', $applicationOrigin)),
)));

foreach ($allowedOrigins as $origin) {
    $parsedOrigin = parse_url($origin);
    $originHost = strtolower((string) ($parsedOrigin['host'] ?? ''));
    $isLoopback = $originHost === 'localhost'
        || str_ends_with($originHost, '.localhost')
        || $originHost === '::1'
        || (filter_var($originHost, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && str_starts_with($originHost, '127.'));

    if (! $parsedOrigin || ! isset($parsedOrigin['scheme'], $parsedOrigin['host'])
        || ($parsedOrigin['scheme'] !== 'https' && ! ($parsedOrigin['scheme'] === 'http' && $isLoopback))) {
        throw new InvalidArgumentException('WebAuthn origins must use HTTPS, except for localhost development.');
    }
}

return [
    'rp_name' => env('WEBAUTHN_RP_NAME', env('APP_NAME', 'VisionWeb Central Authentication')),
    'rp_id' => env('WEBAUTHN_RP_ID', $applicationHost),
    'allowed_origins' => $allowedOrigins,
    'challenge_expire_minutes' => 5,
];
