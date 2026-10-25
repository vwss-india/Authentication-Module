<?php

$stringList = static fn (string $value): array => array_values(array_filter(array_map('trim', explode(',', $value))));

return [
    'paths' => $stringList((string) env('CORS_PATHS', '')),
    'allowed_methods' => $stringList((string) env('CORS_ALLOWED_METHODS', '')),
    'allowed_origins' => $stringList((string) env('CORS_ALLOWED_ORIGINS', '')),
    'allowed_origins_patterns' => [],
    'allowed_headers' => $stringList((string) env('CORS_ALLOWED_HEADERS', '')),
    'exposed_headers' => [],
    'max_age' => (int) env('CORS_MAX_AGE', 0),
    'supports_credentials' => filter_var(env('CORS_SUPPORTS_CREDENTIALS', false), FILTER_VALIDATE_BOOLEAN),
];
