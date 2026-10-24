<?php

use App\Models\User;

return [

    'defaults' => [
        'guard' => env('AUTH_GUARD', 'web'),
        'passwords' => env('AUTH_PASSWORD_BROKER', 'users'),
    ],

    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],

        'api' => [
            'driver' => 'passport',
            'provider' => 'users',
        ],
    ],

    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => env('AUTH_MODEL', User::class),
        ],
    ],

    'passwords' => [
        'users' => [
            'provider' => 'users',
            'table' => env('AUTH_PASSWORD_RESET_TOKEN_TABLE', 'password_reset_tokens'),
            'expire' => 60,
            'throttle' => 60,
        ],
    ],

    'password_timeout' => env('AUTH_PASSWORD_TIMEOUT', 10800),

    'phone_verification_expire_minutes' => env('PHONE_VERIFICATION_EXPIRE_MINUTES', 10),
    'oidc_access_token_expire_minutes' => env('OIDC_ACCESS_TOKEN_EXPIRE_MINUTES', 10),
    'oidc_id_token_expire_minutes' => env('OIDC_ID_TOKEN_EXPIRE_MINUTES', 5),
    'oidc_key_retention_minutes' => env('OIDC_KEY_RETENTION_MINUTES', 1440),
    'security_monitoring' => [
        'failed_login_threshold' => env('SECURITY_FAILED_LOGIN_THRESHOLD', 5),
        'window_minutes' => env('SECURITY_FAILED_LOGIN_WINDOW_MINUTES', 15),
        'alert_delivery_max_attempts' => env('SECURITY_ALERT_DELIVERY_MAX_ATTEMPTS', 3),
    ],

];
