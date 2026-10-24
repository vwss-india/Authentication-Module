<?php

namespace Tests\Unit;

use InvalidArgumentException;
use Tests\TestCase;

class WebAuthnConfigurationTest extends TestCase
{
    public function test_non_tls_webauthn_origins_are_rejected_outside_localhost(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->loadConfigurationWithOrigin('http://auth.example.test');
    }

    public function test_localhost_http_origin_is_allowed_for_local_development(): void
    {
        $configuration = $this->loadConfigurationWithOrigin('http://localhost:8000');

        $this->assertSame(['http://localhost:8000'], $configuration['allowed_origins']);
    }

    private function loadConfigurationWithOrigin(string $origin): array
    {
        $keys = ['APP_URL', 'WEBAUTHN_ALLOWED_ORIGINS'];
        $original = [];

        foreach ($keys as $key) {
            $original[$key] = [
                'server' => $_SERVER[$key] ?? null,
                'server_exists' => array_key_exists($key, $_SERVER),
                'env' => $_ENV[$key] ?? null,
                'env_exists' => array_key_exists($key, $_ENV),
                'process' => getenv($key),
            ];
        }

        try {
            foreach ($keys as $key) {
                $_SERVER[$key] = $key === 'APP_URL' ? 'http://localhost' : $origin;
                $_ENV[$key] = $key === 'APP_URL' ? 'http://localhost' : $origin;
                putenv($key.'='.$_SERVER[$key]);
            }

            return require dirname(__DIR__, 2).'/config/webauthn.php';
        } finally {
            foreach ($original as $key => $values) {
                if ($values['server_exists']) {
                    $_SERVER[$key] = $values['server'];
                } else {
                    unset($_SERVER[$key]);
                }

                if ($values['env_exists']) {
                    $_ENV[$key] = $values['env'];
                } else {
                    unset($_ENV[$key]);
                }

                $values['process'] === false ? putenv($key) : putenv($key.'='.$values['process']);
            }
        }
    }
}
