<?php

namespace Tests\Unit;

use Tests\TestCase;

class SessionConfigurationTest extends TestCase
{
    public function test_session_cookie_is_secure_by_default_in_production(): void
    {
        $this->assertTrue($this->secureCookieSettingFor('production'));
    }

    public function test_session_cookie_is_not_secure_by_default_in_local_development(): void
    {
        $this->assertFalse($this->secureCookieSettingFor('local'));
    }

    private function secureCookieSettingFor(string $appEnvironment): bool
    {
        $keys = ['APP_ENV', 'SESSION_SECURE_COOKIE'];
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
            $this->setEnvironmentValue('APP_ENV', $appEnvironment);
            $this->unsetEnvironmentValue('SESSION_SECURE_COOKIE');

            $configuration = require dirname(__DIR__, 2).'/config/session.php';

            return $configuration['secure'];
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

                $values['process'] === false
                    ? putenv($key)
                    : putenv($key.'='.$values['process']);
            }
        }
    }

    private function setEnvironmentValue(string $key, string $value): void
    {
        $_SERVER[$key] = $value;
        $_ENV[$key] = $value;
        putenv($key.'='.$value);
    }

    private function unsetEnvironmentValue(string $key): void
    {
        unset($_SERVER[$key], $_ENV[$key]);
        putenv($key);
    }
}
