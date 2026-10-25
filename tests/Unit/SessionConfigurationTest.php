<?php

namespace Tests\Unit;

use Tests\TestCase;

class SessionConfigurationTest extends TestCase
{
    public function test_session_cookie_is_secure_by_default_in_production(): void
    {
        $this->assertTrue($this->sessionCookieSettingFor('production', 'secure'));
    }

    public function test_session_cookie_is_not_secure_by_default_in_local_development(): void
    {
        $this->assertFalse($this->sessionCookieSettingFor('local', 'secure'));
    }

    public function test_session_cookie_cannot_be_made_insecure_by_an_environment_override_in_production(): void
    {
        $this->assertTrue($this->sessionCookieSettingFor('production', 'secure', 'false'));
    }

    public function test_session_cookie_cannot_be_made_script_accessible_by_an_environment_override_in_production(): void
    {
        $this->assertTrue($this->sessionCookieSettingFor('production', 'http_only', 'false'));
    }

    public function test_session_cookie_is_http_only_by_default_in_production(): void
    {
        $this->assertTrue($this->sessionCookieSettingFor('production', 'http_only'));
    }

    private function sessionCookieSettingFor(string $appEnvironment, string $setting, ?string $override = null): bool
    {
        $environmentKeys = [
            'secure' => 'SESSION_SECURE_COOKIE',
            'http_only' => 'SESSION_HTTP_ONLY',
        ];
        $keys = ['APP_ENV', ...array_values($environmentKeys)];
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

            foreach ($environmentKeys as $key) {
                $this->unsetEnvironmentValue($key);
            }

            if ($override !== null) {
                $this->setEnvironmentValue($environmentKeys[$setting], $override);
            }

            $configuration = require dirname(__DIR__, 2).'/config/session.php';

            return $configuration[$setting];
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
