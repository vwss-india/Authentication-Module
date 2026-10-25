<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Tests\TestCase;

class ProductionHardeningTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
    }

    public function test_security_headers_and_nonce_csp_allow_the_login_page_inline_script(): void
    {
        config(['security.headers.csp_enabled' => true]);

        $response = $this->get('/login')->assertOk();
        $policy = (string) $response->headers->get('Content-Security-Policy');
        preg_match("/'nonce-([A-Za-z0-9_-]+)'/", $policy, $policyNonce);
        preg_match_all('/<script\\b[^>]*\\bnonce="([A-Za-z0-9_-]+)"/', $response->getContent(), $scriptNonces);

        $response->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=()')
            ->assertHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        $this->assertNotEmpty($policyNonce);
        $this->assertNotEmpty($scriptNonces[1]);
        $this->assertSame([$policyNonce[1]], array_values(array_unique($scriptNonces[1])));
        $this->assertStringContainsString("style-src 'self'", $policy);
        $this->assertStringNotContainsString("'unsafe-inline'", $policy);
        $this->assertStringContainsString("frame-ancestors 'none'", $policy);
    }

    public function test_local_responses_do_not_receive_hsts_and_untrusted_forwarded_proto_is_ignored(): void
    {
        $response = $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.20'])
            ->withHeaders(['X-Forwarded-Proto' => 'https'])
            ->get('/up')
            ->assertOk();

        $this->assertFalse($response->headers->has('Strict-Transport-Security'));
    }

    public function test_cors_does_not_reflect_unconfigured_origins(): void
    {
        $response = $this->withHeaders([
            'Origin' => 'https://untrusted.example',
            'Access-Control-Request-Method' => 'POST',
        ])->options('/api/v1/auth/me');

        $this->assertFalse($response->headers->has('Access-Control-Allow-Origin'), json_encode($response->headers->all()));
        $this->assertFalse($response->headers->has('Access-Control-Allow-Credentials'), json_encode($response->headers->all()));
    }

    public function test_production_readiness_command_passes_safe_configuration_without_disclosing_keys(): void
    {
        $this->configureProductionEnvironment();
        config(['app.key' => 'deployment-key-value-must-not-be-printed']);

        $exitCode = Artisan::call('app:check-production-readiness');
        $output = Artisan::output();

        $this->assertSame(0, $exitCode, $output);
        $this->assertStringContainsString('APP_KEY is configured (value suppressed)', $output);
        $this->assertStringContainsString('Not verified by this command', $output);
        $this->assertStringNotContainsString('deployment-key-value-must-not-be-printed', $output);
    }

    public function test_production_readiness_command_fails_insecure_configuration_without_printing_values(): void
    {
        $this->configureProductionEnvironment();
        config([
            'app.debug' => true,
            'app.url' => 'http://localhost:8000',
            'session.secure' => false,
            'session.http_only' => false,
            'session.same_site' => 'none',
            'security.headers.csp_enabled' => false,
        ]);

        $exitCode = Artisan::call('app:check-production-readiness');
        $output = Artisan::output();

        $this->assertSame(1, $exitCode);
        $this->assertStringContainsString('FAIL APP_DEBUG is disabled', $output);
        $this->assertStringContainsString('FAIL Session cookies are Secure', $output);
        $this->assertStringNotContainsString('http://localhost:8000', $output);
    }

    public function test_production_readiness_command_rejects_wildcard_cors_origins(): void
    {
        $this->configureProductionEnvironment();
        config(['cors' => [
            'paths' => ['api/*'],
            'allowed_origins' => ['*'],
            'allowed_methods' => ['*'],
            'allowed_headers' => ['*'],
            'supports_credentials' => true,
        ]]);

        $exitCode = Artisan::call('app:check-production-readiness');
        $output = Artisan::output();

        $this->assertSame(1, $exitCode);
        $this->assertStringContainsString('FAIL CORS does not allow every origin', $output);
        $this->assertStringContainsString('FAIL Credentialed CORS has an explicit origin allowlist', $output);
    }

    public function test_production_readiness_command_rejects_non_ip_trusted_proxy_entries(): void
    {
        $this->configureProductionEnvironment();
        config(['security.trusted_proxies' => ['proxy.example.test']]);

        $exitCode = Artisan::call('app:check-production-readiness');
        $output = Artisan::output();

        $this->assertSame(1, $exitCode);
        $this->assertStringContainsString('FAIL Trusted proxy entries are IP addresses or CIDRs', $output);
        $this->assertStringNotContainsString('proxy.example.test', $output);
    }

    public function test_hsts_is_only_added_for_a_production_https_request(): void
    {
        $this->app->instance('env', 'production');
        config(['app.env' => 'production']);

        $response = $this->withServerVariables(['HTTPS' => 'on', 'SERVER_PORT' => '443'])
            ->get('https://central-auth.test/up')
            ->assertOk();

        $response->assertHeader('Strict-Transport-Security', 'max-age=31536000');
    }

    public function test_forwarded_https_is_trusted_only_from_a_configured_proxy(): void
    {
        $this->app->instance('env', 'production');
        config([
            'app.env' => 'production',
            'security.headers.csp_enabled' => false,
            'security.trusted_proxies' => ['192.0.2.55'],
        ]);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.55'])
            ->withHeaders(['X-Forwarded-Proto' => 'https'])
            ->get('/up')
            ->assertOk();

        $response->assertHeader('Strict-Transport-Security', 'max-age=31536000');
    }

    private function configureProductionEnvironment(): void
    {
        $this->app->instance('env', 'production');
        config([
            'app.env' => 'production',
            'app.debug' => false,
            'app.url' => 'https://central-auth.example.test',
            'app.key' => 'test-application-key',
            'session.secure' => true,
            'session.http_only' => true,
            'session.same_site' => 'lax',
            'security.headers.csp_enabled' => true,
            'security.trusted_proxies_wildcard' => false,
            'security.trusted_proxies' => [],
            'cors' => [],
        ]);
    }
}
