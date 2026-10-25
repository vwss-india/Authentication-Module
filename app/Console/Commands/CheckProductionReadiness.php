<?php

namespace App\Console\Commands;

use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Arr;

#[Signature('app:check-production-readiness')]
#[Description('Check production security configuration without displaying secret values or contacting external services.')]
class CheckProductionReadiness extends Command
{
    public function handle(): int
    {
        $url = parse_url((string) config('app.url'));
        $validAppUrl = is_array($url)
            && strtolower((string) ($url['scheme'] ?? '')) === 'https'
            && ! empty($url['host'])
            && ! isset($url['user'])
            && ! isset($url['pass'])
            && ! isset($url['fragment'])
            && ! in_array(strtolower($url['host']), ['localhost', '127.0.0.1', '[::1]'], true);
        $sameSite = strtolower((string) config('session.same_site'));
        $cors = (array) config('cors', []);
        $allowedOrigins = Arr::get($cors, 'allowed_origins', Arr::get($cors, 'allowedOrigins', []));
        $corsWildcard = is_array($allowedOrigins) && collect($allowedOrigins)->contains(
            fn (mixed $origin): bool => is_string($origin) && str_contains($origin, '*'),
        );
        $corsCredentials = (bool) Arr::get($cors, 'supports_credentials', Arr::get($cors, 'supportsCredentials', false));
        $trustedProxiesWildcard = (bool) config('security.trusted_proxies_wildcard', false);
        $trustedProxies = config('security.trusted_proxies', []);
        $trustedProxiesValid = is_array($trustedProxies)
            && collect($trustedProxies)->every(fn (mixed $proxy): bool => is_string($proxy) && $this->isValidProxyAddress($proxy));

        $checks = [
            'APP_ENV is production' => config('app.env') === 'production',
            'APP_DEBUG is disabled' => config('app.debug') === false,
            'APP_URL is an HTTPS origin' => $validAppUrl,
            'Session cookies are Secure' => config('session.secure') === true,
            'Session cookies are HttpOnly' => config('session.http_only') === true,
            'Session SameSite is Lax or Strict' => in_array($sameSite, ['lax', 'strict'], true),
            'Content Security Policy is enabled' => config('security.headers.csp_enabled') === true,
            'APP_KEY is configured (value suppressed)' => is_string(config('app.key')) && trim(config('app.key')) !== '',
            'CORS does not allow every origin' => ! $corsWildcard,
            'Credentialed CORS has an explicit origin allowlist' => ! $corsCredentials || (is_array($allowedOrigins) && $allowedOrigins !== [] && ! $corsWildcard),
            'Trusted proxy wildcard is disabled' => ! $trustedProxiesWildcard,
            'Trusted proxy entries are IP addresses or CIDRs' => $trustedProxiesValid,
        ];

        $failed = false;

        foreach ($checks as $name => $passed) {
            $this->line(sprintf('%s %s', $passed ? '<info>PASS</info>' : '<error>FAIL</error>', $name));
            $failed = $failed || ! $passed;
        }

        if ($trustedProxies === []) {
            $this->comment('TRUSTED_PROXIES is empty: forwarded headers are ignored. Confirm direct HTTPS termination or configure exact proxy IPs/CIDRs.');
        } else {
            $this->comment('Explicit trusted proxy entries are configured; verify them against the deployment network.');
        }

        if (Arr::get($cors, 'paths', []) === []) {
            $this->comment('No CORS paths are enabled; browser API access is same-origin only.');
        }

        $this->warn('Not verified by this command: live TLS/DNS, Passport and OIDC signing-key custody/permissions/rotation, SMTP inbox delivery, or external providers and relying-party clients.');

        return $failed ? self::FAILURE : self::SUCCESS;
    }

    private function isValidProxyAddress(string $proxy): bool
    {
        $parts = explode('/', $proxy, 2);
        $packedAddress = inet_pton($parts[0]);

        if ($packedAddress === false) {
            return false;
        }

        if (! isset($parts[1])) {
            return true;
        }

        if (! ctype_digit($parts[1])) {
            return false;
        }

        return (int) $parts[1] <= strlen($packedAddress) * 8;
    }
}
