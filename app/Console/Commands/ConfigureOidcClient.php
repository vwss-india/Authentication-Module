<?php

namespace App\Console\Commands;

use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

#[Signature('oidc:client:configure {clientId} {--client-type=confidential} {--subject-type=public} {--scopes=openid,profile,email} {--product=} {--logout-redirects=} {--disabled}')]
#[Description('Configure OIDC metadata for an existing Passport authorization-code client.')]
class ConfigureOidcClient extends Command
{
    public function handle(): int
    {
        $clientId = (string) $this->argument('clientId');
        $client = DB::table('oauth_clients')->where('id', $clientId)->first();

        if (! $client || $client->revoked) {
            $this->error('The Passport client does not exist or is revoked.');

            return self::FAILURE;
        }

        $grantTypes = json_decode((string) $client->grant_types, true) ?: [];

        if (! in_array('authorization_code', $grantTypes, true)) {
            $this->error('The Passport client must support the authorization-code grant.');

            return self::FAILURE;
        }

        $clientType = (string) $this->option('client-type');
        $subjectType = (string) $this->option('subject-type');
        $scopes = array_values(array_unique(array_filter(explode(',', (string) $this->option('scopes')))));
        $productSlug = trim((string) $this->option('product'));
        $logoutRedirects = array_values(array_unique(array_filter(explode(',', (string) $this->option('logout-redirects')))));

        if (! in_array($clientType, ['confidential', 'public'], true)) {
            $this->error('The client type must be confidential or public.');

            return self::FAILURE;
        }

        if (($clientType === 'confidential' && ! $client->secret)
            || ($clientType === 'public' && $client->secret)) {
            $this->error('The selected client type does not match the Passport client secret configuration.');

            return self::FAILURE;
        }

        if (! in_array($subjectType, ['public', 'pairwise'], true)) {
            $this->error('The subject type must be public or pairwise.');

            return self::FAILURE;
        }

        if (! in_array('openid', $scopes, true) || array_diff($scopes, ['openid', 'profile', 'email', 'phone', 'product_access'])) {
            $this->error('Scopes must include openid and use only supported OIDC scopes.');

            return self::FAILURE;
        }

        $product = null;
        if (in_array('product_access', $scopes, true) || $productSlug !== '') {
            if ($productSlug === '') {
                $this->error('A product slug is required when enabling the product_access scope.');

                return self::FAILURE;
            }

            $product = DB::table('products')->where('slug', $productSlug)->where('status', 'active')->first();

            if (! $product) {
                $this->error('The product does not exist or is not active.');

                return self::FAILURE;
            }
        }

        foreach ($logoutRedirects as $redirectUri) {
            if (! $this->isSafeRedirectUri($redirectUri)) {
                $this->error('Every post-logout redirect must use HTTPS or a localhost HTTP origin.');

                return self::FAILURE;
            }
        }

        DB::table('oidc_client_metadata')->updateOrInsert(
            ['oauth_client_id' => $clientId],
            [
                'client_type' => $clientType,
                'product_id' => $product?->id,
                'application_type' => 'web',
                'subject_type' => $subjectType,
                'allowed_scopes' => json_encode($scopes, JSON_THROW_ON_ERROR),
                'post_logout_redirect_uris' => json_encode($logoutRedirects, JSON_THROW_ON_ERROR),
                'allowed_origins' => json_encode([], JSON_THROW_ON_ERROR),
                'require_pkce' => true,
                'require_consent' => true,
                'enabled' => ! $this->option('disabled'),
                'created_at' => now(),
                'updated_at' => now(),
            ]
        );

        $this->info('OIDC client metadata saved.');

        return self::SUCCESS;
    }

    private function isSafeRedirectUri(string $uri): bool
    {
        $parts = parse_url($uri);

        if (! is_array($parts) || empty($parts['host']) || isset($parts['fragment'])) {
            return false;
        }

        if (($parts['scheme'] ?? null) === 'https') {
            return true;
        }

        return ($parts['scheme'] ?? null) === 'http'
            && in_array(strtolower($parts['host']), ['localhost', '127.0.0.1', '[::1]'], true);
    }
}
