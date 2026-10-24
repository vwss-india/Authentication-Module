<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;

class RotateOidcSigningKey extends Command
{
    private array $keyGenerationErrors = [];

    protected $signature = 'oidc:keys:rotate';

    protected $description = 'Rotate the OIDC RS256 signing key and retain prior keys for existing ID tokens';

    public function handle(): int
    {
        $tokenLifetime = max(1, (int) config('auth.oidc_id_token_expire_minutes', 5));
        $retention = max(1, (int) config('auth.oidc_key_retention_minutes', 1440));

        if ($retention <= $tokenLifetime) {
            $this->error('OIDC key retention must exceed the configured ID token lifetime.');

            return self::FAILURE;
        }

        $privateKey = $this->newRsaKey();

        if (! $privateKey || ! openssl_pkey_export($privateKey, $privatePem, null, $this->openSslOptions())) {
            $this->error('Unable to create an OIDC signing key.'.($this->keyGenerationErrors ? ' OpenSSL: '.implode('; ', $this->keyGenerationErrors) : ''));

            return self::FAILURE;
        }

        $details = openssl_pkey_get_details($privateKey);
        if (! is_array($details) || ! isset($details['key'])) {
            $this->error('Unable to read the OIDC public key.');

            return self::FAILURE;
        }

        $publicPem = $details['key'];
        $keyId = bin2hex(substr(hash('sha256', $publicPem, true), 0, 16));
        $now = now();

        DB::transaction(function () use ($now, $retention, $keyId, $privatePem, $publicPem): void {
            DB::table('oidc_signing_keys')
                ->whereNull('retired_at')
                ->where(function ($query): void {
                    $query->whereNull('expires_at')->orWhere('expires_at', '>', now());
                })
                ->update([
                    'expires_at' => $now->copy()->addMinutes($retention),
                    'updated_at' => $now,
                ]);

            DB::table('oidc_signing_keys')->insert([
                'key_id' => $keyId,
                'algorithm' => 'RS256',
                'public_key_pem' => $publicPem,
                'private_key_encrypted' => Crypt::encryptString($privatePem),
                'not_before' => $now,
                'expires_at' => null,
                'retired_at' => null,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
        });

        $this->info('OIDC signing key rotated; prior verification keys remain published during the configured retention window.');

        return self::SUCCESS;
    }

    private function newRsaKey(): false|\OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new($this->openSslOptions() + [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if ($key) {
            return $key;
        }
        $this->collectOpenSslErrors();

        return false;
    }

    private function openSslOptions(): array
    {
        $configuredPath = getenv('OPENSSL_CONF');
        $xamppConfig = dirname(PHP_BINARY).DIRECTORY_SEPARATOR.'extras'.DIRECTORY_SEPARATOR.'ssl'.DIRECTORY_SEPARATOR.'openssl.cnf';
        $configPath = is_string($configuredPath) && is_file($configuredPath) ? $configuredPath : $xamppConfig;

        return is_file($configPath) ? ['config' => $configPath] : [];
    }

    private function collectOpenSslErrors(): void
    {
        while (($error = openssl_error_string()) !== false) {
            $this->keyGenerationErrors[] = $error;
        }
    }
}
