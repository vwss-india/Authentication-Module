<?php

namespace App\Console\Commands;

use App\Models\AuditLog;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Throwable;

#[Signature('auth:product-credential:create {clientId} {--name=} {--reason=} {--expires-at=} {--force}')]
#[Description('Create a one-time product-server credential for an active product-bound OIDC client.')]
class CreateProductServerCredential extends Command
{
    public function handle(): int
    {
        $clientId = (string) $this->argument('clientId');
        $name = trim((string) $this->option('name'));
        $reason = trim((string) $this->option('reason'));
        $expiresAtValue = trim((string) $this->option('expires-at'));

        if (! Str::isUuid($clientId) || mb_strlen($name) < 3 || mb_strlen($name) > 100) {
            $this->error('Provide a valid client UUID and credential name of 3 to 100 characters.');

            return self::FAILURE;
        }

        if (mb_strlen($reason) < 5 || mb_strlen($reason) > 500) {
            $this->error('Provide an operator reason of 5 to 500 characters with --reason.');

            return self::FAILURE;
        }

        if (! preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/D', $expiresAtValue)) {
            $this->error('Provide --expires-at as a future RFC 3339 timestamp including its timezone.');

            return self::FAILURE;
        }

        try {
            $expiresAt = Carbon::parse($expiresAtValue)->utc();
        } catch (Throwable) {
            $this->error('The credential expiration timestamp is invalid.');

            return self::FAILURE;
        }

        if (! $expiresAt->isFuture() || $expiresAt->greaterThan(now()->addYear())) {
            $this->error('The credential expiration must be in the future and within one year.');

            return self::FAILURE;
        }

        $client = $this->eligibleClient($clientId);
        if (! $client) {
            $this->error('The client must be active, enabled, authorization-code capable, and bound to an active product with product_access scope.');

            return self::FAILURE;
        }

        if (! $this->option('force') && ! $this->confirm("Create a product-server credential for {$client->product_slug} / {$client->id}?")) {
            return self::FAILURE;
        }

        $credentialId = (string) Str::uuid();
        $secret = bin2hex(random_bytes(32));

        DB::transaction(function () use ($clientId, $client, $credentialId, $secret, $name, $reason, $expiresAt): void {
            $lockedClient = $this->eligibleClient($clientId, true);

            if (! $lockedClient || (int) $lockedClient->product_id !== (int) $client->product_id) {
                throw new \RuntimeException('The client product binding changed before credential creation.');
            }

            DB::table('product_api_credentials')->insert([
                'id' => $credentialId,
                'oauth_client_id' => $clientId,
                'product_id' => $client->product_id,
                'name' => $name,
                'secret_hash' => Hash::make($secret),
                'expires_at' => $expiresAt,
                'revoked_at' => null,
                'last_used_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            $request = Request::create('/console/product-credential', 'POST');
            AuditLog::recordEntry($request, null, 'product.server_credential.created', [
                'credential_id' => $credentialId,
                'credential_name' => $name,
                'oauth_client_id' => $clientId,
                'product_id' => (int) $client->product_id,
                'product_slug' => $client->product_slug,
                'expires_at' => $expiresAt->toIso8601String(),
                'reason' => $reason,
                'provisioning' => 'console',
            ]);

            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => null,
                'event_type' => 'product.server_credential.created',
                'result' => 'success',
                'ip_address' => null,
                'user_agent' => null,
                'request_id' => null,
                'context' => json_encode([
                    'credential_id' => $credentialId,
                    'oauth_client_id' => $clientId,
                    'product_slug' => $client->product_slug,
                    'expires_at' => $expiresAt->toIso8601String(),
                    'reason' => $reason,
                    'source' => 'console',
                ], JSON_THROW_ON_ERROR),
                'occurred_at' => now(),
            ]);
        });

        $this->info("Credential ID: {$credentialId}");
        $this->line("Credential secret (shown once): {$secret}");
        $this->warn('Copy the secret directly to the product secret manager now. It cannot be retrieved later; do not capture this output in logs.');

        return self::SUCCESS;
    }

    private function eligibleClient(string $clientId, bool $lock = false): ?object
    {
        $query = DB::table('oauth_clients as clients')
            ->join('oidc_client_metadata as settings', 'settings.oauth_client_id', '=', 'clients.id')
            ->join('products', 'products.id', '=', 'settings.product_id')
            ->where('clients.id', $clientId)
            ->where('clients.revoked', false)
            ->where('settings.enabled', true)
            ->where('products.status', 'active')
            ->select([
                'clients.id', 'clients.grant_types', 'settings.product_id',
                'settings.allowed_scopes', 'products.slug as product_slug',
            ]);

        if ($lock) {
            $query->lockForUpdate();
        }

        $client = $query->first();
        if (! $client
            || ! in_array('authorization_code', json_decode((string) $client->grant_types, true) ?: [], true)
            || ! in_array('product_access', json_decode((string) $client->allowed_scopes, true) ?: [], true)) {
            return null;
        }

        return $client;
    }
}
