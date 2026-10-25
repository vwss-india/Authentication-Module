<?php

namespace App\Console\Commands;

use App\Models\AuditLog;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

#[Signature('auth:product-credential:revoke {credentialId} {--reason=} {--force}')]
#[Description('Revoke an active product-server credential.')]
class RevokeProductServerCredential extends Command
{
    public function handle(): int
    {
        $credentialId = (string) $this->argument('credentialId');
        $reason = trim((string) $this->option('reason'));

        if (! Str::isUuid($credentialId)) {
            $this->error('Provide a valid credential UUID.');

            return self::FAILURE;
        }

        if (mb_strlen($reason) < 5 || mb_strlen($reason) > 500) {
            $this->error('Provide an operator reason of 5 to 500 characters with --reason.');

            return self::FAILURE;
        }

        $credential = DB::table('product_api_credentials')->where('id', $credentialId)->first();
        if (! $credential || $credential->revoked_at !== null) {
            $this->error('The credential does not exist or has already been revoked.');

            return self::FAILURE;
        }

        if (! $this->option('force') && ! $this->confirm("Revoke product-server credential {$credentialId} for client {$credential->oauth_client_id}?")) {
            return self::FAILURE;
        }

        $revoked = DB::transaction(function () use ($credentialId, $reason): bool {
            $locked = DB::table('product_api_credentials')->where('id', $credentialId)->lockForUpdate()->first();
            if (! $locked || $locked->revoked_at !== null) {
                return false;
            }

            DB::table('product_api_credentials')->where('id', $credentialId)->update([
                'revoked_at' => now(),
                'updated_at' => now(),
            ]);

            $productSlug = DB::table('products')->where('id', $locked->product_id)->value('slug');
            $request = Request::create('/console/product-credential/revoke', 'POST');
            $details = [
                'credential_id' => $credentialId,
                'oauth_client_id' => $locked->oauth_client_id,
                'product_slug' => $productSlug,
                'reason' => $reason,
                'provisioning' => 'console',
            ];
            AuditLog::recordEntry($request, null, 'product.server_credential.revoked', $details);

            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => null,
                'event_type' => 'product.server_credential.revoked',
                'result' => 'success',
                'ip_address' => null,
                'user_agent' => null,
                'request_id' => null,
                'context' => json_encode($details, JSON_THROW_ON_ERROR),
                'occurred_at' => now(),
            ]);

            return true;
        });

        if (! $revoked) {
            $this->error('The credential was revoked by another operation before this request completed.');

            return self::FAILURE;
        }

        $this->info("Product-server credential {$credentialId} was revoked.");

        return self::SUCCESS;
    }
}
