<?php

namespace App\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Throwable;

class ProductServerCredentialService
{
    public function authenticate(Request $request): ?object
    {
        $credentialId = (string) $request->header('X-VisionWeb-Product-Credential', '');
        $secret = (string) $request->header('X-VisionWeb-Product-Secret', '');

        if (! Str::isUuid($credentialId) || ! preg_match('/\A[a-f0-9]{64}\z/D', $secret)) {
            return null;
        }

        return DB::transaction(function () use ($credentialId, $secret): ?object {
            $credential = DB::table('product_api_credentials as credentials')
                ->join('oauth_clients as clients', 'clients.id', '=', 'credentials.oauth_client_id')
                ->join('oidc_client_metadata as settings', 'settings.oauth_client_id', '=', 'clients.id')
                ->join('products', 'products.id', '=', 'credentials.product_id')
                ->where('credentials.id', $credentialId)
                ->whereColumn('settings.product_id', 'credentials.product_id')
                ->where('clients.revoked', false)
                ->where('settings.enabled', true)
                ->where('products.status', 'active')
                ->whereNull('credentials.revoked_at')
                ->where('credentials.expires_at', '>', now())
                ->lockForUpdate()
                ->first([
                    'credentials.id as credential_id',
                    'credentials.secret_hash',
                    'credentials.oauth_client_id',
                    'credentials.product_id',
                    'clients.grant_types',
                    'products.slug as product_slug',
                    'settings.allowed_scopes',
                ]);

            if (! $credential) {
                return null;
            }

            if (! in_array('authorization_code', json_decode((string) $credential->grant_types, true) ?: [], true)) {
                return null;
            }

            $scopes = json_decode((string) $credential->allowed_scopes, true) ?: [];

            if (! in_array('product_access', $scopes, true)) {
                return null;
            }

            try {
                if (! Hash::check($secret, $credential->secret_hash)) {
                    return null;
                }
            } catch (Throwable) {
                return null;
            }

            $updated = DB::table('product_api_credentials')
                ->where('id', $credential->credential_id)
                ->whereNull('revoked_at')
                ->where('expires_at', '>', now())
                ->update(['last_used_at' => now(), 'updated_at' => now()]);

            if ($updated !== 1) {
                return null;
            }

            return (object) [
                'credential_id' => $credential->credential_id,
                'oauth_client_id' => $credential->oauth_client_id,
                'product_id' => (int) $credential->product_id,
                'product_slug' => $credential->product_slug,
            ];
        });
    }
}
