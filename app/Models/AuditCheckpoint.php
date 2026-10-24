<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;

class AuditCheckpoint extends Model
{
    protected $guarded = [];

    public static function createForLatestEntry(): ?object
    {
        $verification = AuditLog::verifyChain();

        if (! $verification['valid'] || $verification['last_sequence'] === 0) {
            return null;
        }

        $entry = DB::table('audit_logs')->where('sequence_number', $verification['last_sequence'])->first();
        $latestCheckpoint = DB::table('audit_checkpoints')->max('sequence_number');

        if ($latestCheckpoint >= $entry->sequence_number) {
            return DB::table('audit_checkpoints')->where('sequence_number', $latestCheckpoint)->first();
        }

        $activeKey = DB::table('oidc_signing_keys')
            ->where('algorithm', 'RS256')
            ->whereNull('retired_at')
            ->where(function ($query): void {
                $query->whereNull('not_before')->orWhere('not_before', '<=', now());
            })
            ->where(function ($query): void {
                $query->whereNull('expires_at')->orWhere('expires_at', '>', now());
            })
            ->orderByDesc('id')
            ->first();

        if ($activeKey && $activeKey->private_key_encrypted) {
            $keyId = $activeKey->key_id;
            $publicPem = $activeKey->public_key_pem;
            $privatePem = Crypt::decryptString($activeKey->private_key_encrypted);
        } else {
            $privatePem = @file_get_contents(Passport::keyPath('oauth-private.key'));
            $publicPem = @file_get_contents(Passport::keyPath('oauth-public.key'));
            $privateKey = $privatePem ? openssl_pkey_get_private($privatePem) : false;

            if (! $privateKey || ! $publicPem) {
                throw new \RuntimeException('Passport signing keys are required to sign audit checkpoints.');
            }

            $keyId = bin2hex(substr(hash('sha256', $publicPem, true), 0, 16));
            DB::table('oidc_signing_keys')->updateOrInsert(
                ['key_id' => $keyId],
                [
                    'algorithm' => 'RS256',
                    'public_key_pem' => $publicPem,
                    'private_key_encrypted' => Crypt::encryptString($privatePem),
                    'not_before' => now(),
                    'expires_at' => null,
                    'retired_at' => null,
                    'updated_at' => now(),
                    'created_at' => now(),
                ]
            );
        }

        $privateKey = openssl_pkey_get_private($privatePem);
        if (! $privateKey) {
            throw new \RuntimeException('The active signing key is unavailable.');
        }

        $message = $entry->sequence_number."\n".$entry->entry_hash;

        if (! openssl_sign($message, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('Unable to sign the audit checkpoint.');
        }

        $id = DB::table('audit_checkpoints')->insertGetId([
            'sequence_number' => $entry->sequence_number,
            'chain_hash' => $entry->entry_hash,
            'signature_algorithm' => 'RS256',
            'signature' => rtrim(strtr(base64_encode($signature), '+/', '-_'), '='),
            'key_id' => $keyId,
            'signed_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return DB::table('audit_checkpoints')->where('id', $id)->first();
    }

    public static function verifyAll(): bool
    {
        foreach (DB::table('audit_checkpoints')->orderBy('sequence_number')->get() as $checkpoint) {
            $entry = DB::table('audit_logs')->where('sequence_number', $checkpoint->sequence_number)->first();
            $key = DB::table('oidc_signing_keys')->where('key_id', $checkpoint->key_id)->first();
            $encodedSignature = $checkpoint->signature;
            $signature = base64_decode(strtr(
                $encodedSignature.str_repeat('=', (4 - strlen($encodedSignature) % 4) % 4),
                '-_',
                '+/'
            ), true);
            $publicKey = $key ? openssl_pkey_get_public($key->public_key_pem) : false;

            if (
                ! $entry
                || ! $publicKey
                || ! hash_equals($entry->entry_hash, $checkpoint->chain_hash)
                || $checkpoint->signature_algorithm !== 'RS256'
                || ! is_string($signature)
                || openssl_verify(
                    $checkpoint->sequence_number."\n".$checkpoint->chain_hash,
                    $signature,
                    $publicKey,
                    OPENSSL_ALGO_SHA256
                ) !== 1
            ) {
                return false;
            }
        }

        return true;
    }
}
