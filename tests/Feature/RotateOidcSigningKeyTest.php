<?php

namespace Tests\Feature;

use App\Models\AuditCheckpoint;
use App\Models\AuditLog;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

class RotateOidcSigningKeyTest extends TestCase
{
    use RefreshDatabase;

    public function test_key_rotation_publishes_new_and_prior_keys_during_retention(): void
    {
        $oldKeyId = $this->getJson('/oidc/jwks')->assertOk()->json('keys.0.kid');

        $this->artisan('oidc:keys:rotate')->assertSuccessful();

        $response = $this->getJson('/oidc/jwks')->assertOk();
        $keyIds = collect($response->json('keys'))->pluck('kid');

        $this->assertCount(2, $keyIds);
        $this->assertContains($oldKeyId, $keyIds);
        $this->assertDatabaseHas('oidc_signing_keys', [
            'key_id' => $oldKeyId,
            'retired_at' => null,
        ]);
        $oldKeyExpiry = DB::table('oidc_signing_keys')->where('key_id', $oldKeyId)->value('expires_at');
        $this->assertTrue($oldKeyExpiry > now());
        $newKeyId = DB::table('oidc_signing_keys')->orderByDesc('id')->value('key_id');
        $this->assertNotSame($oldKeyId, $newKeyId);
        $this->assertContains($newKeyId, $keyIds);

        AuditLog::recordEntry(request(), null, 'test.key_rotation_checkpoint');
        $checkpoint = AuditCheckpoint::createForLatestEntry();

        $this->assertSame($newKeyId, $checkpoint->key_id);
        $this->assertSame($oldKeyExpiry, DB::table('oidc_signing_keys')->where('key_id', $oldKeyId)->value('expires_at'));
    }

    public function test_rotation_is_rejected_when_key_retention_does_not_cover_id_token_lifetime(): void
    {
        config([
            'auth.oidc_id_token_expire_minutes' => 5,
            'auth.oidc_key_retention_minutes' => 5,
        ]);

        $this->artisan('oidc:keys:rotate')->assertFailed();

        $this->assertDatabaseCount('oidc_signing_keys', 0);
    }
}
