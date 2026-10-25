<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\ClientRepository;
use Tests\TestCase;

class ProductServerAccessTest extends TestCase
{
    use RefreshDatabase;

    public function test_valid_product_server_and_matching_client_token_allow_product_access(): void
    {
        $user = $this->activeUser();
        $product = $this->createProduct('server-access-product');
        $clientId = $this->createProductClient((int) $product->id);
        $organization = $this->createOrganization($user, (int) $product->id, true);
        $token = $this->createUserToken($user, $clientId, (int) $product->id);
        $credential = $this->createServerCredential($clientId, (int) $product->id);

        $this->sendDecision($token, $credential, $organization)
            ->assertOk()
            ->assertJson([
                'access' => true,
                'product' => 'server-access-product',
                'organization' => $organization,
                'feature' => 'records',
                'permission' => 'records.read',
            ]);

        $this->assertNotNull(DB::table('product_api_credentials')->where('id', $credential['id'])->value('last_used_at'));
    }

    public function test_product_access_returns_401_when_server_credentials_are_missing(): void
    {
        $this->postJson('/api/oidc/product-access', $this->decisionPayload((string) Str::uuid()))
            ->assertUnauthorized()
            ->assertJsonPath('error', 'invalid_product_server_credentials');
    }

    public function test_product_access_returns_401_when_server_secret_is_invalid(): void
    {
        $user = $this->activeUser();
        $product = $this->createProduct('invalid-secret-product');
        $clientId = $this->createProductClient((int) $product->id);
        $organization = $this->createOrganization($user, (int) $product->id, true);
        $token = $this->createUserToken($user, $clientId, (int) $product->id);
        $credential = $this->createServerCredential($clientId, (int) $product->id);

        $this->sendDecision($token, [...$credential, 'secret' => str_repeat('0', 64)], $organization)
            ->assertUnauthorized()
            ->assertJsonPath('error', 'invalid_product_server_credentials');

        $failureContext = (string) DB::table('security_events')->where('event_type', 'auth.product_server')->value('context');
        $this->assertStringNotContainsString(str_repeat('0', 64), $failureContext);
    }

    public function test_product_access_returns_401_for_a_revoked_server_credential(): void
    {
        $user = $this->activeUser();
        $product = $this->createProduct('revoked-server-product');
        $clientId = $this->createProductClient((int) $product->id);
        $organization = $this->createOrganization($user, (int) $product->id, true);
        $token = $this->createUserToken($user, $clientId, (int) $product->id);
        $credential = $this->createServerCredential($clientId, (int) $product->id);
        DB::table('product_api_credentials')->where('id', $credential['id'])->update(['revoked_at' => now()]);

        $this->sendDecision($token, $credential, $organization)
            ->assertUnauthorized()
            ->assertJsonPath('error', 'invalid_product_server_credentials');
    }

    public function test_product_access_returns_401_for_an_expired_server_credential(): void
    {
        $user = $this->activeUser();
        $product = $this->createProduct('expired-server-product');
        $clientId = $this->createProductClient((int) $product->id);
        $organization = $this->createOrganization($user, (int) $product->id, true);
        $token = $this->createUserToken($user, $clientId, (int) $product->id);
        $credential = $this->createServerCredential($clientId, (int) $product->id);
        DB::table('product_api_credentials')->where('id', $credential['id'])->update(['expires_at' => now()->subSecond()]);

        $this->sendDecision($token, $credential, $organization)
            ->assertUnauthorized()
            ->assertJsonPath('error', 'invalid_product_server_credentials');
    }

    public function test_product_server_credential_rejects_a_token_with_a_different_client_audience(): void
    {
        $user = $this->activeUser();
        $product = $this->createProduct('wrong-audience-product');
        $serverClientId = $this->createProductClient((int) $product->id);
        $otherClientId = $this->createProductClient((int) $product->id);
        $organization = $this->createOrganization($user, (int) $product->id, true);
        $token = $this->createUserToken($user, $otherClientId, (int) $product->id);
        $credential = $this->createServerCredential($serverClientId, (int) $product->id);

        $this->sendDecision($token, $credential, $organization)
            ->assertForbidden()
            ->assertJsonPath('error', 'product_audience_mismatch');
    }

    public function test_product_server_credential_cannot_cross_product_and_client_binding(): void
    {
        $user = $this->activeUser();
        $firstProduct = $this->createProduct('first-bound-product');
        $secondProduct = $this->createProduct('second-bound-product');
        $firstClientId = $this->createProductClient((int) $firstProduct->id);
        $secondClientId = $this->createProductClient((int) $secondProduct->id);
        $organization = $this->createOrganization($user, (int) $firstProduct->id, true);
        $token = $this->createUserToken($user, $firstClientId, (int) $firstProduct->id);
        $credential = $this->createServerCredential($secondClientId, (int) $secondProduct->id);

        $this->sendDecision($token, $credential, $organization)
            ->assertForbidden()
            ->assertJsonPath('error', 'product_audience_mismatch');
    }

    public function test_valid_server_and_token_are_denied_when_product_membership_is_suspended(): void
    {
        $user = $this->activeUser();
        $product = $this->createProduct('unauthorized-member-product');
        $clientId = $this->createProductClient((int) $product->id);
        $organization = $this->createOrganization($user, (int) $product->id, false);
        $token = $this->createUserToken($user, $clientId, (int) $product->id);
        $credential = $this->createServerCredential($clientId, (int) $product->id);

        $this->sendDecision($token, $credential, $organization)
            ->assertForbidden()
            ->assertJsonPath('error', 'access_denied');
    }

    public function test_operator_can_create_and_revoke_expiring_product_server_credentials(): void
    {
        $product = $this->createProduct('credential-lifecycle-product');
        $clientId = $this->createProductClient((int) $product->id);

        $this->assertSame(0, Artisan::call('auth:product-credential:create', [
            'clientId' => $clientId,
            '--name' => 'Staging product API',
            '--reason' => 'Provision approved staging API',
            '--expires-at' => now()->addDays(30)->toIso8601String(),
            '--force' => true,
        ]));

        $output = Artisan::output();
        preg_match('/Credential ID: ([0-9a-f-]{36})/', $output, $idMatches);
        preg_match('/Credential secret \(shown once\): ([0-9a-f]{64})/', $output, $secretMatches);
        $this->assertArrayHasKey(1, $idMatches);
        $this->assertArrayHasKey(1, $secretMatches);
        $credentialId = $idMatches[1];
        $secret = $secretMatches[1];
        $storedHash = DB::table('product_api_credentials')->where('id', $credentialId)->value('secret_hash');
        $this->assertNotSame($secret, $storedHash);
        $this->assertTrue(Hash::check($secret, $storedHash));
        $this->assertDatabaseHas('audit_logs', ['action' => 'product.server_credential.created']);
        $auditDetails = (string) DB::table('audit_logs')->where('action', 'product.server_credential.created')->value('details');
        $eventContext = (string) DB::table('security_events')->where('event_type', 'product.server_credential.created')->value('context');
        $this->assertStringNotContainsString($secret, $auditDetails);
        $this->assertStringNotContainsString($secret, $eventContext);

        $this->assertSame(0, Artisan::call('auth:product-credential:revoke', [
            'credentialId' => $credentialId,
            '--reason' => 'Rotate staging API credential',
            '--force' => true,
        ]));
        $this->assertNotNull(DB::table('product_api_credentials')->where('id', $credentialId)->value('revoked_at'));
        $this->assertDatabaseHas('audit_logs', ['action' => 'product.server_credential.revoked']);
    }

    public function test_operator_cannot_create_a_product_server_credential_that_expires_after_one_year(): void
    {
        $product = $this->createProduct('long-lived-credential-product');
        $clientId = $this->createProductClient((int) $product->id);

        $this->assertSame(1, Artisan::call('auth:product-credential:create', [
            'clientId' => $clientId,
            '--name' => 'Long-lived API credential',
            '--reason' => 'Provision test credential',
            '--expires-at' => now()->addYears(2)->toIso8601String(),
            '--force' => true,
        ]));
        $this->assertDatabaseCount('product_api_credentials', 0);
    }

    private function activeUser(): User
    {
        return User::factory()->create(['status' => 'active', 'email_verified_at' => now()]);
    }

    private function createProduct(string $slug): object
    {
        $id = DB::table('products')->insertGetId([
            'slug' => $slug,
            'name' => Str::headline($slug),
            'status' => 'active',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return DB::table('products')->where('id', $id)->first();
    }

    private function createProductClient(int $productId): string
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient(
            'Product API test client', ['https://product.example.test/callback'], false
        );
        DB::table('oidc_client_metadata')->insert([
            'oauth_client_id' => $client->id,
            'client_type' => 'public',
            'product_id' => $productId,
            'application_type' => 'web',
            'subject_type' => 'pairwise',
            'allowed_scopes' => json_encode(['openid', 'product_access'], JSON_THROW_ON_ERROR),
            'post_logout_redirect_uris' => '[]',
            'allowed_origins' => '[]',
            'require_pkce' => true,
            'require_consent' => true,
            'enabled' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $client->id;
    }

    private function createOrganization(User $owner, int $productId, bool $activeMembership): string
    {
        $planId = DB::table('product_plans')->insertGetId([
            'product_id' => $productId,
            'slug' => 'standard',
            'name' => 'Standard',
            'status' => 'active',
            'seat_limit' => 5,
            'billing_interval' => 'monthly',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $organizationId = DB::table('product_organizations')->insertGetId([
            'public_id' => (string) Str::uuid(),
            'product_id' => $productId,
            'owner_user_id' => $owner->id,
            'name' => 'Test organization',
            'status' => 'active',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $roleId = DB::table('product_roles')->insertGetId([
            'organization_id' => $organizationId,
            'role_key' => 'reader',
            'name' => 'Reader',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('product_role_permissions')->insert([
            'product_role_id' => $roleId,
            'permission_key' => 'records.read',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('product_memberships')->insert([
            'organization_id' => $organizationId,
            'user_id' => $owner->id,
            'product_role_id' => $roleId,
            'status' => $activeMembership ? 'active' : 'suspended',
            'joined_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('product_subscriptions')->insert([
            'organization_id' => $organizationId,
            'plan_id' => $planId,
            'status' => 'active',
            'starts_at' => now()->subMinute(),
            'renews_at' => now()->addDays(29),
            'ends_at' => now()->addDays(30),
            'canceled_at' => null,
            'provider' => null,
            'provider_subscription_id' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('product_entitlements')->insert([
            ['plan_id' => $planId, 'feature_key' => 'access', 'enabled' => true, 'usage_limit' => null, 'created_at' => now(), 'updated_at' => now()],
            ['plan_id' => $planId, 'feature_key' => 'records', 'enabled' => true, 'usage_limit' => null, 'created_at' => now(), 'updated_at' => now()],
        ]);

        return (string) DB::table('product_organizations')->where('id', $organizationId)->value('public_id');
    }

    /** @return array{id: string, secret: string} */
    private function createServerCredential(string $clientId, int $productId): array
    {
        $id = (string) Str::uuid();
        $secret = bin2hex(random_bytes(32));
        DB::table('product_api_credentials')->insert([
            'id' => $id,
            'oauth_client_id' => $clientId,
            'product_id' => $productId,
            'name' => 'Test credential',
            'secret_hash' => Hash::make($secret),
            'expires_at' => now()->addDay(),
            'revoked_at' => null,
            'last_used_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return ['id' => $id, 'secret' => $secret];
    }

    private function createUserToken(User $user, string $clientId, int $productId): string
    {
        $token = bin2hex(random_bytes(32));
        DB::table('oidc_access_tokens')->insert([
            'user_id' => $user->id,
            'oauth_client_id' => $clientId,
            'product_id' => $productId,
            'token_hash' => hash('sha256', $token),
            'scopes' => json_encode(['openid', 'product_access'], JSON_THROW_ON_ERROR),
            'expires_at' => now()->addMinutes(10),
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $token;
    }

    private function sendDecision(string $userToken, array $serverCredential, string $organization): TestResponse
    {
        return $this->withHeaders([
            'X-VisionWeb-Product-Credential' => $serverCredential['id'],
            'X-VisionWeb-Product-Secret' => $serverCredential['secret'],
        ])->withToken($userToken)->postJson('/api/oidc/product-access', $this->decisionPayload($organization));
    }

    private function decisionPayload(string $organization): array
    {
        return [
            'organization' => $organization,
            'feature' => 'records',
            'permission' => 'records.read',
        ];
    }
}
