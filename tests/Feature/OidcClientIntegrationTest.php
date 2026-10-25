<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\ClientRepository;
use Tests\TestCase;

class OidcClientIntegrationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.url' => 'https://central-auth.example.test']);
        $this->withoutVite();
    }

    public function test_separate_relying_party_client_completes_sso_pkce_jwt_validation_and_product_access(): void
    {
        $user = User::factory()->create([
            'email' => 'sso-member@example.test',
            'password' => 'Strong-Sso-Password-2030',
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $clientId = app(ClientRepository::class)
            ->createAuthorizationCodeGrantClient('VisionWeb Local Test Client', ['https://test-client.example/callback'], false)->id;
        $organization = $this->createProductMembership($user);
        $productId = DB::table('products')->where('slug', 'integration-product')->value('id');
        DB::table('oidc_client_metadata')->insert([
            'oauth_client_id' => $clientId, 'client_type' => 'public', 'application_type' => 'web',
            'product_id' => $productId,
            'subject_type' => 'pairwise', 'allowed_scopes' => json_encode(['openid', 'email', 'product_access']),
            'post_logout_redirect_uris' => json_encode([]), 'allowed_origins' => json_encode([]),
            'require_pkce' => true, 'require_consent' => true, 'enabled' => true,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $serverCredential = $this->createProductServerCredential($clientId, (int) $productId);
        $client = new LocalOidcTestClient($clientId, 'https://central-auth.example.test', 'https://test-client.example/callback');
        Route::get('/_test-client/login', fn () => redirect()->away($client->authorizationUrl()));

        // The relying party initiates login and Central Auth sends the browser to its login page.
        $this->get('/_test-client/login')->assertRedirect($client->authorizationUrl());
        $this->get($client->authorizationUrl())->assertRedirect(route('login'));
        $this->post('/login', [
            'email' => $user->email,
            'password' => 'Strong-Sso-Password-2030',
        ])->assertRedirect();

        // The signed-in browser revisits the authorization request and approves consent.
        $this->get($client->authorizationUrl())->assertOk()->assertSee('VisionWeb Local Test Client');
        $approval = $this->post('/oidc/authorize/approve', ['approve' => '1'])->assertRedirect();
        $code = $client->acceptCallback((string) $approval->headers->get('Location'));

        // The separate client exchanges the short-lived code using the original verifier.
        $tokenResponse = $this->postJson('/oidc/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'code' => $code,
            'redirect_uri' => 'https://test-client.example/callback',
            'code_verifier' => $client->verifier(),
        ])->assertOk()->assertJsonStructure(['access_token', 'id_token', 'expires_in']);
        $accessToken = $tokenResponse->json('access_token');
        $discovery = $this->getJson('/.well-known/openid-configuration')->assertOk()->json();
        $jwks = $this->getJson('/oidc/jwks')->assertOk()->json('keys');
        $claims = $client->validateIdToken($tokenResponse->json('id_token'), $jwks, $discovery['issuer'], $client->nonce(), $accessToken);
        $this->assertSame($clientId, $claims['aud']);
        $this->assertSame('integration-product', $claims['visionweb_product']);
        $this->assertNotSame($user->public_id, $claims['sub'], 'Pairwise client subject must not expose the public user identifier.');

        $this->withToken($accessToken)->getJson('/oidc/userinfo')->assertOk()
            ->assertJsonPath('sub', $claims['sub'])->assertJsonPath('email', $user->email);
        $accessRequest = [
            'product' => 'integration-product',
            'organization' => $organization,
            'feature' => 'records',
            'permission' => 'records.read',
        ];
        $this->requestProductAccess($accessToken, $serverCredential, $accessRequest)
            ->assertOk()->assertJson(['access' => true]);
        $this->requestProductAccess($accessToken, $serverCredential, [
            ...$accessRequest, 'product' => 'another-product',
        ])->assertForbidden()->assertJsonPath('error', 'product_binding_mismatch');
        $this->requestProductAccess($accessToken, $serverCredential, [
            'organization' => $organization, 'feature' => 'records', 'permission' => 'records.read',
        ])->assertOk()->assertJsonPath('product', 'integration-product');
        $this->requestProductAccess($accessToken, $serverCredential, [
            ...$accessRequest, 'organization' => (string) Str::uuid(),
        ])->assertForbidden()->assertJson(['access' => false]);

        DB::table('product_subscriptions')->where('organization_id', DB::table('product_organizations')->where('public_id', $organization)->value('id'))
            ->update(['status' => 'expired', 'ends_at' => now()->subMinute()]);
        $this->requestProductAccess($accessToken, $serverCredential, $accessRequest)
            ->assertForbidden()->assertJson(['error' => 'access_denied']);

        DB::table('product_subscriptions')->where('organization_id', DB::table('product_organizations')->where('public_id', $organization)->value('id'))
            ->update(['status' => 'active', 'ends_at' => now()->addDay()]);
        DB::table('product_memberships')->where('user_id', $user->id)->update(['status' => 'suspended']);
        $this->requestProductAccess($accessToken, $serverCredential, $accessRequest)
            ->assertForbidden()->assertJsonPath('error', 'access_denied');

        DB::table('product_memberships')->where('user_id', $user->id)->update(['status' => 'active']);
        $this->actingAs($user)->get('/oidc/authorize?'.http_build_query([
            'client_id' => $clientId, 'redirect_uri' => 'https://test-client.example/callback',
            'response_type' => 'code', 'scope' => 'openid email product_access', 'state' => 'tamper',
            'nonce' => 'tamper', 'code_challenge' => str_repeat('a', 43), 'code_challenge_method' => 'S256',
            'product' => 'another-product',
        ]))->assertRedirect()->assertSessionHasErrors('product');
    }

    public function test_product_access_scope_requires_a_valid_product_binding_and_rejects_invalid_client(): void
    {
        $user = User::factory()->create(['status' => 'active', 'email_verified_at' => now()]);
        $clientId = app(ClientRepository::class)->createAuthorizationCodeGrantClient(
            'Unbound product client', ['https://test-client.example/callback'], false
        )->id;
        DB::table('oidc_client_metadata')->insert([
            'oauth_client_id' => $clientId, 'client_type' => 'public', 'application_type' => 'web',
            'subject_type' => 'public', 'allowed_scopes' => json_encode(['openid', 'product_access']),
            'post_logout_redirect_uris' => json_encode([]), 'allowed_origins' => json_encode([]),
            'require_pkce' => true, 'require_consent' => true, 'enabled' => true,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $parameters = [
            'client_id' => $clientId, 'redirect_uri' => 'https://test-client.example/callback',
            'response_type' => 'code', 'scope' => 'openid product_access', 'state' => 'state',
            'nonce' => 'nonce', 'code_challenge' => str_repeat('a', 43), 'code_challenge_method' => 'S256',
        ];

        $this->actingAs($user)->get('/oidc/authorize?'.http_build_query($parameters))
            ->assertForbidden()->assertDontSee('authorization');

        $parameters['client_id'] = (string) Str::uuid();
        $this->actingAs($user)->get('/oidc/authorize?'.http_build_query($parameters))->assertBadRequest();
        $parameters['client_id'] = $clientId;
        $parameters['redirect_uri'] = 'https://attacker.example/callback';
        $parameters['scope'] = 'openid';
        $this->actingAs($user)->get('/oidc/authorize?'.http_build_query($parameters))->assertBadRequest();
    }

    private function createProductMembership(User $user): string
    {
        $now = now();
        $productId = DB::table('products')->insertGetId([
            'slug' => 'integration-product', 'name' => 'Integration Product', 'status' => 'active',
            'created_at' => $now, 'updated_at' => $now,
        ]);
        $planId = DB::table('product_plans')->insertGetId([
            'product_id' => $productId, 'slug' => 'integration', 'name' => 'Integration Plan', 'status' => 'active',
            'seat_limit' => 5, 'billing_interval' => 'monthly', 'created_at' => $now, 'updated_at' => $now,
        ]);
        $organizationPublicId = (string) Str::uuid();
        $organizationId = DB::table('product_organizations')->insertGetId([
            'public_id' => $organizationPublicId, 'product_id' => $productId, 'owner_user_id' => $user->id,
            'name' => 'Integration Tenant', 'status' => 'active', 'created_at' => $now, 'updated_at' => $now,
        ]);
        $roleId = DB::table('product_roles')->insertGetId([
            'organization_id' => $organizationId, 'role_key' => 'integration.reader', 'name' => 'Reader',
            'created_at' => $now, 'updated_at' => $now,
        ]);
        DB::table('product_role_permissions')->insert([
            'product_role_id' => $roleId, 'permission_key' => 'records.read', 'created_at' => $now, 'updated_at' => $now,
        ]);
        DB::table('product_memberships')->insert([
            'organization_id' => $organizationId, 'user_id' => $user->id, 'product_role_id' => $roleId,
            'status' => 'active', 'joined_at' => $now, 'created_at' => $now, 'updated_at' => $now,
        ]);
        DB::table('product_subscriptions')->insert([
            'organization_id' => $organizationId, 'plan_id' => $planId, 'status' => 'active',
            'starts_at' => $now->copy()->subDay(), 'renews_at' => $now->copy()->addDays(29),
            'ends_at' => $now->copy()->addDays(30), 'canceled_at' => null, 'provider' => null,
            'provider_subscription_id' => null, 'created_at' => $now, 'updated_at' => $now,
        ]);
        DB::table('product_entitlements')->insert([
            ['plan_id' => $planId, 'feature_key' => 'access', 'enabled' => true, 'usage_limit' => null, 'created_at' => $now, 'updated_at' => $now],
            ['plan_id' => $planId, 'feature_key' => 'records', 'enabled' => true, 'usage_limit' => 500, 'created_at' => $now, 'updated_at' => $now],
        ]);

        return $organizationPublicId;
    }

    /** @return array{id: string, secret: string} */
    private function createProductServerCredential(string $clientId, int $productId): array
    {
        $credential = [
            'id' => (string) Str::uuid(),
            'secret' => bin2hex(random_bytes(32)),
        ];
        DB::table('product_api_credentials')->insert([
            'id' => $credential['id'],
            'oauth_client_id' => $clientId,
            'product_id' => $productId,
            'name' => 'OIDC fixture product API',
            'secret_hash' => Hash::make($credential['secret']),
            'expires_at' => now()->addDay(),
            'revoked_at' => null,
            'last_used_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $credential;
    }

    private function requestProductAccess(string $accessToken, array $serverCredential, array $payload): TestResponse
    {
        return $this->withHeaders([
            'X-VisionWeb-Product-Credential' => $serverCredential['id'],
            'X-VisionWeb-Product-Secret' => $serverCredential['secret'],
        ])->withToken($accessToken)->postJson('/api/oidc/product-access', $payload);
    }
}

/** A minimal separate relying-party client used to execute and validate the local OIDC flow. */
final class LocalOidcTestClient
{
    private readonly string $state;

    private readonly string $nonce;

    private readonly string $verifier;

    public function __construct(
        private readonly string $clientId,
        private readonly string $issuer,
        private readonly string $redirectUri,
    ) {
        $this->state = self::base64UrlEncode(random_bytes(32));
        $this->nonce = self::base64UrlEncode(random_bytes(32));
        $this->verifier = self::base64UrlEncode(random_bytes(48));
    }

    public function authorizationUrl(): string
    {
        $challenge = self::base64UrlEncode(hash('sha256', $this->verifier, true));
        $query = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid email product_access',
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);

        return rtrim($this->issuer, '/').'/oidc/authorize?'.$query;
    }

    public function acceptCallback(string $location): string
    {
        $parts = parse_url($location);
        parse_str((string) ($parts['query'] ?? ''), $query);
        if (($query['state'] ?? null) !== $this->state || ! is_string($query['code'] ?? null)) {
            throw new \RuntimeException('The relying party rejected the authorization callback state or code.');
        }

        return $query['code'];
    }

    /** @return array<string, mixed> */
    public function validateIdToken(string $jwt, array $jwks, string $issuer, string $nonce, string $accessToken): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new \RuntimeException('The ID token is not a compact JWT.');
        }
        $header = json_decode(self::base64UrlDecode($parts[0]), true, flags: JSON_THROW_ON_ERROR);
        $claims = json_decode(self::base64UrlDecode($parts[1]), true, flags: JSON_THROW_ON_ERROR);
        $key = collect($jwks)->firstWhere('kid', $header['kid'] ?? null);
        if (($header['alg'] ?? null) !== 'RS256' || ! $key) {
            throw new \RuntimeException('The ID token signing key or algorithm is not trusted.');
        }
        $signatureValid = openssl_verify(
            $parts[0].'.'.$parts[1],
            self::base64UrlDecode($parts[2]),
            self::jwkToPem($key),
            OPENSSL_ALGO_SHA256,
        ) === 1;
        $expectedAtHash = self::base64UrlEncode(substr(hash('sha256', $accessToken, true), 0, 16));
        $audience = $claims['aud'] ?? null;
        if (
            ! $signatureValid
            || ($claims['iss'] ?? null) !== $issuer
            || ! (is_string($audience) ? $audience === $this->clientId : in_array($this->clientId, $audience ?? [], true))
            || ($claims['nonce'] ?? null) !== $nonce
            || ($claims['exp'] ?? 0) <= now()->timestamp
            || ($claims['iat'] ?? PHP_INT_MAX) > now()->addMinute()->timestamp
            || ! hash_equals($expectedAtHash, (string) ($claims['at_hash'] ?? ''))
        ) {
            throw new \RuntimeException('The ID token signature or relying-party claims are invalid.');
        }

        return $claims;
    }

    public function verifier(): string
    {
        return $this->verifier;
    }

    public function nonce(): string
    {
        return $this->nonce;
    }

    private static function jwkToPem(array $jwk): string
    {
        $modulus = self::base64UrlDecode((string) $jwk['n']);
        $exponent = self::base64UrlDecode((string) $jwk['e']);
        $rsaKey = self::derSequence(self::derInteger($modulus).self::derInteger($exponent));
        $algorithm = hex2bin('300d06092a864886f70d0101010500');
        $bitString = "\x03".self::derLength(strlen($rsaKey) + 1)."\x00".$rsaKey;
        $spki = self::derSequence($algorithm.$bitString);

        return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($spki), 64, "\n")."-----END PUBLIC KEY-----\n";
    }

    private static function derInteger(string $value): string
    {
        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00".$value;
        }

        return "\x02".self::derLength(strlen($value)).$value;
    }

    private static function derSequence(string $value): string
    {
        return "\x30".self::derLength(strlen($value)).$value;
    }

    private static function derLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }
        $encoded = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($encoded)).$encoded;
    }

    private static function base64UrlDecode(string $value): string
    {
        $padding = (4 - strlen($value) % 4) % 4;

        return base64_decode(strtr($value, '-_', '+/').str_repeat('=', $padding), true) ?: '';
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
