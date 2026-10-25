<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\ClientRepository;
use Tests\TestCase;

class OidcFlowTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config(['app.url' => 'https://auth.example.test']);
    }

    public function test_discovery_and_jwks_publish_an_rs256_signing_key(): void
    {
        $this->get('/.well-known/openid-configuration')
            ->assertOk()
            ->assertJsonPath('issuer', 'https://auth.example.test')
            ->assertJsonPath('authorization_endpoint', 'https://auth.example.test/oidc/authorize')
            ->assertJsonPath('visionweb_product_access_endpoint', 'https://auth.example.test/api/oidc/product-access')
            ->assertJsonPath('code_challenge_methods_supported.0', 'S256');

        $response = $this->getJson('/oidc/jwks')
            ->assertOk()
            ->assertJsonPath('keys.0.kty', 'RSA')
            ->assertJsonPath('keys.0.alg', 'RS256');

        $this->assertDatabaseHas('oidc_signing_keys', [
            'key_id' => $response->json('keys.0.kid'),
            'algorithm' => 'RS256',
        ]);
    }

    public function test_authorization_code_flow_signs_id_token_and_rejects_replay(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
            'phone' => '+15551234567',
            'phone_verified_at' => now(),
        ]);
        $clientId = $this->createOidcClient();
        $verifier = str_repeat('v', 64);
        $challenge = $this->codeChallenge($verifier);

        $this->actingAs($user)
            ->get('/oidc/authorize?'.http_build_query([
                'client_id' => $clientId,
                'redirect_uri' => 'https://client.example/callback',
                'response_type' => 'code',
                'scope' => 'openid profile email phone',
                'state' => 'client-state',
                'nonce' => 'client-nonce',
                'code_challenge' => $challenge,
                'code_challenge_method' => 'S256',
            ]))
            ->assertOk()
            ->assertSee('class="vwss-app"', false)
            ->assertSee('Authorize VisionWeb OIDC test client')
            ->assertSee('Requested permissions')
            ->assertSee('Approve access')
            ->assertSee('Deny');

        $this->assertDatabaseCount('oidc_authorization_codes', 0);

        $approval = $this->post('/oidc/authorize/approve', ['approve' => '1'])
            ->assertRedirect();
        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $parameters);

        $this->assertSame('client-state', $parameters['state'] ?? null);
        $code = $parameters['code'] ?? null;
        $this->assertIsString($code);

        $this->post('/oidc/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'code' => $code,
            'redirect_uri' => 'https://client.example/callback',
            'code_verifier' => str_repeat('x', 64),
        ])->assertBadRequest()->assertJsonPath('error', 'invalid_grant');

        $this->assertDatabaseHas('oidc_authorization_codes', [
            'code_hash' => hash('sha256', $code),
            'consumed_at' => null,
        ]);

        $token = $this->post('/oidc/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'code' => $code,
            'redirect_uri' => 'https://client.example/callback',
            'code_verifier' => $verifier,
        ])->assertOk()->assertJsonStructure(['access_token', 'expires_in', 'id_token', 'scope']);

        $idToken = $token->json('id_token');
        $parts = explode('.', $idToken);
        $this->assertCount(3, $parts);
        $header = json_decode($this->base64UrlDecode($parts[0]), true, flags: JSON_THROW_ON_ERROR);
        $claims = json_decode($this->base64UrlDecode($parts[1]), true, flags: JSON_THROW_ON_ERROR);
        $publicPem = DB::table('oidc_signing_keys')->where('key_id', $header['kid'])->value('public_key_pem');

        $this->assertSame('RS256', $header['alg']);
        $this->assertSame('https://auth.example.test', $claims['iss']);
        $this->assertSame($clientId, $claims['aud']);
        $this->assertSame('client-nonce', $claims['nonce']);
        $this->assertSame($user->email, $claims['email']);
        $this->assertTrue($claims['phone_number_verified']);
        $this->assertSame(1, openssl_verify(
            $parts[0].'.'.$parts[1],
            $this->base64UrlDecode($parts[2]),
            openssl_pkey_get_public($publicPem),
            OPENSSL_ALGO_SHA256
        ));

        $this->withToken($token->json('access_token'))
            ->getJson('/oidc/userinfo')
            ->assertOk()
            ->assertJsonPath('sub', $claims['sub'])
            ->assertJsonPath('email_verified', true)
            ->assertJsonMissingPath('password');

        $this->post('/oidc/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'code' => $code,
            'redirect_uri' => 'https://client.example/callback',
            'code_verifier' => $verifier,
        ])->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
    }

    public function test_oidc_authorization_rejects_unregistered_redirects_and_unsupported_pkce(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $clientId = $this->createOidcClient();
        $parameters = [
            'client_id' => $clientId,
            'redirect_uri' => 'https://attacker.example/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'state',
            'nonce' => 'nonce',
            'code_challenge' => $this->codeChallenge(str_repeat('a', 64)),
            'code_challenge_method' => 'S256',
        ];

        $this->actingAs($user)
            ->get('/oidc/authorize?'.http_build_query($parameters))
            ->assertBadRequest()
            ->assertDontSee('attacker.example');

        $parameters['redirect_uri'] = 'https://client.example/callback';
        $parameters['code_challenge_method'] = 'plain';

        $this->from('/')->get('/oidc/authorize?'.http_build_query($parameters))
            ->assertRedirect('/')
            ->assertSessionHasErrors('code_challenge_method');
    }

    public function test_oidc_userinfo_rejects_expired_and_revoked_access_tokens(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $clientId = $this->createOidcClient();
        $bearer = bin2hex(random_bytes(32));
        $id = DB::table('oidc_access_tokens')->insertGetId([
            'user_id' => $user->id,
            'oauth_client_id' => $clientId,
            'token_hash' => hash('sha256', $bearer),
            'scopes' => json_encode(['openid', 'email']),
            'expires_at' => now()->addMinute(),
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->withToken($bearer)->getJson('/oidc/userinfo')->assertOk();

        DB::table('oidc_access_tokens')->where('id', $id)->update(['revoked_at' => now()]);
        $this->withToken($bearer)->getJson('/oidc/userinfo')->assertUnauthorized();

        DB::table('oidc_access_tokens')->where('id', $id)->update([
            'revoked_at' => null,
            'expires_at' => now()->subSecond(),
        ]);
        $this->withToken($bearer)->getJson('/oidc/userinfo')->assertUnauthorized();
    }

    public function test_oidc_logout_revokes_access_tokens_and_validates_redirects(): void
    {
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);
        $clientId = $this->createOidcClient();
        $bearer = bin2hex(random_bytes(32));
        DB::table('oidc_access_tokens')->insert([
            'user_id' => $user->id,
            'oauth_client_id' => $clientId,
            'token_hash' => hash('sha256', $bearer),
            'scopes' => json_encode(['openid']),
            'expires_at' => now()->addMinutes(10),
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($user)->post('/oidc/logout', [
            'client_id' => $clientId,
            'post_logout_redirect_uri' => 'https://attacker.example/logout',
        ])->assertBadRequest();

        $this->actingAs($user)->post('/oidc/logout', [
            'client_id' => $clientId,
            'post_logout_redirect_uri' => 'https://client.example/logout',
            'state' => 'logout-state',
        ])->assertRedirect('https://client.example/logout?state=logout-state');

        $this->assertDatabaseHas('oidc_access_tokens', [
            'token_hash' => hash('sha256', $bearer),
        ]);
        $this->withToken($bearer)->getJson('/oidc/userinfo')->assertUnauthorized();
    }

    public function test_oidc_client_command_configures_only_valid_authorization_code_clients(): void
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient(
            'Configured OIDC client',
            ['https://client.example/callback'],
            false
        );

        $exitCode = Artisan::call('oidc:client:configure', [
            'clientId' => $client->id,
            '--client-type' => 'public',
            '--subject-type' => 'pairwise',
            '--scopes' => 'openid,email',
            '--logout-redirects' => 'https://client.example/logout',
        ]);

        $this->assertSame(0, $exitCode);
        $this->assertDatabaseHas('oidc_client_metadata', [
            'oauth_client_id' => $client->id,
            'client_type' => 'public',
            'subject_type' => 'pairwise',
            'require_pkce' => true,
            'require_consent' => true,
            'enabled' => true,
        ]);

        $exitCode = Artisan::call('oidc:client:configure', [
            'clientId' => $client->id,
            '--client-type' => 'public',
            '--scopes' => 'email',
        ]);

        $this->assertSame(1, $exitCode);
    }

    public function test_oidc_client_command_requires_and_persists_an_active_product_for_product_access(): void
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient(
            'Product-bound OIDC client', ['https://client.example/callback'], false
        );
        $now = now();
        $productId = DB::table('products')->insertGetId([
            'slug' => 'test-product', 'name' => 'Test Product', 'status' => 'active',
            'created_at' => $now, 'updated_at' => $now,
        ]);

        $this->assertSame(1, Artisan::call('oidc:client:configure', [
            'clientId' => $client->id,
            '--client-type' => 'public',
            '--scopes' => 'openid,email,product_access',
        ]));

        $this->assertSame(0, Artisan::call('oidc:client:configure', [
            'clientId' => $client->id,
            '--client-type' => 'public',
            '--scopes' => 'openid,email,product_access',
            '--product' => 'test-product',
        ]));
        $this->assertDatabaseHas('oidc_client_metadata', [
            'oauth_client_id' => $client->id,
            'product_id' => $productId,
        ]);
    }

    private function createOidcClient(): string
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient(
            'VisionWeb OIDC test client',
            ['https://client.example/callback'],
            false
        );

        DB::table('oidc_client_metadata')->insert([
            'oauth_client_id' => $client->id,
            'client_type' => 'public',
            'application_type' => 'web',
            'subject_type' => 'pairwise',
            'allowed_scopes' => json_encode(['openid', 'profile', 'email', 'phone']),
            'post_logout_redirect_uris' => json_encode(['https://client.example/logout']),
            'allowed_origins' => json_encode([]),
            'require_pkce' => true,
            'require_consent' => true,
            'enabled' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $client->id;
    }

    private function codeChallenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string
    {
        $padding = (4 - strlen($value) % 4) % 4;

        return base64_decode(strtr($value, '-_', '+/').str_repeat('=', $padding));
    }
}
