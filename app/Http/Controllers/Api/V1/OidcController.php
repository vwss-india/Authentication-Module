<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use Symfony\Component\HttpFoundation\Response;

class OidcController extends Controller
{
    public function discovery(): JsonResponse
    {
        $issuer = rtrim((string) config('app.url'), '/');

        return response()->json([
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer.'/oidc/authorize',
            'token_endpoint' => $issuer.'/oidc/token',
            'userinfo_endpoint' => $issuer.'/oidc/userinfo',
            'jwks_uri' => $issuer.'/oidc/jwks',
            'end_session_endpoint' => $issuer.'/oidc/logout',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public', 'pairwise'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => ['openid', 'profile', 'email', 'phone'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'code_challenge_methods_supported' => ['S256'],
            'claims_supported' => [
                'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'name',
                'preferred_username', 'email', 'email_verified', 'phone_number',
                'phone_number_verified', 'at_hash',
            ],
        ]);
    }

    public function jwks(): JsonResponse
    {
        $this->activeSigningKey();

        $keys = DB::table('oidc_signing_keys')
            ->whereNull('retired_at')
            ->where(function ($query): void {
                $query->whereNull('not_before')->orWhere('not_before', '<=', now());
            })
            ->where(function ($query): void {
                $query->whereNull('expires_at')->orWhere('expires_at', '>', now());
            })
            ->get();

        $publicKeys = [];

        foreach ($keys as $key) {
            $publicKey = openssl_pkey_get_public($key->public_key_pem);
            $details = $publicKey ? openssl_pkey_get_details($publicKey) : false;

            if (! $details || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
                continue;
            }

            $publicKeys[] = [
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => 'RS256',
                'kid' => $key->key_id,
                'n' => $this->base64UrlEncode($details['rsa']['n']),
                'e' => $this->base64UrlEncode($details['rsa']['e']),
            ];
        }

        return response()->json(['keys' => $publicKeys]);
    }

    public function authorize(Request $request): Response
    {
        $data = $request->validate([
            'client_id' => ['required', 'uuid'],
            'redirect_uri' => ['required', 'string', 'max:2048'],
            'response_type' => ['required', 'in:code'],
            'scope' => ['required', 'string', 'max:500'],
            'state' => ['required', 'string', 'max:255'],
            'nonce' => ['required', 'string', 'max:255'],
            'code_challenge' => ['required', 'regex:/^[A-Za-z0-9_-]{43}$/'],
            'code_challenge_method' => ['required', 'in:S256'],
        ]);

        $client = $this->oidcClient($request, $data['client_id']);
        $redirectUris = json_decode((string) $client->redirect_uris, true) ?: [];

        if (! in_array($data['redirect_uri'], $redirectUris, true)) {
            $this->recordEvent($request, $request->user(), 'auth.oidc.authorization', 'blocked', [
                'reason' => 'invalid_redirect',
                'client_id' => $client->id,
            ]);

            return response('Invalid redirect URI.', 400);
        }

        $scopes = array_values(array_unique(preg_split('/\s+/', trim($data['scope'])) ?: []));
        $configuredScopes = json_decode((string) $client->allowed_scopes, true);
        $allowedScopes = is_array($configuredScopes)
            ? $configuredScopes
            : ['openid', 'profile', 'email', 'phone'];

        if (! in_array('openid', $scopes, true) || array_diff($scopes, $allowedScopes)) {
            $this->recordEvent($request, $request->user(), 'auth.oidc.authorization', 'blocked', [
                'reason' => 'invalid_scope',
                'client_id' => $client->id,
            ]);

            return response('Invalid scope.', 400);
        }

        $user = $request->user();

        if (! $user || $user->status !== 'active' || ! $user->email_verified_at) {
            return response('The account is not eligible for single sign-on.', 403);
        }

        $request->session()->put('oidc_authorization', [
            ...$data,
            'scopes' => $scopes,
            'user_id' => $user->id,
        ]);

        $this->recordEvent($request, $user, 'auth.oidc.authorization', 'requested', [
            'client_id' => $client->id,
            'scopes' => $scopes,
        ]);

        return response()->view('auth.oidc.consent', [
            'clientName' => $client->name,
            'scopes' => $scopes,
        ]);
    }

    public function approve(Request $request): RedirectResponse|JsonResponse
    {
        $authorization = $request->session()->pull('oidc_authorization');

        if (! is_array($authorization) || $authorization['user_id'] !== $request->user()?->id) {
            return response()->json(['message' => 'The authorization request has expired.'], 422);
        }

        $client = $this->oidcClient($request, $authorization['client_id']);

        if (! $request->boolean('approve')) {
            $this->recordEvent($request, $request->user(), 'auth.oidc.authorization', 'denied', [
                'client_id' => $client->id,
            ]);

            return redirect()->away($authorization['redirect_uri'].'?'.http_build_query([
                'error' => 'access_denied',
                'state' => $authorization['state'],
            ], '', '&', PHP_QUERY_RFC3986));
        }

        $code = bin2hex(random_bytes(32));

        DB::table('oidc_authorization_codes')->insert([
            'user_id' => $authorization['user_id'],
            'oauth_client_id' => $client->id,
            'code_hash' => hash('sha256', $code),
            'redirect_uri' => $authorization['redirect_uri'],
            'scopes' => json_encode($authorization['scopes'], JSON_THROW_ON_ERROR),
            'nonce' => $authorization['nonce'],
            'code_challenge' => $authorization['code_challenge'],
            'code_challenge_method' => 'S256',
            'expires_at' => now()->addMinutes(5),
            'consumed_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->recordEvent($request, $request->user(), 'auth.oidc.authorization', 'approved', [
            'client_id' => $client->id,
            'scopes' => $authorization['scopes'],
        ]);

        return redirect()->away($authorization['redirect_uri'].'?'.http_build_query([
            'code' => $code,
            'state' => $authorization['state'],
        ], '', '&', PHP_QUERY_RFC3986));
    }

    public function token(Request $request): JsonResponse
    {
        $data = $request->validate([
            'grant_type' => ['required', 'in:authorization_code'],
            'client_id' => ['nullable', 'uuid'],
            'client_secret' => ['nullable', 'string', 'max:255'],
            'code' => ['required', 'string', 'size:64'],
            'redirect_uri' => ['required', 'string', 'max:2048'],
            'code_verifier' => ['required', 'regex:/^[A-Za-z0-9._~-]{43,128}$/'],
        ]);

        $clientId = $request->getUser() ?: ($data['client_id'] ?? null);

        if (! $clientId) {
            return response()->json(['error' => 'invalid_client'], 401);
        }

        $client = $this->oidcClient($request, $clientId);

        if (! $this->clientSecretIsValid($client, $request->getPassword() ?? ($data['client_secret'] ?? null))) {
            $this->recordEvent($request, null, 'oauth.token', 'failure', ['reason' => 'invalid_client']);

            return response()->json(['error' => 'invalid_client'], 401);
        }

        $code = DB::transaction(function () use ($data, $client): ?object {
            $record = DB::table('oidc_authorization_codes')
                ->where('code_hash', hash('sha256', $data['code']))
                ->where('oauth_client_id', $client->id)
                ->where('redirect_uri', $data['redirect_uri'])
                ->whereNull('consumed_at')
                ->where('expires_at', '>', now())
                ->lockForUpdate()
                ->first();

            if (! $record) {
                return null;
            }

            $challenge = $this->base64UrlEncode(hash('sha256', $data['code_verifier'], true));

            if (! hash_equals($record->code_challenge, $challenge)) {
                return null;
            }

            $consumed = DB::table('oidc_authorization_codes')
                ->where('id', $record->id)
                ->whereNull('consumed_at')
                ->where('expires_at', '>', now())
                ->update(['consumed_at' => now(), 'updated_at' => now()]);

            return $consumed === 1 ? $record : null;
        });

        if (! $code) {
            $this->recordEvent($request, null, 'auth.oidc.token', 'failure', ['reason' => 'invalid_grant']);

            return response()->json(['error' => 'invalid_grant'], 400);
        }

        $user = User::query()->find($code->user_id);

        if (! $user || $user->status !== 'active' || ! $user->email_verified_at) {
            $this->recordEvent($request, $user, 'auth.oidc.token', 'failure', ['reason' => 'account_unavailable']);

            return response()->json(['error' => 'invalid_grant'], 400);
        }

        $scopes = json_decode($code->scopes, true) ?: ['openid'];
        $accessToken = bin2hex(random_bytes(32));
        $expiresAt = now()->addMinutes(max(1, (int) config('auth.oidc_access_token_expire_minutes', 10)));

        DB::table('oidc_access_tokens')->insert([
            'user_id' => $user->id,
            'oauth_client_id' => $client->id,
            'token_hash' => hash('sha256', $accessToken),
            'scopes' => json_encode($scopes, JSON_THROW_ON_ERROR),
            'expires_at' => $expiresAt,
            'revoked_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $idToken = $this->issueIdToken($user, $client->id, $code->nonce, $scopes, $accessToken);
        $this->recordEvent($request, $user, 'auth.oidc.token', 'success', [
            'client_id' => $client->id,
            'scopes' => $scopes,
        ]);

        return response()->json([
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => now()->diffInSeconds($expiresAt),
            'id_token' => $idToken,
            'scope' => implode(' ', $scopes),
        ])->header('Cache-Control', 'no-store')->header('Pragma', 'no-cache');
    }

    public function userinfo(Request $request): JsonResponse
    {
        $bearer = $request->bearerToken();

        if (! $bearer) {
            $this->recordEvent($request, null, 'auth.oidc.userinfo', 'failure', ['reason' => 'missing_bearer']);

            return response()->json(['error' => 'invalid_token'], 401);
        }

        $token = DB::table('oidc_access_tokens as tokens')
            ->join('oauth_clients as clients', 'clients.id', '=', 'tokens.oauth_client_id')
            ->join('oidc_client_metadata as settings', 'settings.oauth_client_id', '=', 'clients.id')
            ->where('clients.revoked', false)
            ->where('settings.enabled', true)
            ->where('tokens.token_hash', hash('sha256', $bearer))
            ->whereNull('tokens.revoked_at')
            ->where('tokens.expires_at', '>', now())
            ->select('tokens.*')
            ->first();
        $user = $token ? User::query()->find($token->user_id) : null;

        if (! $user || $user->status !== 'active' || ! $user->email_verified_at) {
            $this->recordEvent($request, $user, 'auth.oidc.userinfo', 'failure', ['reason' => 'invalid_token']);

            return response()->json(['error' => 'invalid_token'], 401);
        }

        $this->recordEvent($request, $user, 'auth.oidc.userinfo', 'success', [
            'client_id' => $token->oauth_client_id,
        ]);

        return response()->json($this->claims(
            $user,
            $token->oauth_client_id,
            json_decode($token->scopes, true) ?: []
        ));
    }

    public function logout(Request $request): Response
    {
        $user = $request->user();
        $data = $request->validate([
            'client_id' => ['nullable', 'uuid'],
            'post_logout_redirect_uri' => ['nullable', 'string', 'max:2048'],
            'state' => ['nullable', 'string', 'max:255'],
        ]);
        $redirectUri = null;

        if (($data['post_logout_redirect_uri'] ?? null) && ! ($data['client_id'] ?? null)) {
            return response('A client ID is required for a post-logout redirect.', 400);
        }

        if (($data['client_id'] ?? null) && ($data['post_logout_redirect_uri'] ?? null)) {
            $client = DB::table('oauth_clients')->where('id', $data['client_id'])->first();
            $settings = DB::table('oidc_client_metadata')->where('oauth_client_id', $data['client_id'])->first();
            $allowed = $settings ? json_decode((string) $settings->post_logout_redirect_uris, true) ?: [] : [];

            if (! $client || ! $settings || ! in_array($data['post_logout_redirect_uri'], $allowed, true)) {
                $this->recordEvent($request, $user, 'auth.oidc.logout', 'blocked', [
                    'reason' => 'invalid_redirect',
                    'client_id' => $data['client_id'],
                ]);

                return response('Invalid post-logout redirect URI.', 400);
            }

            $redirectUri = $data['post_logout_redirect_uri'];
        }

        if ($user) {
            DB::table('oidc_access_tokens')
                ->where('user_id', $user->id)
                ->whereNull('revoked_at')
                ->update(['revoked_at' => now(), 'updated_at' => now()]);
        }

        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        $this->recordEvent($request, $user, 'auth.oidc.logout', 'success');

        if ($redirectUri) {
            $query = isset($data['state']) ? ['state' => $data['state']] : [];

            return redirect()->away($redirectUri.(count($query) ? '?'.http_build_query($query) : ''));
        }

        return response('Signed out.', 200);
    }

    private function oidcClient(Request $request, string $clientId): object
    {
        $client = DB::table('oauth_clients as clients')
            ->join('oidc_client_metadata as settings', 'settings.oauth_client_id', '=', 'clients.id')
            ->where('clients.id', $clientId)
            ->where('clients.revoked', false)
            ->where('settings.enabled', true)
            ->select('clients.*', 'settings.allowed_scopes', 'settings.client_type')
            ->first();

        if (! $client) {
            $this->recordEvent($request, $request->user(), 'oauth.client', 'failure', [
                'reason' => 'invalid_or_disabled_client',
            ]);
            abort(400, 'The OIDC client is not registered or enabled.');
        }

        $grantTypes = json_decode((string) $client->grant_types, true) ?: [];

        if (! in_array('authorization_code', $grantTypes, true)) {
            $this->recordEvent($request, $request->user(), 'oauth.client', 'failure', [
                'reason' => 'grant_not_allowed',
            ]);
            abort(400, 'The OIDC client is not authorized for the code flow.');
        }

        return $client;
    }

    private function clientSecretIsValid(object $client, ?string $secret): bool
    {
        if ($client->client_type === 'public') {
            return $secret === null || $secret === '';
        }

        return is_string($secret) && is_string($client->secret) && Hash::check($secret, $client->secret);
    }

    private function issueIdToken(User $user, string $clientId, string $nonce, array $scopes, string $accessToken): string
    {
        $key = $this->activeSigningKey();
        $now = now()->timestamp;
        $claims = [
            'iss' => rtrim((string) config('app.url'), '/'),
            'sub' => $this->subjectFor($user, $clientId),
            'aud' => $clientId,
            'iat' => $now,
            'exp' => $now + (max(1, (int) config('auth.oidc_id_token_expire_minutes', 5)) * 60),
            'auth_time' => $user->last_login_at?->timestamp ?? $now,
            'nonce' => $nonce,
            'at_hash' => $this->base64UrlEncode(substr(hash('sha256', $accessToken, true), 0, 16)),
            ...$this->claims($user, $clientId, $scopes),
        ];
        $header = $this->base64UrlEncode(json_encode([
            'typ' => 'JWT',
            'alg' => 'RS256',
            'kid' => $key->key_id,
        ], JSON_THROW_ON_ERROR));
        $payload = $this->base64UrlEncode(json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        $signingInput = $header.'.'.$payload;
        $privateKey = openssl_pkey_get_private(Crypt::decryptString($key->private_key_encrypted));

        if (! $privateKey || ! openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('The OIDC signing key is unavailable.');
        }

        return $signingInput.'.'.$this->base64UrlEncode($signature);
    }

    private function activeSigningKey(): object
    {
        $key = DB::table('oidc_signing_keys')
            ->whereNull('retired_at')
            ->where(function ($query): void {
                $query->whereNull('not_before')->orWhere('not_before', '<=', now());
            })
            ->where(function ($query): void {
                $query->whereNull('expires_at')->orWhere('expires_at', '>', now());
            })
            ->orderByDesc('id')
            ->first();

        if ($key) {
            return $key;
        }

        $privatePem = @file_get_contents(Passport::keyPath('oauth-private.key'));
        $publicPem = @file_get_contents(Passport::keyPath('oauth-public.key'));

        if (! $privatePem || ! $publicPem || ! openssl_pkey_get_private($privatePem)) {
            throw new \RuntimeException('Passport signing keys are required for OIDC.');
        }

        $keyId = bin2hex(substr(hash('sha256', $publicPem, true), 0, 16));

        DB::table('oidc_signing_keys')->insert([
            'key_id' => $keyId,
            'algorithm' => 'RS256',
            'public_key_pem' => $publicPem,
            'private_key_encrypted' => Crypt::encryptString($privatePem),
            'not_before' => now(),
            'expires_at' => null,
            'retired_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return DB::table('oidc_signing_keys')->where('key_id', $keyId)->first();
    }

    private function claims(User $user, string $clientId, array $scopes): array
    {
        $claims = ['sub' => $this->subjectFor($user, $clientId)];

        if (in_array('profile', $scopes, true)) {
            $claims['name'] = $user->name;
            $claims['preferred_username'] = $user->username;
        }

        if (in_array('email', $scopes, true)) {
            $claims['email'] = $user->email;
            $claims['email_verified'] = $user->email_verified_at !== null;
        }

        if (in_array('phone', $scopes, true)) {
            $claims['phone_number'] = $user->phone;
            $claims['phone_number_verified'] = $user->phone_verified_at !== null;
        }

        return $claims;
    }

    private function subjectFor(User $user, string $clientId): string
    {
        $subjectType = DB::table('oidc_client_metadata')
            ->where('oauth_client_id', $clientId)
            ->value('subject_type');

        if ($subjectType !== 'pairwise') {
            return $user->public_id;
        }

        $subject = DB::table('oidc_subject_identifiers')
            ->where('user_id', $user->id)
            ->where('client_id', $clientId)
            ->value('subject_identifier');

        if ($subject) {
            return $subject;
        }

        $subject = $this->base64UrlEncode(hash_hmac(
            'sha256',
            $user->public_id.':'.$clientId,
            (string) config('app.key'),
            true
        ));

        DB::table('oidc_subject_identifiers')->insert([
            'user_id' => $user->id,
            'client_id' => $clientId,
            'subject_identifier' => $subject,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $subject;
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function recordEvent(Request $request, ?User $user, string $type, string $result, array $context = []): void
    {
        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $user?->id,
            'event_type' => $type,
            'result' => $result,
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
            'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
            'context' => json_encode($context, JSON_THROW_ON_ERROR),
            'occurred_at' => now(),
        ]);

        AuditLog::recordEntry($request, $user, $type.'.'.$result, $context);
    }
}
