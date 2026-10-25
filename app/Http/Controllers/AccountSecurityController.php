<?php

namespace App\Http\Controllers;

use App\Models\AuditLog;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

class AccountSecurityController extends Controller
{
    public function settings(Request $request): View
    {
        $user = $request->user();
        $mfaEnabled = DB::table('mfa_methods')->where('user_id', $user->id)->where('type', 'totp')
            ->whereNotNull('verified_at')->whereNull('revoked_at')->exists();
        $recoveryCodes = DB::table('mfa_recovery_codes as codes')
            ->join('mfa_methods as methods', 'methods.id', '=', 'codes.mfa_method_id')
            ->where('methods.user_id', $user->id)->where('methods.type', 'totp')
            ->whereNotNull('methods.verified_at')->whereNull('methods.revoked_at')
            ->whereNull('codes.used_at')->count();
        $devices = DB::table('trusted_devices')->where('user_id', $user->id)
            ->whereNull('revoked_at')->where('expires_at', '>', now())->orderByDesc('last_used_at')->limit(50)->get();
        $passkeys = DB::table('webauthn_credentials')->where('user_id', $user->id)
            ->whereNull('revoked_at')->orderByDesc('created_at')->limit(50)->get(['public_id', 'name', 'transports', 'last_used_at', 'created_at']);

        $sessionStoreAvailable = config('session.driver') === 'database';
        $sessions = collect();
        if ($sessionStoreAvailable) {
            $sessionTable = config('session.table', 'sessions');
            $sessions = DB::connection(config('session.connection'))->table($sessionTable)
                ->where('user_id', $user->id)->where('id', '<>', $request->session()->getId())
                ->orderByDesc('last_activity')->limit(50)->get()
                ->map(fn (object $session): object => (object) [
                    'reference' => hash_hmac('sha256', $session->id, (string) config('app.key')),
                    'ip_address' => $session->ip_address,
                    'user_agent' => Str::limit((string) $session->user_agent, 180),
                    'last_activity' => (int) $session->last_activity,
                ]);
        }

        $grants = DB::table('oauth_access_tokens as tokens')
            ->join('oauth_clients as clients', 'clients.id', '=', 'tokens.client_id')
            ->where('tokens.user_id', $user->id)->where('tokens.revoked', false)
            ->where(function ($query): void {
                $query->whereNull('tokens.expires_at')->orWhere('tokens.expires_at', '>', now());
            })->orderByDesc('tokens.created_at')->limit(100)
            ->get(['tokens.client_id', 'clients.name', 'tokens.scopes', 'tokens.created_at', 'tokens.expires_at'])
            ->groupBy('client_id');
        $oidcGrants = DB::table('oidc_access_tokens as tokens')
            ->join('oauth_clients as clients', 'clients.id', '=', 'tokens.oauth_client_id')
            ->where('tokens.user_id', $user->id)->whereNull('tokens.revoked_at')
            ->where('tokens.expires_at', '>', now())->orderByDesc('tokens.created_at')->limit(100)
            ->get([
                'tokens.oauth_client_id as client_id', 'clients.name', 'tokens.scopes',
                'tokens.created_at', 'tokens.expires_at',
            ])->groupBy('client_id');
        foreach ($oidcGrants as $clientId => $clientGrants) {
            $grants->put($clientId, $grants->get($clientId, collect())->concat($clientGrants));
        }

        return view('security-settings', compact(
            'mfaEnabled', 'recoveryCodes', 'devices', 'passkeys', 'sessions', 'sessionStoreAvailable', 'grants'
        ));
    }

    public function updateProfile(Request $request): RedirectResponse
    {
        $user = $request->user();
        $data = $request->validate([
            'name' => ['required', 'string', 'max:150'],
            'username' => ['nullable', 'string', 'max:80', 'alpha_dash', Rule::unique('users', 'username')->ignore($user->id)],
            'phone' => ['nullable', 'string', 'max:20', Rule::unique('users', 'phone')->ignore($user->id)],
        ]);
        $phoneChanged = $user->phone !== ($data['phone'] ?? null);
        $user->forceFill([
            'name' => $data['name'],
            'username' => $data['username'] ?? null,
            'phone' => $data['phone'] ?? null,
            'phone_verified_at' => $phoneChanged ? null : $user->phone_verified_at,
        ])->save();

        $this->recordUserAction($request, 'account.profile.updated', ['phone_verification_reset' => $phoneChanged]);

        return back()->with('status', $phoneChanged
            ? 'Profile updated. Verify the changed phone number before relying on it for recovery.'
            : 'Profile updated.');
    }

    public function changePassword(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'current_password' => ['required', 'current_password:web'],
            'password' => ['required', 'string', 'min:12', 'max:128', 'confirmed'],
        ]);
        $user = $request->user();
        $currentSessionId = $request->session()->getId();

        DB::transaction(function () use ($request, $user, $data, $currentSessionId): void {
            $user->forceFill([
                'password' => $data['password'],
                'password_changed_at' => now(),
                'force_password_change' => false,
                'remember_token' => Str::random(60),
            ])->save();

            $tokenIds = DB::table('oauth_access_tokens')->where('user_id', $user->id)
                ->where('revoked', false)->pluck('id');
            if ($tokenIds->isNotEmpty()) {
                DB::table('oauth_refresh_tokens')->whereIn('access_token_id', $tokenIds)
                    ->where('revoked', false)->update(['revoked' => true]);
                DB::table('oauth_access_tokens')->whereIn('id', $tokenIds)
                    ->update(['revoked' => true, 'updated_at' => now()]);
            }
            if (config('session.driver') === 'database') {
                DB::connection(config('session.connection'))->table(config('session.table', 'sessions'))
                    ->where('user_id', $user->id)->where('id', '<>', $currentSessionId)->delete();
            }
            DB::table('trusted_devices')->where('user_id', $user->id)->whereNull('revoked_at')
                ->update(['revoked_at' => now(), 'updated_at' => now()]);
            $this->recordUserAction($request, 'auth.password_changed', ['other_sessions_revoked' => true]);
        });

        $request->session()->regenerate();

        return back()->with('status', 'Password changed. Other active sessions, OAuth grants, and trusted devices were revoked.');
    }

    public function revokeSession(Request $request, string $reference): RedirectResponse
    {
        abort_unless(preg_match('/^[a-f0-9]{64}$/', $reference) === 1, 404);
        abort_if(config('session.driver') !== 'database', 409, 'Session management is not available for this session driver.');

        $table = DB::connection(config('session.connection'))->table(config('session.table', 'sessions'));
        $sessions = $table->where('user_id', $request->user()->id)
            ->where('id', '<>', $request->session()->getId())->get(['id']);
        $sessionId = $sessions->first(fn (object $session): bool => hash_equals(
            hash_hmac('sha256', $session->id, (string) config('app.key')),
            $reference
        ))?->id;

        abort_unless($sessionId, 404);
        $table->where('user_id', $request->user()->id)->where('id', $sessionId)->delete();
        $this->recordUserAction($request, 'auth.session.revoked', ['reference' => $reference]);

        return back()->with('status', 'The selected session was revoked.');
    }

    public function revokeConnectedApp(Request $request, string $clientId): RedirectResponse
    {
        abort_unless(Str::isUuid($clientId), 404);
        $userId = $request->user()->id;

        $count = DB::transaction(function () use ($request, $clientId, $userId): int {
            $tokenIds = DB::table('oauth_access_tokens')->where('user_id', $userId)
                ->where('client_id', $clientId)->where('revoked', false)->lockForUpdate()->pluck('id');
            $oidcTokenIds = DB::table('oidc_access_tokens')->where('user_id', $userId)
                ->where('oauth_client_id', $clientId)->whereNull('revoked_at')->lockForUpdate()->pluck('id');
            if ($tokenIds->isEmpty() && $oidcTokenIds->isEmpty()) {
                return 0;
            }
            DB::table('oauth_refresh_tokens')->whereIn('access_token_id', $tokenIds)
                ->where('revoked', false)->update(['revoked' => true]);
            $count = DB::table('oauth_access_tokens')->whereIn('id', $tokenIds)
                ->where('revoked', false)->update(['revoked' => true, 'updated_at' => now()]);
            $oidcCount = $oidcTokenIds->isEmpty() ? 0 : DB::table('oidc_access_tokens')
                ->whereIn('id', $oidcTokenIds)->whereNull('revoked_at')->update(['revoked_at' => now(), 'updated_at' => now()]);
            $this->recordUserAction($request, 'oauth.user_grant.revoked', [
                'client_id' => $clientId,
                'passport_token_count' => $count,
                'oidc_token_count' => $oidcCount,
            ]);

            return $count + $oidcCount;
        });

        abort_if($count === 0, 404);

        return back()->with('status', 'Connected application access was revoked.');
    }

    private function recordUserAction(Request $request, string $action, array $details): void
    {
        $user = $request->user();
        AuditLog::recordEntry($request, $user, $action, $details);
        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $user->id,
            'event_type' => $action,
            'result' => 'success',
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
            'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
            'context' => json_encode($details, JSON_THROW_ON_ERROR),
            'occurred_at' => now(),
        ]);
    }
}
