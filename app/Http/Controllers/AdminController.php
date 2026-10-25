<?php

namespace App\Http\Controllers;

use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\Response;

class AdminController extends Controller
{
    public function dashboard(Request $request): View|JsonResponse
    {
        $statistics = [
            'users' => User::query()->count(),
            'active_users' => User::query()->where('status', 'active')->count(),
            'pending_users' => User::query()->where('status', 'pending')->count(),
            'open_alerts' => DB::table('security_alerts')->where('status', 'open')->count(),
        ];
        $alerts = DB::table('security_alerts')->orderByDesc('detected_at')->limit(10)->get();

        if ($this->wantsJson($request)) {
            return response()->json(['statistics' => $statistics, 'alerts' => $alerts]);
        }

        return view('admin.dashboard', compact('statistics', 'alerts'));
    }

    public function users(Request $request): View|JsonResponse
    {
        $filters = $request->validate([
            'q' => ['nullable', 'string', 'max:150'],
            'status' => ['nullable', 'in:pending,active,suspended,disabled'],
        ]);
        $query = User::query()->select(['id', 'public_id', 'name', 'email', 'status', 'email_verified_at', 'last_login_at', 'created_at']);

        if (! empty($filters['q'])) {
            $term = $filters['q'];
            $query->where(function ($query) use ($term): void {
                $query->where('name', 'like', '%'.$term.'%')
                    ->orWhere('email', 'like', '%'.$term.'%')
                    ->orWhere('public_id', 'like', '%'.$term.'%');
            });
        }

        if (! empty($filters['status'])) {
            $query->where('status', $filters['status']);
        }

        $users = $query->orderByDesc('created_at')->paginate(25)->withQueryString();

        if ($this->wantsJson($request)) {
            return response()->json($users);
        }

        return view('admin.users.index', compact('users', 'filters'));
    }

    public function showUser(Request $request, User $user): View|JsonResponse
    {
        $events = DB::table('security_events')->where('user_id', $user->id)
            ->orderByDesc('occurred_at')->limit(25)->get();
        $alerts = DB::table('security_alerts')->where('user_id', $user->id)
            ->orderByDesc('detected_at')->limit(25)->get();
        $isAdmin = DB::table('central_admins')->where('user_id', $user->id)
            ->whereNull('revoked_at')->exists();

        if ($this->wantsJson($request)) {
            return response()->json([
                'user' => $user->only(['public_id', 'name', 'username', 'email', 'phone', 'status', 'email_verified_at', 'last_login_at', 'last_login_ip', 'created_at']),
                'is_admin' => $isAdmin,
                'security_events' => $events,
                'alerts' => $alerts,
            ]);
        }

        return view('admin.users.show', compact('user', 'events', 'alerts', 'isAdmin'));
    }

    public function updateUserStatus(Request $request, User $user): Response|JsonResponse
    {
        $data = $request->validate([
            'status' => ['required', 'in:active,suspended,disabled'],
            'reason' => ['required', 'string', 'min:5', 'max:500'],
            'confirmed' => ['required', 'accepted'],
        ]);
        $actor = $request->user();

        abort_if($actor->is($user), 422, 'Administrators cannot change their own account status here.');
        abort_if(DB::table('central_admins')->where('user_id', $user->id)->whereNull('revoked_at')->exists(), 422, 'Admin accounts require the controlled console provisioning process.');
        abort_if($data['status'] === 'active' && ! $user->email_verified_at, 422, 'An account must verify its email before activation.');

        DB::transaction(function () use ($request, $user, $data, $actor): void {
            $lockedUser = User::query()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            $previousStatus = $lockedUser->status;
            $lockedUser->forceFill(['status' => $data['status']])->save();

            if ($data['status'] !== 'active') {
                $tokenIds = DB::table('oauth_access_tokens')
                    ->where('user_id', $lockedUser->id)->where('revoked', false)->pluck('id');
                if ($tokenIds->isNotEmpty()) {
                    DB::table('oauth_refresh_tokens')->whereIn('access_token_id', $tokenIds)
                        ->where('revoked', false)->update(['revoked' => true]);
                    DB::table('oauth_access_tokens')->whereIn('id', $tokenIds)
                        ->update(['revoked' => true, 'updated_at' => now()]);
                }
                DB::table('sessions')->where('user_id', $lockedUser->id)->delete();
                DB::table('trusted_devices')->where('user_id', $lockedUser->id)
                    ->whereNull('revoked_at')->update(['revoked_at' => now(), 'updated_at' => now()]);
            }

            $context = [
                'target_public_id' => $lockedUser->public_id,
                'from' => $previousStatus,
                'to' => $data['status'],
                'reason' => $data['reason'],
            ];
            AuditLog::recordEntry($request, $actor, 'admin.user.status_changed', $context);
            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => $lockedUser->id,
                'event_type' => 'admin.user.status_changed',
                'result' => 'success',
                'ip_address' => $request->ip(),
                'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
                'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
                'context' => json_encode(['actor_public_id' => $actor->public_id, ...$context], JSON_THROW_ON_ERROR),
                'occurred_at' => now(),
            ]);
        });

        if ($this->wantsJson($request)) {
            return response()->json(['message' => 'Account status updated.']);
        }

        return redirect()->route('admin.users.show', $user)->with('status', 'Account status updated.');
    }

    public function events(Request $request): View|JsonResponse
    {
        $events = DB::table('security_events')->leftJoin('users', 'users.id', '=', 'security_events.user_id')
            ->select(['security_events.*', 'users.email as user_email', 'users.public_id as user_public_id'])
            ->orderByDesc('occurred_at')->paginate(50)->withQueryString();

        if ($this->wantsJson($request)) {
            return response()->json($events);
        }

        return view('admin.events', compact('events'));
    }

    public function audit(Request $request): View|JsonResponse
    {
        $entries = DB::table('audit_logs')->orderByDesc('sequence_number')->paginate(50)->withQueryString();

        if ($this->wantsJson($request)) {
            return response()->json(['integrity' => AuditLog::verifyChain(), 'entries' => $entries]);
        }

        return view('admin.audit', ['entries' => $entries, 'integrity' => AuditLog::verifyChain()]);
    }

    public function alerts(Request $request): View|JsonResponse
    {
        $alerts = DB::table('security_alerts')->leftJoin('users', 'users.id', '=', 'security_alerts.user_id')
            ->select(['security_alerts.*', 'users.email as user_email'])
            ->orderByDesc('detected_at')->paginate(50)->withQueryString();

        if ($request->expectsJson()) {
            return response()->json($alerts);
        }

        return view('admin.alerts', compact('alerts'));
    }

    public function clients(Request $request): View|JsonResponse
    {
        $clients = DB::table('oauth_clients as clients')
            ->leftJoin('oidc_client_metadata as oidc', 'oidc.oauth_client_id', '=', 'clients.id')
            ->select([
                'clients.id', 'clients.name', 'clients.provider', 'clients.redirect_uris',
                'clients.grant_types', 'clients.revoked', 'clients.created_at',
                'oidc.client_type', 'oidc.subject_type', 'oidc.allowed_scopes', 'oidc.enabled as oidc_enabled',
            ])->orderBy('clients.name')->paginate(50)->withQueryString();

        if ($this->wantsJson($request)) {
            return response()->json($clients);
        }

        return view('admin.clients', compact('clients'));
    }

    public function revokeClient(Request $request, string $clientId): Response|JsonResponse
    {
        abort_unless(Str::isUuid($clientId), 404);
        $data = $request->validate([
            'reason' => ['required', 'string', 'min:5', 'max:500'],
            'confirmed' => ['required', 'accepted'],
        ]);
        $actor = $request->user();

        DB::transaction(function () use ($request, $clientId, $data, $actor): void {
            $client = DB::table('oauth_clients')->where('id', $clientId)->lockForUpdate()->first();
            abort_unless($client, 404);
            if (! $client->revoked) {
                DB::table('oauth_clients')->where('id', $clientId)->update(['revoked' => true, 'updated_at' => now()]);
                DB::table('oidc_client_metadata')->where('oauth_client_id', $clientId)->update(['enabled' => false, 'updated_at' => now()]);
                $tokenIds = DB::table('oauth_access_tokens')->where('client_id', $clientId)
                    ->where('revoked', false)->pluck('id');
                if ($tokenIds->isNotEmpty()) {
                    DB::table('oauth_refresh_tokens')->whereIn('access_token_id', $tokenIds)
                        ->where('revoked', false)->update(['revoked' => true]);
                    DB::table('oauth_access_tokens')->whereIn('id', $tokenIds)
                        ->update(['revoked' => true, 'updated_at' => now()]);
                }
                DB::table('oidc_access_tokens')->where('oauth_client_id', $clientId)
                    ->whereNull('revoked_at')->update(['revoked_at' => now(), 'updated_at' => now()]);
            }

            $details = ['client_id' => $clientId, 'client_name' => $client->name, 'reason' => $data['reason']];
            AuditLog::recordEntry($request, $actor, 'admin.oauth_client.revoked', $details);
            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(), 'user_id' => $actor->id,
                'event_type' => 'admin.oauth_client.revoked', 'result' => 'success',
                'ip_address' => $request->ip(), 'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
                'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
                'context' => json_encode($details, JSON_THROW_ON_ERROR), 'occurred_at' => now(),
            ]);
        });

        if ($this->wantsJson($request)) {
            return response()->json(['message' => 'OAuth client revoked.']);
        }

        return back()->with('status', 'OAuth client and its tokens were revoked.');
    }

    private function wantsJson(Request $request): bool
    {
        return $request->is('api/*') || $request->expectsJson();
    }
}
