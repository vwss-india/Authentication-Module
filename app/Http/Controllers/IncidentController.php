<?php

namespace App\Http\Controllers;

use App\Models\AuditLog;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\Response;

class IncidentController extends Controller
{
    private const array STATUS_TRANSITIONS = [
        'new' => ['investigating'],
        'investigating' => ['contained', 'resolved'],
        'contained' => ['investigating', 'resolved'],
        'resolved' => ['investigating', 'closed'],
        'closed' => [],
    ];

    public function userReports(Request $request): View|JsonResponse
    {
        $reports = DB::table('security_incidents')->where('user_id', $request->user()->id)
            ->orderByDesc('submitted_at')->paginate(20)->withQueryString();

        return $this->wantsJson($request)
            ? response()->json($reports)
            : view('incidents.index', compact('reports'));
    }

    public function submitReport(Request $request): Response|JsonResponse
    {
        $data = $request->validate([
            'category' => ['required', 'in:unfamiliar_login,unfamiliar_device,account_change,suspected_compromise,other'],
            'description' => ['required', 'string', 'min:15', 'max:5000'],
        ]);
        $user = $request->user();
        $reference = (string) Str::uuid();

        DB::transaction(function () use ($request, $user, $data, $reference): void {
            $incidentId = DB::table('security_incidents')->insertGetId([
                'reference' => $reference,
                'user_id' => $user->id,
                'category' => $data['category'],
                'description' => $data['description'],
                'severity' => 'medium',
                'status' => 'new',
                'assigned_admin_user_id' => null,
                'submitted_at' => now(),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            DB::table('incident_investigation_entries')->insert([
                'security_incident_id' => $incidentId,
                'actor_user_id' => $user->id,
                'entry_type' => 'user_reported',
                'body' => 'Report received.',
                'details' => json_encode(['category' => $data['category']], JSON_THROW_ON_ERROR),
                'recorded_at' => now(),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            $this->recordEvent($request, $user->id, 'security.incident.reported', 'success', ['reference' => $reference]);
            AuditLog::recordEntry($request, $user, 'security.incident.reported', ['reference' => $reference]);
        });

        if ($this->wantsJson($request)) {
            return response()->json(['message' => 'Your report was received.', 'reference' => $reference], 201);
        }

        return redirect()->route('incidents.show', $reference)->with('status', 'Your report was received. Save the reference shown on this page.');
    }

    public function showUserReport(Request $request, string $reference): View|JsonResponse
    {
        $incident = DB::table('security_incidents')->where('reference', $reference)
            ->where('user_id', $request->user()->id)->firstOrFail();
        $updates = DB::table('incident_investigation_entries')
            ->where('security_incident_id', $incident->id)
            ->whereIn('entry_type', ['user_reported', 'status_update', 'user_update'])
            ->orderBy('recorded_at')->get(['entry_type', 'body', 'recorded_at']);

        return $this->wantsJson($request)
            ? response()->json(['incident' => $incident, 'updates' => $updates])
            : view('incidents.show', compact('incident', 'updates'));
    }

    public function adminIncidents(Request $request): View|JsonResponse
    {
        $filters = $request->validate([
            'status' => ['nullable', 'in:new,investigating,contained,resolved,closed'],
            'severity' => ['nullable', 'in:low,medium,high,critical'],
        ]);
        $query = DB::table('security_incidents')->leftJoin('users', 'users.id', '=', 'security_incidents.user_id')
            ->leftJoin('users as assigned_users', 'assigned_users.id', '=', 'security_incidents.assigned_admin_user_id')
            ->select(['security_incidents.*', 'users.email as reporter_email', 'assigned_users.name as assignee_name']);
        if (! empty($filters['status'])) {
            $query->where('security_incidents.status', $filters['status']);
        }
        if (! empty($filters['severity'])) {
            $query->where('security_incidents.severity', $filters['severity']);
        }
        $incidents = $query->orderByRaw("CASE security_incidents.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END")
            ->orderByDesc('security_incidents.submitted_at')->paginate(25)->withQueryString();

        return $this->wantsJson($request)
            ? response()->json($incidents)
            : view('admin.incidents.index', compact('incidents', 'filters'));
    }

    public function showAdminIncident(Request $request, string $reference): View|JsonResponse
    {
        $incident = DB::table('security_incidents')->where('reference', $reference)->firstOrFail();
        $reporter = $incident->user_id ? DB::table('users')->where('id', $incident->user_id)->first(['id', 'email', 'public_id', 'status']) : null;
        $events = $incident->user_id ? DB::table('security_events')->where('user_id', $incident->user_id)
            ->where('occurred_at', '>=', now()->parse($incident->submitted_at)->subDays(30))
            ->orderByDesc('occurred_at')->limit(100)->get() : collect();
        $entries = DB::table('incident_investigation_entries')->where('security_incident_id', $incident->id)
            ->orderBy('recorded_at')->get();
        $transitions = self::STATUS_TRANSITIONS[$incident->status] ?? [];

        return $this->wantsJson($request)
            ? response()->json(['incident' => $incident, 'reporter' => $reporter, 'security_events' => $events, 'history' => $entries, 'allowed_transitions' => $transitions])
            : view('admin.incidents.show', compact('incident', 'reporter', 'events', 'entries', 'transitions'));
    }

    public function updateIncident(Request $request, string $reference): Response|JsonResponse
    {
        $data = $request->validate([
            'status' => ['nullable', 'in:new,investigating,contained,resolved,closed'],
            'severity' => ['nullable', 'in:low,medium,high,critical'],
            'assign_to_self' => ['nullable', 'boolean'],
        ]);
        $actor = $request->user();

        DB::transaction(function () use ($request, $reference, $data, $actor): void {
            $incident = DB::table('security_incidents')->where('reference', $reference)->lockForUpdate()->first();
            abort_unless($incident, 404);
            $changes = [];
            if (! empty($data['status'])) {
                abort_unless(in_array($data['status'], self::STATUS_TRANSITIONS[$incident->status] ?? [], true), 422, 'That incident status transition is not allowed.');
                $changes['status'] = $data['status'];
                $this->addEntry((int) $incident->id, $actor->id, 'status_update', 'Status changed from '.ucfirst($incident->status).' to '.ucfirst($data['status']).'.', [
                    'from' => $incident->status,
                    'to' => $data['status'],
                ]);
            }
            if (! empty($data['severity']) && $data['severity'] !== $incident->severity) {
                $changes['severity'] = $data['severity'];
                $this->addEntry((int) $incident->id, $actor->id, 'severity_update', 'Severity changed to '.ucfirst($data['severity']).'.', ['severity' => $data['severity']]);
            }
            if (array_key_exists('assign_to_self', $data) && $data['assign_to_self']) {
                $changes['assigned_admin_user_id'] = $actor->id;
                $this->addEntry((int) $incident->id, $actor->id, 'assignment', 'Investigator assignment updated.', ['assigned_admin_user_id' => $actor->id]);
            }
            abort_if($changes === [], 422, 'Choose a valid incident change.');
            $changes['updated_at'] = now();
            DB::table('security_incidents')->where('id', $incident->id)->update($changes);
            AuditLog::recordEntry($request, $actor, 'admin.incident.updated', ['reference' => $reference, 'changes' => $changes]);
        });

        return $this->wantsJson($request)
            ? response()->json(['message' => 'Investigation updated.'])
            : back()->with('status', 'Investigation updated.');
    }

    public function addInvestigationEntry(Request $request, string $reference): Response|JsonResponse
    {
        $data = $request->validate([
            'entry_type' => ['required', 'in:note,finding'],
            'body' => ['required', 'string', 'min:3', 'max:5000'],
        ]);
        $incident = DB::table('security_incidents')->where('reference', $reference)->firstOrFail();

        DB::transaction(function () use ($request, $incident, $data): void {
            $this->addEntry((int) $incident->id, $request->user()->id, $data['entry_type'], $data['body']);
            AuditLog::recordEntry($request, $request->user(), 'admin.incident.entry_added', [
                'reference' => $incident->reference,
                'entry_type' => $data['entry_type'],
            ]);
        });

        return $this->wantsJson($request)
            ? response()->json(['message' => 'Investigation entry recorded.'], 201)
            : back()->with('status', 'Investigation entry recorded.');
    }

    public function remediateSessions(Request $request, string $reference): Response|JsonResponse
    {
        $request->validate(['confirmed' => ['required', 'accepted']]);
        $incident = DB::table('security_incidents')->where('reference', $reference)->firstOrFail();
        abort_unless($incident->user_id, 409, 'The reported account is no longer available.');
        $actor = $request->user();

        $counts = DB::transaction(function () use ($request, $incident, $actor, $reference): array {
            $tokenIds = DB::table('oauth_access_tokens')->where('user_id', $incident->user_id)
                ->where('revoked', false)->lockForUpdate()->pluck('id');
            $refreshCount = $tokenIds->isEmpty() ? 0 : DB::table('oauth_refresh_tokens')
                ->whereIn('access_token_id', $tokenIds)->where('revoked', false)->update(['revoked' => true]);
            $tokenCount = $tokenIds->isEmpty() ? 0 : DB::table('oauth_access_tokens')
                ->whereIn('id', $tokenIds)->where('revoked', false)->update(['revoked' => true, 'updated_at' => now()]);
            $sessionCount = 0;
            if (config('session.driver') === 'database') {
                $sessionCount = DB::connection(config('session.connection'))->table(config('session.table', 'sessions'))
                    ->where('user_id', $incident->user_id)->where('id', '<>', $request->session()->getId())->delete();
            }
            $deviceCount = DB::table('trusted_devices')->where('user_id', $incident->user_id)
                ->whereNull('revoked_at')->update(['revoked_at' => now(), 'updated_at' => now()]);
            $counts = ['tokens' => $tokenCount, 'refresh_tokens' => $refreshCount, 'sessions' => $sessionCount, 'trusted_devices' => $deviceCount];
            $this->addEntry((int) $incident->id, $actor->id, 'remediation', 'Administrator revoked active sessions, tokens, and trusted devices.', $counts);
            AuditLog::recordEntry($request, $actor, 'admin.incident.sessions_revoked', ['reference' => $reference, ...$counts]);
            $this->recordEvent($request, $incident->user_id, 'admin.incident.sessions_revoked', 'success', ['reference' => $reference, ...$counts]);

            return $counts;
        });

        return $this->wantsJson($request)
            ? response()->json(['message' => 'Active sessions and trusted devices were revoked.', 'revoked' => $counts])
            : back()->with('status', 'Active sessions, OAuth tokens, refresh tokens, and trusted devices were revoked.');
    }

    private function addEntry(int $incidentId, int $actorId, string $type, string $body, array $details = []): void
    {
        DB::table('incident_investigation_entries')->insert([
            'security_incident_id' => $incidentId,
            'actor_user_id' => $actorId,
            'entry_type' => $type,
            'body' => $body,
            'details' => json_encode($details, JSON_THROW_ON_ERROR),
            'recorded_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function recordEvent(Request $request, int $userId, string $type, string $result, array $context): void
    {
        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $userId,
            'event_type' => $type,
            'result' => $result,
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
            'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
            'context' => json_encode($context, JSON_THROW_ON_ERROR),
            'occurred_at' => now(),
        ]);
    }

    private function wantsJson(Request $request): bool
    {
        return $request->is('api/*') || $request->expectsJson();
    }
}
