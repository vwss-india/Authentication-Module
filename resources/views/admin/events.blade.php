@extends('admin.layout')
@section('title', 'Security events')
@section('content')
<h1 class="title is-3">Security events</h1><p class="mb-4">Recorded authentication evidence is contextual and is not proof of identity or malicious intent.</p><div class="box table-container"><table class="table is-fullwidth"><thead><tr><th>Time</th><th>User</th><th>Event</th><th>Result</th><th>IP</th><th>User agent</th></tr></thead><tbody>@forelse ($events as $event)<tr><td>{{ \Illuminate\Support\Carbon::parse($event->occurred_at)->format('M j, Y g:i A') }}</td><td>{{ $event->user_email ?? 'Unknown account' }}</td><td>{{ $event->event_type }}</td><td>{{ $event->result }}</td><td>{{ $event->ip_address ?? '—' }}</td><td>{{ \Illuminate\Support\Str::limit($event->user_agent ?? '—', 100) }}</td></tr>@empty<tr><td colspan="6">No events recorded.</td></tr>@endforelse</tbody></table></div>{{ $events->links() }}
@endsection
