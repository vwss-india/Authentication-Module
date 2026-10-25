@extends('admin.layout')
@section('title', 'Security alerts')
@section('content')
<h1 class="title is-3">Security alerts</h1><div class="box table-container"><table class="table is-fullwidth"><thead><tr><th>Detected</th><th>User</th><th>Type</th><th>Severity</th><th>Status</th></tr></thead><tbody>@forelse ($alerts as $alert)<tr><td>{{ \Illuminate\Support\Carbon::parse($alert->detected_at)->format('M j, Y g:i A') }}</td><td>{{ $alert->email ?? 'Unknown account' }}</td><td>{{ $alert->alert_type }}</td><td>{{ $alert->severity }}</td><td>{{ $alert->status }}</td></tr>@empty<tr><td colspan="5">No alerts recorded.</td></tr>@endforelse</tbody></table></div>{{ $alerts->links() }}
@endsection
