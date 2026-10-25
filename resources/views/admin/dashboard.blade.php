@extends('admin.layout')
@section('title', 'Admin dashboard')
@section('content')
<header class="mb-5"><h1 class="title is-3">Master Admin</h1><p class="subtitle is-6">Current persisted identity and security overview</p></header>
<div class="columns is-multiline">@foreach (['users' => 'Accounts', 'active_users' => 'Active accounts', 'pending_users' => 'Pending verification', 'open_alerts' => 'Open alerts'] as $key => $label)<div class="column is-half-tablet is-one-quarter-desktop"><article class="box"><p class="has-text-grey">{{ $label }}</p><p class="title is-3 mt-2">{{ number_format($statistics[$key]) }}</p></article></div>@endforeach</div>
<section class="box"><h2 class="title is-5">Recent security alerts</h2>@if ($alerts->isEmpty())<p>No alerts are recorded.</p>@else<div class="table-container"><table class="table is-fullwidth"><thead><tr><th>Type</th><th>Severity</th><th>Status</th><th>Detected</th></tr></thead><tbody>@foreach ($alerts as $alert)<tr><td>{{ $alert->alert_type }}</td><td>{{ ucfirst($alert->severity) }}</td><td>{{ ucfirst($alert->status) }}</td><td>{{ \Illuminate\Support\Carbon::parse($alert->detected_at)->format('M j, Y g:i A') }}</td></tr>@endforeach</tbody></table></div>@endif</section><a class="button is-primary" href="{{ route('admin.users.index') }}">Manage accounts</a>
@endsection
