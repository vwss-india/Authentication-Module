@extends('layouts.portal')
@section('title', 'Account security')
@section('content')
<header class="mb-5"><h1 class="title is-3">Account security</h1><p class="subtitle is-6">Recent sign-in and security events for your account</p></header>
<p class="mb-4"><a class="button is-primary is-light" href="{{ route('security.settings') }}">Manage security settings</a></p>
<p class="mb-4"><a class="button is-light" href="{{ route('incidents.index') }}">Report suspicious activity</a></p>
<section class="box"><h2 class="title is-5">Recent activity</h2>
    @if ($events->isEmpty())<p>No security activity is available yet.</p>@else
    <div class="table-container"><table class="table is-fullwidth"><thead><tr><th>Event</th><th>Result</th><th>Time</th></tr></thead><tbody>
    @foreach ($events as $event)<tr><td>{{ str($event->event_type)->replace('_', ' ')->title() }}</td><td>{{ ucfirst($event->result) }}</td><td>{{ \Illuminate\Support\Carbon::parse($event->occurred_at)->format('M j, Y g:i A') }}</td></tr>@endforeach
    </tbody></table></div>@endif
</section>
<section class="box"><h2 class="title is-5">If something looks wrong</h2><p>Change your password using the <a href="{{ route('password.request') }}">password recovery page</a>, then contact your VisionWeb product administrator if product access may be affected.</p></section>
@endsection
