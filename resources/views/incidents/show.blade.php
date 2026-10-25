@extends('layouts.portal')
@section('title', 'Report status')
@section('content')
<a href="{{ route('incidents.index') }}">← Your reports</a><header class="mt-4 mb-5"><h1 class="title is-3">Report {{ $incident->reference }}</h1><p class="subtitle is-6">Submitted {{ \Illuminate\Support\Carbon::parse($incident->submitted_at)->format('M j, Y g:i A') }} · Status: {{ ucfirst($incident->status) }}</p></header>
<section class="box"><h2 class="title is-5">Your description</h2><p class="mb-4">{{ $incident->description }}</p><p><strong>Category:</strong> {{ str($incident->category)->replace('_', ' ')->title() }}</p></section>
<section class="box"><h2 class="title is-5">Status updates</h2><ol>@foreach ($updates as $update)<li class="mb-3"><strong>{{ str($update->entry_type)->replace('_', ' ')->title() }}</strong> · {{ \Illuminate\Support\Carbon::parse($update->recorded_at)->format('M j, Y g:i A') }}<br>{{ $update->body }}</li>@endforeach</ol></section>
<section class="notification is-info"><strong>Protect your account:</strong> change your password, review sessions and connected applications, and contact your product administrator if product access may be affected. IP and device records are contextual and do not prove who used an account.</section>
@endsection
