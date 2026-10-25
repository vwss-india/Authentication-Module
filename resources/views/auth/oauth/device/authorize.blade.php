@extends('layouts.portal')
@section('title', 'Authorize device access')
@section('content')
<section class="columns is-centered">
    <div class="column is-half-tablet is-two-fifths-widescreen">
        <div class="box">
            <h1 class="title is-3">Authorize {{ $client->name }}</h1>
            <p class="mb-2">This device will be able to access your VisionWeb account as {{ $user->email }}.</p>

            @if (count($scopes) > 0)
                <h2 class="title is-5 mt-4">Requested permissions</h2>
                <ul class="mb-5">
                    @foreach ($scopes as $scope)
                        <li>{{ $scope->description ?: $scope->id }}</li>
                    @endforeach
                </ul>
            @endif

            <div class="notification is-warning is-light" role="note">
                Continue only if you entered this code for a device you control.
            </div>

            <div class="columns">
                <div class="column">
                    <form method="post" action="{{ route('passport.device.authorizations.approve') }}">
                        @csrf
                        <input type="hidden" name="state" value="{{ $request->session()->get('state') }}">
                        <input type="hidden" name="client_id" value="{{ $client->id }}">
                        <input type="hidden" name="auth_token" value="{{ $authToken }}">
                        <button class="button is-primary is-fullwidth" type="submit">Approve device</button>
                    </form>
                </div>
                <div class="column">
                    <form method="post" action="{{ route('passport.device.authorizations.deny') }}">
                        @csrf
                        @method('delete')
                        <input type="hidden" name="state" value="{{ $request->session()->get('state') }}">
                        <input type="hidden" name="client_id" value="{{ $client->id }}">
                        <input type="hidden" name="auth_token" value="{{ $authToken }}">
                        <button class="button is-light is-fullwidth" type="submit">Deny</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</section>
@endsection
