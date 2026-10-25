@extends('layouts.portal')
@section('title', 'Authorize application')
@section('content')
<section class="columns is-centered">
    <div class="column is-half-tablet is-two-fifths-widescreen">
        <div class="box">
            <h1 class="title is-3">Authorize {{ $client->name }}</h1>
            <p class="mb-2">This application is requesting access to your VisionWeb account.</p>
            <p class="mb-4"><strong>Signed in as:</strong> {{ $user->email }}</p>

            @if (count($scopes) > 0)
                <h2 class="title is-5">Requested permissions</h2>
                <ul class="mb-5">
                    @foreach ($scopes as $scope)
                        <li>{{ $scope->description ?: $scope->id }}</li>
                    @endforeach
                </ul>
            @else
                <p class="mb-5">This application is not requesting additional permissions.</p>
            @endif

            <div class="notification is-warning is-light" role="note">
                Approve only if you recognize this application. You can revoke connected applications from your security settings.
            </div>

            <div class="columns">
                <div class="column">
                    <form method="post" action="{{ route('passport.authorizations.approve') }}">
                        @csrf
                        <input type="hidden" name="auth_token" value="{{ $authToken }}">
                        <button class="button is-primary is-fullwidth" type="submit">Approve access</button>
                    </form>
                </div>
                <div class="column">
                    <form method="post" action="{{ route('passport.authorizations.deny') }}">
                        @csrf
                        @method('delete')
                        <input type="hidden" name="auth_token" value="{{ $authToken }}">
                        <button class="button is-light is-fullwidth" type="submit">Deny</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</section>
@endsection
