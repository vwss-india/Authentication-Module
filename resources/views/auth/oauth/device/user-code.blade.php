@extends('layouts.portal')
@section('title', 'Authorize a device')
@section('content')
<section class="columns is-centered">
    <div class="column is-half-tablet is-one-third-widescreen">
        <div class="box">
            <h1 class="title is-3">Authorize a device</h1>
            <p class="mb-4">Enter the one-time code shown on the device you are signing in to.</p>

            @if ($errors->has('user_code'))
                <div class="notification is-danger" role="alert">{{ $errors->first('user_code') }}</div>
            @endif

            <form method="get" action="{{ route('passport.device.authorizations.authorize') }}">
                <div class="field">
                    <label class="label" for="user_code">Device code</label>
                    <input class="input" id="user_code" name="user_code" value="{{ old('user_code') }}" required autocomplete="one-time-code" aria-describedby="device-code-help">
                    <p class="help" id="device-code-help">Only enter a code from a device you control.</p>
                </div>
                <button class="button is-primary is-fullwidth" type="submit">Continue</button>
            </form>
        </div>
    </div>
</section>
@endsection
