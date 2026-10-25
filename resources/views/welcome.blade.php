@extends('layouts.portal')

@section('content')
<section class="hero is-medium">
    <div class="hero-body px-0">
        <p class="tag is-light mb-4">VisionWeb Central Identity</p>
        <h1 class="title is-1">One secure sign-in<br>for VisionWeb products.</h1>
        <p class="subtitle is-5 mt-4">Manage your identity and account security from one place. Product access is managed by each product and its entitlements.</p>
        <div class="buttons mt-5">
            @auth
                <a class="button is-primary is-rounded" href="{{ route('account') }}">Go to your account</a>
            @else
                <a class="button is-primary is-rounded" href="{{ route('login') }}">Sign in</a>
            @endauth
        </div>
    </div>
</section>
<div class="columns is-multiline">
    <div class="column is-one-third"><article class="box"><h2 class="title is-5">Your identity</h2><p>Review your account details and sign-in status in one secure place.</p></article></div>
    <div class="column is-one-third"><article class="box"><h2 class="title is-5">Account protection</h2><p>Use a unique password, enable multi-factor authentication, and review unfamiliar activity.</p></article></div>
    <div class="column is-one-third"><article class="box"><h2 class="title is-5">Product access</h2><p>Each VisionWeb product controls its own membership and permissions. A Central Auth sign-in alone does not grant product access.</p></article></div>
</div>
@endsection
