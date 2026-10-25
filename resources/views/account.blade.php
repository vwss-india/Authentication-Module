@extends('layouts.portal')
@section('title', 'Your account')
@section('content')
<header class="mb-5"><h1 class="title is-3">Your account</h1><p class="subtitle is-6">Identity and sign-in information</p></header>
<div class="columns"><div class="column is-two-thirds"><section class="box">
    <h2 class="title is-5">Profile</h2>
    <form method="post" action="{{ route('account.profile.update') }}">@csrf
        <div class="field"><label class="label" for="name">Name</label><input class="input" id="name" name="name" value="{{ old('name', $user->name) }}" maxlength="150" required></div>
        <div class="field"><label class="label" for="username">Username</label><input class="input" id="username" name="username" value="{{ old('username', $user->username) }}" maxlength="80" autocomplete="username"></div>
        <div class="field"><label class="label" for="phone">Phone</label><input class="input" id="phone" name="phone" type="tel" value="{{ old('phone', $user->phone) }}" maxlength="20" autocomplete="tel"><p class="help">Changing your phone clears its verification state.</p></div>
        <div class="field"><label class="label">Email</label><p>{{ $user->email }} · {{ $user->email_verified_at ? 'Verified' : 'Not verified' }}</p><p class="help">Email changes are not available in the current account workflow.</p></div>
        <p class="mb-4"><strong>Account status:</strong> {{ ucfirst($user->status) }} · <strong>Last sign-in:</strong> {{ $user->last_login_at?->format('M j, Y g:i A') ?? 'No sign-in recorded' }}</p>
        <button class="button is-primary" type="submit">Save profile</button>
    </form>
</section><section class="box"><h2 class="title is-5">Product access</h2><p>Access is decided by each product's membership, subscription, entitlement, and product-specific permissions.</p><a href="{{ route('products.index') }}">Review your product access</a></section></div>
<div class="column"><section class="box"><h2 class="title is-5">Password</h2><form method="post" action="{{ route('account.password.update') }}">@csrf
    <div class="field"><label class="label" for="current_password">Current password</label><input class="input" type="password" id="current_password" name="current_password" autocomplete="current-password" required></div>
    <div class="field"><label class="label" for="password">New password</label><input class="input" type="password" id="password" name="password" minlength="12" maxlength="128" autocomplete="new-password" required></div>
    <div class="field"><label class="label" for="password_confirmation">Confirm new password</label><input class="input" type="password" id="password_confirmation" name="password_confirmation" minlength="12" maxlength="128" autocomplete="new-password" required></div>
    <button class="button is-primary" type="submit">Change password</button></form></section><section class="box"><h2 class="title is-5">Protect your account</h2><p>Enable multi-factor authentication and review unfamiliar activity.</p><a href="{{ route('security.settings') }}">Manage security settings</a><br><a href="{{ route('security') }}">Review security activity</a></section></div></div>
@endsection
