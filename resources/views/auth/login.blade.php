@extends('layouts.portal')
@section('title', 'Sign in')
@section('content')
<section class="columns is-centered"><div class="column is-half-tablet is-one-third-widescreen"><div class="box">
    <h1 class="title is-3">Sign in</h1><p class="mb-5">Access your VisionWeb identity account.</p>
    @if (! empty($error))<div class="notification is-danger" role="alert">{{ $error }}</div>@endif
    @if ($errors->any())<div class="notification is-danger" role="alert">{{ $errors->first() }}</div>@endif
    <form method="post" action="{{ route('login.store') }}">
        @csrf
        <div class="field"><label class="label" for="email">Email</label><div class="control"><input class="input" id="email" name="email" type="email" value="{{ $email ?? old('email') }}" required autocomplete="username"></div></div>
        <div class="field"><label class="label" for="password">Password</label><div class="control"><input class="input" id="password" name="password" type="password" required autocomplete="current-password"></div></div>
        @if ($mfaRequired ?? false)<div class="field"><label class="label" for="code">Authenticator or recovery code</label><div class="control"><input class="input" id="code" name="code" type="text" required autocomplete="one-time-code"></div><p class="help">Enter a current authenticator code or an unused recovery code.</p></div>@endif
        <button class="button is-primary is-fullwidth" type="submit">Sign in</button>
    </form>
    <div class="has-text-centered my-4"><span class="has-text-grey">or</span></div>
    <button class="button is-light is-fullwidth" id="passkey-login" type="button">Sign in with a passkey</button>
    <div id="passkey-message" class="notification is-hidden mt-4" role="status" aria-live="polite"></div>
    <form id="passkey-mfa-form" class="box mt-4" hidden><p class="mb-3">Your passkey is verified. Enter your authenticator code to finish signing in.</p><label class="label" for="passkey-mfa-code">Authenticator code</label><input class="input mb-3" id="passkey-mfa-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required><button class="button is-primary is-fullwidth" type="submit">Continue</button></form>
    <p class="mt-4"><a href="{{ route('password.request') }}">Forgot your password?</a></p>
    <p class="mt-2"><a href="{{ route('verification.notice') }}">Verify your email</a> · <a href="{{ route('register') }}">Create an account</a></p>
 </div></div></section>
<script nonce="{{ request()->attributes->get('csp_nonce') }}">
(() => {
    const button = document.getElementById('passkey-login');
    const message = document.getElementById('passkey-message');
    const mfaForm = document.getElementById('passkey-mfa-form');
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
    let mfaChallenge = null;
    const show = (text, ok = false) => { message.className = `notification ${ok ? 'is-success' : 'is-danger'} mt-4`; message.textContent = text; };
    const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), char => char.charCodeAt(0));
    const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    const send = async (url, body) => { const response = await fetch(url, {method: 'POST', headers: {'Accept': 'application/json', 'Content-Type': 'application/json'}, body: JSON.stringify(body)}); const result = await response.json().catch(() => ({})); if (!response.ok) throw new Error(result.message || result.error || 'Passkey sign-in failed.'); return result; };
    const establishSession = async token => {
        const response = await fetch('{{ route('login.passkey.session') }}', {method: 'POST', credentials: 'same-origin', headers: {'Accept': 'application/json', 'X-CSRF-TOKEN': csrf, 'Authorization': `Bearer ${token}`}});
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(result.message || 'The browser session could not be established. Please try again.');
        show('Passkey sign-in complete. Redirecting…', true);
        window.location.assign('{{ route('account') }}');
    };
    button.addEventListener('click', async () => {
        button.disabled = true;
        show('Contacting your authenticator…', true);
        try {
            if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('This browser does not support passkeys.');
            const options = await send('/api/v1/auth/passkeys/authentication/options', {});
            const publicKey = options.public_key;
            publicKey.challenge = decode(publicKey.challenge);
            (publicKey.allowCredentials || []).forEach(item => { item.id = decode(item.id); });
            const credential = await navigator.credentials.get({publicKey});
            if (!credential) throw new Error('Passkey sign-in was cancelled.');
            const assertion = {id: credential.id, rawId: encode(credential.rawId), type: credential.type, response: {authenticatorData: encode(credential.response.authenticatorData), clientDataJSON: encode(credential.response.clientDataJSON), signature: encode(credential.response.signature), userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null}};
            const result = await send(`/api/v1/auth/passkeys/authentication/${options.challenge_id}/verify`, assertion);
            if (result.mfa_required) { mfaChallenge = result.challenge_token; mfaForm.hidden = false; document.getElementById('passkey-mfa-code').focus(); show('Passkey verified. Complete the authenticator check to continue.', true); return; }
            await establishSession(result.access_token);
        } catch (error) { show(error.message || 'Passkey sign-in failed.'); button.disabled = false; }
    });
    mfaForm.addEventListener('submit', async event => {
        event.preventDefault();
        const submit = mfaForm.querySelector('button'); submit.disabled = true;
        try {
            const result = await send('/api/v1/auth/login/2fa', {challenge_token: mfaChallenge, code: document.getElementById('passkey-mfa-code').value, device_name: 'VisionWeb Browser Session'});
            await establishSession(result.access_token);
        } catch (error) { show(error.message || 'Authenticator verification failed.'); submit.disabled = false; }
    });
})();
</script>
@endsection
