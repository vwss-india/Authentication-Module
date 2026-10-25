@extends('layouts.portal')
@section('title', 'Reset password')
@section('content')
<section class="columns is-centered">
    <div class="column is-half-tablet is-one-third-widescreen">
        <div class="box">
            <h1 class="title is-3">Reset your password</h1>
            <p class="mb-4">Enter a new password for your account.</p>

            <p id="message" class="notification is-hidden" role="status" aria-live="polite"></p>

            <form id="reset-form">
                <div class="field">
                    <label class="label" for="email">Email</label>
                    <input class="input" id="email" name="email" type="email" autocomplete="username" required readonly>
                </div>
                <div class="field">
                    <label class="label" for="password">New password</label>
                    <input class="input" id="password" name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required>
                </div>
                <div class="field">
                    <label class="label" for="password_confirmation">Confirm new password</label>
                    <input class="input" id="password_confirmation" name="password_confirmation" type="password" minlength="12" maxlength="128" autocomplete="new-password" required>
                </div>
                <button id="submit-button" class="button is-primary is-fullwidth" type="submit">Reset password</button>
            </form>

            <p class="mt-4"><a href="{{ route('login') }}">Back to sign in</a></p>
        </div>
    </div>
</section>

<script nonce="{{ request()->attributes->get('csp_nonce') }}">
(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token') || '';
    const email = params.get('email') || '';

    // Remove the sensitive token from the visible browser URL.
    window.history.replaceState({}, document.title, '/reset-password');

    const form = document.getElementById('reset-form');
    const message = document.getElementById('message');
    const button = document.getElementById('submit-button');

    document.getElementById('email').value = email;

    if (!token || !email) {
        message.className = 'notification is-danger';
        message.textContent = 'Reset link is missing required information. Request a new password reset email.';
        form.hidden = true;
        return;
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        message.className = 'notification is-hidden';

        const password = document.getElementById('password').value;
        const confirmation = document.getElementById('password_confirmation').value;

        if (password !== confirmation) {
            message.className = 'notification is-danger';
            message.textContent = 'Passwords do not match.';
            return;
        }

        button.disabled = true;
        message.className = 'notification is-info';
        message.textContent = 'Resetting password…';

        try {
            const response = await fetch('/api/v1/auth/reset-password', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email,
                    token,
                    password,
                    password_confirmation: confirmation
                })
            });
            const data = await response.json().catch(() => ({}));

            if (!response.ok) {
                const errors = data.errors ? Object.values(data.errors).flat().join(' ') : '';
                message.className = 'notification is-danger';
                message.textContent = errors || data.message || 'Password reset failed.';
                return;
            }

            form.hidden = true;
            message.className = 'notification is-success';
            message.textContent = 'Password reset successfully. You can now sign in.';
        } catch {
            message.className = 'notification is-danger';
            message.textContent = 'Unable to contact the server. Please try again.';
        } finally {
            button.disabled = false;
        }
    });
})();
</script>
@endsection
