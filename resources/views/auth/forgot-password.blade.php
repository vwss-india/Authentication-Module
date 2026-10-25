@extends('layouts.portal')
@section('title', 'Password recovery')
@section('content')
<section class="columns is-centered"><div class="column is-half-tablet is-one-third-widescreen"><div class="box">
    <h1 class="title is-3">Recover your account</h1>
    <p class="mb-4">Choose a contact preference. Email is currently the available delivery channel; SMS and WhatsApp requests are sent to your registered email instead.</p>
    <div id="recovery-message" class="notification is-hidden" role="status" aria-live="polite"></div>
    <form id="recovery-form">
        <div class="field"><label class="label" for="email">Account email</label><input class="input" id="email" name="email" type="email" autocomplete="email" required maxlength="254"></div>
        <div class="field"><label class="label" for="channel">Preferred channel</label><div class="select is-fullwidth"><select id="channel" name="channel"><option value="email">Email</option><option value="sms">SMS (delivered by email for now)</option><option value="whatsapp">WhatsApp (delivered by email for now)</option></select></div></div>
        <p id="channel-note" class="help mb-4">Recovery instructions are sent by email.</p>
        <button id="recovery-submit" class="button is-primary is-fullwidth" type="submit">Send recovery instructions</button>
    </form>
    <p class="mt-4"><a href="{{ route('login') }}">Back to sign in</a></p>
</div></div></section>
<script nonce="{{ request()->attributes->get('csp_nonce') }}">
(() => {
    const form = document.getElementById('recovery-form');
    const channel = document.getElementById('channel');
    const note = document.getElementById('channel-note');
    const message = document.getElementById('recovery-message');
    const button = document.getElementById('recovery-submit');
    channel.addEventListener('change', () => {
        note.textContent = channel.value === 'email'
            ? 'Recovery instructions are sent by email.'
            : 'This channel is not configured. If the account is eligible, instructions will be sent to its registered email address.';
    });
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        button.disabled = true;
        message.className = 'notification is-info';
        message.textContent = 'Submitting your request…';
        try {
            const response = await fetch('/api/v1/auth/forgot-password', {
                method: 'POST', headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
                body: JSON.stringify({email: document.getElementById('email').value})
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.message || 'Unable to submit the request.');
            message.className = 'notification is-success';
            message.textContent = data.message + (channel.value === 'email' ? '' : ' SMS and WhatsApp delivery are not configured; use the registered email inbox.');
            form.reset();
        } catch (error) {
            message.className = 'notification is-danger';
            message.textContent = error.message || 'Unable to contact the server. Please try again.';
        } finally { button.disabled = false; }
    });
})();
</script>
@endsection
