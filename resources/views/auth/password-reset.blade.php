<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="no-referrer">
    <title>Reset Password - {{ config('app.name') }}</title>
</head>
<body>
    <main>
        <h1>Reset your password</h1>
        <p>Enter your new password below.</p>

        <p id="message" role="status" aria-live="polite"></p>

        <form id="reset-form">
            <label for="email">Email</label>
            <input id="email" name="email" type="email"
                   autocomplete="username" required readonly>

            <label for="password">New password</label>
            <input id="password" name="password" type="password"
                   minlength="12" autocomplete="new-password"
                   required>

            <label for="password_confirmation">Confirm new password</label>
            <input id="password_confirmation"
                   name="password_confirmation" type="password"
                   minlength="12" autocomplete="new-password"
                   required>

            <button id="submit-button" type="submit">
                Reset password
            </button>
        </form>

        <p><a href="/login">Back to sign in</a></p>
    </main>

    <script>
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
            message.textContent =
                'Reset link is missing required information. Request a new password reset email.';
            form.hidden = true;
            return;
        }

        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            message.textContent = '';

            const password = document.getElementById('password').value;
            const confirmation =
                document.getElementById('password_confirmation').value;

            if (password !== confirmation) {
                message.textContent = 'Passwords do not match.';
                return;
            }

            button.disabled = true;
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

                const data = await response.json();

                if (!response.ok) {
                    const errors = data.errors
                        ? Object.values(data.errors).flat().join(' ')
                        : '';

                    message.textContent = errors ||
                        data.message || 'Password reset failed.';
                    return;
                }

                form.hidden = true;
                message.textContent =
                    'Password reset successfully. You can now sign in.';
            } catch {
                message.textContent =
                    'Unable to contact the server. Please try again.';
            } finally {
                button.disabled = false;
            }
        });
    })();
    </script>
</body>
</html>