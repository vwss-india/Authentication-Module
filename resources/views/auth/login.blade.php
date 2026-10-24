<div>
    <!-- It is not the man who has too little, but the man who craves more, that is poor. - Seneca -->
</div>
<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in to {{ config('app.name') }}</title>
</head>
<body>
    <main>
        <h1>Sign in to {{ config('app.name') }}</h1>
        @if (! empty($error))
            <p role="alert">{{ $error }}</p>
        @endif
        @if ($errors->any())
            <p role="alert">{{ $errors->first() }}</p>
        @endif
        <form method="post" action="{{ route('login.store') }}">
            @csrf
            <label for="email">Email</label>
            <input id="email" name="email" type="email" value="{{ $email ?? old('email') }}" required autocomplete="username">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" required autocomplete="current-password">
            @if ($mfaRequired ?? false)
                <label for="code">Authenticator or recovery code</label>
                <input id="code" name="code" type="text" required autocomplete="one-time-code">
                <p>Enter a current authenticator code or an unused recovery code.</p>
            @endif
            <button type="submit">Sign in</button>
        </form>
    </main>
</body>
</html>
