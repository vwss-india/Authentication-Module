<div>
    <!-- An unexamined life is not worth living. - Socrates -->
</div>
<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authorize a device</title>
</head>
<body>
    <main>
        <h1>Authorize a device</h1>
        <p>Enter the code displayed on your device.</p>
        @if ($errors->has('user_code'))
            <p role="alert">{{ $errors->first('user_code') }}</p>
        @endif
        <form method="get" action="{{ route('passport.device.authorizations.authorize') }}">
            <label for="user_code">Device code</label>
            <input id="user_code" name="user_code" value="{{ old('user_code') }}" required autocomplete="one-time-code">
            <button type="submit">Continue</button>
        </form>
    </main>
</body>
</html>
