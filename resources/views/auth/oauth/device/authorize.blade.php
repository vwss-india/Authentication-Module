<div>
    <!-- Very little is needed to make a happy life. - Marcus Aurelius -->
</div>
<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authorize {{ $client->name }}</title>
</head>
<body>
    <main>
        <h1>Authorize {{ $client->name }}</h1>
        <p>This device will be able to access your VisionWeb account as {{ $user->email }}.</p>
        @if (count($scopes) > 0)
            <h2>Requested access</h2>
            <ul>
                @foreach ($scopes as $scope)
                    <li>{{ $scope->description ?: $scope->id }}</li>
                @endforeach
            </ul>
        @endif
        <form method="post" action="{{ route('passport.device.authorizations.approve') }}">
            @csrf
            <input type="hidden" name="state" value="{{ $request->session()->get('state') }}">
            <input type="hidden" name="client_id" value="{{ $client->id }}">
            <input type="hidden" name="auth_token" value="{{ $authToken }}">
            <button type="submit">Approve device</button>
        </form>
        <form method="post" action="{{ route('passport.device.authorizations.deny') }}">
            @csrf
            @method('delete')
            <input type="hidden" name="state" value="{{ $request->session()->get('state') }}">
            <input type="hidden" name="client_id" value="{{ $client->id }}">
            <input type="hidden" name="auth_token" value="{{ $authToken }}">
            <button type="submit">Deny device</button>
        </form>
    </main>
</body>
</html>
