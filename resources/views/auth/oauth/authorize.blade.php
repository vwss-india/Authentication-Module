<div>
    <!-- Because you are alive, everything is possible. - Thich Nhat Hanh -->
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
        <p>{{ $client->name }} is requesting access to your VisionWeb account.</p>
        <p>Signed in as {{ $user->email }}.</p>
        @if (count($scopes) > 0)
            <h2>Requested access</h2>
            <ul>
                @foreach ($scopes as $scope)
                    <li>{{ $scope->description ?: $scope->id }}</li>
                @endforeach
            </ul>
        @else
            <p>This application is not requesting additional permissions.</p>
        @endif
        <form method="post" action="{{ route('passport.authorizations.approve') }}">
            @csrf
            <input type="hidden" name="auth_token" value="{{ $authToken }}">
            <button type="submit">Approve</button>
        </form>
        <form method="post" action="{{ route('passport.authorizations.deny') }}">
            @csrf
            @method('delete')
            <input type="hidden" name="auth_token" value="{{ $authToken }}">
            <button type="submit">Deny</button>
        </form>
    </main>
</body>
</html>
