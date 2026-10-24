<div>
    <!-- Nothing in life is to be feared, it is only to be understood. Now is the time to understand more, so that we may fear less. - Maria Skłodowska-Curie -->
</div>
<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authorize {{ $clientName }}</title>
</head>
<body>
    <main>
        <h1>Authorize {{ $clientName }}</h1>
        <p>This application is requesting access to selected VisionWeb account information.</p>
        <ul>
            @foreach ($scopes as $scope)
                <li>{{ $scope }}</li>
            @endforeach
        </ul>
        <form method="post" action="{{ route('oidc.approve') }}">
            @csrf
            <input type="hidden" name="approve" value="1">
            <button type="submit">Approve</button>
        </form>
        <form method="post" action="{{ route('oidc.approve') }}">
            @csrf
            <input type="hidden" name="approve" value="0">
            <button type="submit">Deny</button>
        </form>
    </main>
</body>
</html>
