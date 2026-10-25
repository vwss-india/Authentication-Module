<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>@yield('title', 'VisionWeb Central Auth') · {{ config('app.name') }}</title>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="vwss-app">
<nav class="navbar is-fixed-top vwss-navbar" role="navigation" aria-label="Main navigation">
    <div class="navbar-brand"><a class="navbar-item has-text-weight-semibold vwss-navbar-brand" href="{{ route('home') }}"><span class="vwss-navbar-brand-mark" role="img" aria-label="VisionWeb"></span><span class="ml-2">Central Auth</span></a>
        <a role="button" class="navbar-burger" aria-label="menu" aria-expanded="false" data-target="portal-menu"><span></span><span></span><span></span></a>
    </div>
    <div id="portal-menu" class="navbar-menu"><div class="navbar-end">
        @auth
            <a class="navbar-item" href="{{ route('account') }}">Account</a>
            <a class="navbar-item" href="{{ route('security.settings') }}">Security settings</a>
            <form class="navbar-item" method="post" action="{{ route('logout') }}">@csrf<button class="button is-light is-small" type="submit">Sign out</button></form>
        @else
            <a class="navbar-item" href="{{ route('login') }}">Sign in</a>
            <a class="navbar-item" href="{{ route('register') }}">Create account</a>
        @endauth
    </div></div>
</nav>
<main class="section"><div class="container">
    @if (session('status'))<div class="notification is-success" role="status">{{ session('status') }}</div>@endif
    @if ($errors->any())<div class="notification is-danger" role="alert">{{ $errors->first() }}</div>@endif
    @yield('content')
    <footer class="has-text-grey is-size-7 mt-6">Central Auth handles identity and authentication. It does not monitor endpoint malware.</footer>
</div></main>
</body>
</html>
