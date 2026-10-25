<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>@yield('title', 'Master Admin') · {{ config('app.name') }}</title>@vite(['resources/css/app.css', 'resources/js/app.js'])</head>
<body class="vwss-app">
<nav class="navbar is-fixed-top vwss-navbar" role="navigation" aria-label="Master admin navigation"><div class="navbar-brand"><a class="navbar-item has-text-weight-semibold vwss-navbar-brand" href="{{ route('admin.dashboard') }}"><span class="vwss-navbar-brand-mark" role="img" aria-label="VisionWeb"></span><span class="ml-2">Master Admin</span></a><a role="button" class="navbar-burger" aria-label="menu" aria-expanded="false" data-target="admin-menu"><span></span><span></span><span></span></a></div>
<div id="admin-menu" class="navbar-menu"><div class="navbar-end"><a class="navbar-item" href="{{ route('home') }}">User portal</a><form class="navbar-item" method="post" action="{{ route('logout') }}">@csrf<button class="button is-light is-small" type="submit">Sign out</button></form></div></div></nav>
<main class="section"><div class="container">@if (session('status'))<div class="notification is-success" role="status">{{ session('status') }}</div>@endif @if ($errors->any())<div class="notification is-danger" role="alert">{{ $errors->first() }}</div>@endif
@php($adminPermissions = request()->attributes->get('central_admin_permissions', []))
<div class="columns"><aside class="column is-one-quarter"><nav class="menu box" aria-label="Admin sections"><p class="menu-label">Operations</p><ul class="menu-list">
@if (in_array('*', $adminPermissions, true) || in_array('dashboard.read', $adminPermissions, true))<li><a href="{{ route('admin.dashboard') }}">Dashboard</a></li>@endif
@if (in_array('*', $adminPermissions, true) || in_array('users.read', $adminPermissions, true))<li><a href="{{ route('admin.users.index') }}">Users</a></li>@endif
@if (in_array('*', $adminPermissions, true) || in_array('oauth.read', $adminPermissions, true))<li><a href="{{ route('admin.clients') }}">OAuth clients</a></li>@endif
@if (in_array('*', $adminPermissions, true) || in_array('products.read', $adminPermissions, true))<li><a href="{{ route('admin.products') }}">Products & subscriptions</a></li>@endif
@if (in_array('*', $adminPermissions, true) || in_array('security.read', $adminPermissions, true))<li><a href="{{ route('admin.events') }}">Security events</a><a href="{{ route('admin.alerts') }}">Security alerts</a></li>@endif
@if (in_array('*', $adminPermissions, true) || in_array('incidents.read', $adminPermissions, true))<li><a href="{{ route('admin.incidents.index') }}">Incident investigations</a></li>@endif
@if (in_array('*', $adminPermissions, true) || in_array('security.audit', $adminPermissions, true))<li><a href="{{ route('admin.audit') }}">Audit integrity</a></li>@endif
</ul></nav></aside><section class="column">@yield('content')</section></div>
<footer class="has-text-grey is-size-7 mt-5">Authentication evidence is contextual and does not establish a person's identity. Central Auth does not detect endpoint malware.</footer></div></main></body></html>
