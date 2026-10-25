<?php

use App\Http\Middleware\AuthenticateProductServer;
use App\Http\Middleware\ConfiguredTrustProxies;
use App\Http\Middleware\RecordPassportTokenFailures;
use App\Http\Middleware\RecordRateLimitEvent;
use App\Http\Middleware\RequireActiveAccount;
use App\Http\Middleware\RequireCentralAdmin;
use App\Http\Middleware\RequireCentralAdminPermission;
use App\Http\Middleware\RequireProductAccess;
use App\Http\Middleware\SecurityHeaders;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->prepend(RecordPassportTokenFailures::class);
        $middleware->append(SecurityHeaders::class);
        $middleware->replace(TrustProxies::class, ConfiguredTrustProxies::class);
        $middleware->alias([
            'product.server' => AuthenticateProductServer::class,
            'security.throttle' => RecordRateLimitEvent::class,
            'central.admin' => RequireCentralAdmin::class,
            'central.admin.permission' => RequireCentralAdminPermission::class,
            'active.account' => RequireActiveAccount::class,
            'product.access' => RequireProductAccess::class,
        ]);
        $middleware->validateCsrfTokens(except: ['oidc/token']);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();
