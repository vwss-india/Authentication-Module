<?php

use App\Http\Controllers\Api\V1\Auth\WebSessionController;
use App\Http\Controllers\Api\V1\OidcController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/login', [WebSessionController::class, 'create'])->name('login');
Route::post('/login', [WebSessionController::class, 'store'])
    ->middleware('security.throttle:5,1')
    ->name('login.store');

Route::get('/reset-password', function () {
    return response()
        ->view('auth.password-reset')
        ->header('Referrer-Policy', 'no-referrer')
        ->header('Cache-Control', 'no-store, private');
})->name('password.reset.form');

Route::post('/logout', [WebSessionController::class, 'destroy'])
    ->middleware(['auth:web', 'security.throttle:10,1'])
    ->name('logout');

Route::get('/.well-known/openid-configuration', [OidcController::class, 'discovery'])
    ->name('oidc.discovery');
Route::get('/oidc/jwks', [OidcController::class, 'jwks'])
    ->name('oidc.jwks');
Route::get('/oidc/authorize', [OidcController::class, 'authorize'])
    ->middleware(['auth:web', 'security.throttle:20,1'])
    ->name('oidc.authorize');
Route::post('/oidc/authorize/approve', [OidcController::class, 'approve'])
    ->middleware(['auth:web', 'security.throttle:10,1'])
    ->name('oidc.approve');
Route::post('/oidc/token', [OidcController::class, 'token'])
    ->middleware('security.throttle:10,1')
    ->name('oidc.token');
Route::get('/oidc/userinfo', [OidcController::class, 'userinfo'])
    ->middleware('security.throttle:30,1')
    ->name('oidc.userinfo');
Route::post('/oidc/logout', [OidcController::class, 'logout'])
    ->middleware(['auth:web', 'security.throttle:10,1'])
    ->name('oidc.logout');
