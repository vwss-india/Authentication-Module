<?php

use App\Http\Controllers\AccountSecurityController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\Api\V1\Auth\MfaController;
use App\Http\Controllers\Api\V1\Auth\WebSessionController;
use App\Http\Controllers\Api\V1\OidcController;
use App\Http\Controllers\Api\V1\WebAuthnController;
use App\Http\Controllers\IncidentController;
use App\Http\Controllers\ProductAccessController;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
})->name('home');

Route::middleware(['auth:web', 'active.account'])->group(function (): void {
    Route::get('/account', fn () => view('account', ['user' => request()->user()]))
        ->name('account');
    Route::get('/account/products', [ProductAccessController::class, 'index'])->name('products.index');
    Route::get('/account/products/{organizationPublicId}/members', [ProductAccessController::class, 'manageMembers'])
        ->whereUuid('organizationPublicId')->name('products.members');
    Route::post('/account/products/{organizationPublicId}/members', [ProductAccessController::class, 'assignMember'])
        ->whereUuid('organizationPublicId')->middleware('security.throttle:10,1')->name('products.members.assign');
    Route::delete('/account/products/{organizationPublicId}/members/{memberPublicId}', [ProductAccessController::class, 'revokeMember'])
        ->whereUuid('organizationPublicId')->whereUuid('memberPublicId')->middleware('security.throttle:10,1')->name('products.members.revoke');
    Route::get('/account/security', function () {
        $events = DB::table('security_events')
            ->where('user_id', request()->user()->id)
            ->orderByDesc('occurred_at')
            ->limit(20)
            ->get();

        return view('security', compact('events'));
    })->name('security');

    Route::get('/account/security/settings', [AccountSecurityController::class, 'settings'])
        ->name('security.settings');
    Route::post('/account/profile', [AccountSecurityController::class, 'updateProfile'])
        ->middleware('security.throttle:10,1')->name('account.profile.update');
    Route::post('/account/password', [AccountSecurityController::class, 'changePassword'])
        ->middleware('security.throttle:5,1')->name('account.password.update');
    Route::delete('/account/security/sessions/{reference}', [AccountSecurityController::class, 'revokeSession'])
        ->where('reference', '[a-f0-9]{64}')->middleware('security.throttle:10,1')->name('security.sessions.revoke');
    Route::delete('/account/security/apps/{clientId}', [AccountSecurityController::class, 'revokeConnectedApp'])
        ->whereUuid('clientId')->middleware('security.throttle:10,1')->name('security.apps.revoke');
    Route::get('/account/security/reports', [IncidentController::class, 'userReports'])->name('incidents.index');
    Route::post('/account/security/reports', [IncidentController::class, 'submitReport'])
        ->middleware('security.throttle:5,1')->name('incidents.store');
    Route::get('/account/security/reports/{reference}', [IncidentController::class, 'showUserReport'])
        ->whereUuid('reference')->name('incidents.show');

    Route::prefix('account/security/actions')->name('security.actions.')->group(function (): void {
        Route::get('/mfa/status', [MfaController::class, 'status'])->name('mfa.status');
        Route::post('/mfa/setup', [MfaController::class, 'setupTotp'])->middleware('security.throttle:5,1')->name('mfa.setup');
        Route::post('/mfa/confirm', [MfaController::class, 'confirmTotp'])->middleware('security.throttle:5,1')->name('mfa.confirm');
        Route::post('/mfa/disable', [MfaController::class, 'disableTotp'])->middleware('security.throttle:5,1')->name('mfa.disable');
        Route::post('/mfa/recovery-codes', [MfaController::class, 'regenerateRecoveryCodes'])->middleware('security.throttle:5,1')->name('mfa.recovery-codes');
        Route::get('/devices', [MfaController::class, 'trustedDevices'])->name('devices.index');
        Route::delete('/devices/{id}', [MfaController::class, 'revokeTrustedDevice'])->whereNumber('id')->name('devices.revoke');
        Route::post('/devices/revoke-all', [MfaController::class, 'revokeAllTrustedDevices'])->name('devices.revoke-all');
        Route::get('/passkeys', [WebAuthnController::class, 'credentials'])->name('passkeys.index');
        Route::post('/passkeys/registration/options', [WebAuthnController::class, 'registrationOptions'])->middleware('security.throttle:5,1')->name('passkeys.options');
        Route::post('/passkeys/registration/{challengeId}/verify', [WebAuthnController::class, 'verifyRegistration'])->whereUuid('challengeId')->middleware('security.throttle:5,1')->name('passkeys.verify');
        Route::delete('/passkeys/{publicId}', [WebAuthnController::class, 'revoke'])->whereUuid('publicId')->name('passkeys.revoke');
    });
});

Route::prefix('admin')->name('admin.')->middleware(['security.throttle:60,1', 'auth:web', 'central.admin'])->group(function (): void {
    Route::get('/', [AdminController::class, 'dashboard'])->middleware('central.admin.permission:dashboard.read')->name('dashboard');
    Route::get('/users', [AdminController::class, 'users'])->middleware('central.admin.permission:users.read')->name('users.index');
    Route::get('/users/{user}', [AdminController::class, 'showUser'])->middleware('central.admin.permission:users.read')->name('users.show');
    Route::post('/users/{user}/status', [AdminController::class, 'updateUserStatus'])
        ->middleware(['security.throttle:10,1', 'central.admin.permission:users.manage'])->name('users.status');
    Route::get('/security/events', [AdminController::class, 'events'])->middleware('central.admin.permission:security.read')->name('events');
    Route::get('/security/alerts', [AdminController::class, 'alerts'])->middleware('central.admin.permission:security.read')->name('alerts');
    Route::get('/security/audit', [AdminController::class, 'audit'])->middleware('central.admin.permission:security.audit')->name('audit');
    Route::get('/oauth-clients', [AdminController::class, 'clients'])->middleware('central.admin.permission:oauth.read')->name('clients');
    Route::post('/oauth-clients/{clientId}/revoke', [AdminController::class, 'revokeClient'])
        ->whereUuid('clientId')->middleware(['security.throttle:5,1', 'central.admin.permission:oauth.manage'])->name('clients.revoke');
    Route::get('/products', [ProductAccessController::class, 'adminCatalog'])->middleware('central.admin.permission:products.read')->name('products');
    Route::get('/security/incidents', [IncidentController::class, 'adminIncidents'])->middleware('central.admin.permission:incidents.read')->name('incidents.index');
    Route::get('/security/incidents/{reference}', [IncidentController::class, 'showAdminIncident'])
        ->whereUuid('reference')->middleware('central.admin.permission:incidents.read')->name('incidents.show');
    Route::post('/security/incidents/{reference}/update', [IncidentController::class, 'updateIncident'])
        ->whereUuid('reference')->middleware('central.admin.permission:incidents.manage')->name('incidents.update');
    Route::post('/security/incidents/{reference}/entries', [IncidentController::class, 'addInvestigationEntry'])
        ->whereUuid('reference')->middleware('central.admin.permission:incidents.manage')->name('incidents.entries');
    Route::post('/security/incidents/{reference}/remediate', [IncidentController::class, 'remediateSessions'])
        ->whereUuid('reference')->middleware(['security.throttle:5,1', 'central.admin.permission:incidents.remediate'])->name('incidents.remediate');
});

Route::get('/login', [WebSessionController::class, 'create'])->name('login');
Route::get('/register', fn () => view('auth.register'))->name('register');
Route::get('/verify-email', fn () => view('auth.verify-email'))->name('verification.notice');
Route::post('/login', [WebSessionController::class, 'store'])
    ->middleware('security.throttle:5,1')
    ->name('login.store');
Route::post('/login/passkey/session', [WebSessionController::class, 'establishPasskeySession'])
    ->middleware(['auth:api', 'active.account', 'security.throttle:5,1'])->name('login.passkey.session');

Route::get('/reset-password', function () {
    return response()
        ->view('auth.password-reset')
        ->header('Referrer-Policy', 'no-referrer')
        ->header('Cache-Control', 'no-store, private');
})->name('password.reset.form');

Route::get('/forgot-password', fn () => view('auth.forgot-password'))
    ->name('password.request');

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
