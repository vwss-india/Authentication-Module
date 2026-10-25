<?php

use App\Http\Controllers\AdminController;
use App\Http\Controllers\Api\V1\Auth\AuthController;
use App\Http\Controllers\Api\V1\Auth\MfaController;
use App\Http\Controllers\Api\V1\Auth\PasswordRecoveryController;
use App\Http\Controllers\Api\V1\OidcController;
use App\Http\Controllers\Api\V1\WebAuthnController;
use App\Http\Controllers\IncidentController;
use App\Http\Middleware\RequireActiveAccount;
use App\Http\Middleware\RequireMfaChallenge;
use Illuminate\Support\Facades\Route;

Route::prefix('v1/auth')->group(function (): void {
    Route::post('/passkeys/authentication/options', [WebAuthnController::class, 'authenticationOptions'])
        ->middleware('security.throttle:10,1');
    Route::post('/passkeys/authentication/{challengeId}/verify', [WebAuthnController::class, 'verifyAuthentication'])
        ->middleware('security.throttle:10,1');

    Route::post('/register', [AuthController::class, 'register'])
        ->middleware('security.throttle:5,1');

    Route::post('/login', [AuthController::class, 'login'])
        ->middleware(['security.throttle:5,1', RequireMfaChallenge::class]);

    Route::post('/login/2fa', [MfaController::class, 'completeLogin'])
        ->middleware('security.throttle:5,1');

    Route::post('/email/verify', [AuthController::class, 'verifyEmail'])
        ->middleware('security.throttle:10,1');

    Route::post('/email/resend', [AuthController::class, 'resendVerification'])
        ->middleware('security.throttle:3,1');

    Route::post('/forgot-password', [PasswordRecoveryController::class, 'forgot'])
        ->middleware('security.throttle:5,1');

    Route::post('/reset-password', [PasswordRecoveryController::class, 'reset'])
        ->middleware('security.throttle:5,1');

    Route::middleware(['auth:api', RequireActiveAccount::class])->group(function (): void {
        Route::get('/me', [AuthController::class, 'me']);
        Route::post('/logout', [AuthController::class, 'logout']);
        Route::post('/logout-all', [AuthController::class, 'logoutAll']);

        Route::post('/phone/verify/request', [AuthController::class, 'requestPhoneVerification'])
            ->middleware('security.throttle:3,1');
        Route::post('/phone/verify', [AuthController::class, 'verifyPhone'])
            ->middleware('security.throttle:10,1');

        Route::get('/mfa/status', [MfaController::class, 'status']);
        Route::post('/mfa/totp/setup', [MfaController::class, 'setupTotp'])
            ->middleware('security.throttle:5,1');
        Route::post('/mfa/totp/confirm', [MfaController::class, 'confirmTotp'])
            ->middleware('security.throttle:5,1');
        Route::post('/mfa/totp/disable', [MfaController::class, 'disableTotp'])
            ->middleware('security.throttle:5,1');
        Route::post('/mfa/recovery-codes/regenerate', [MfaController::class, 'regenerateRecoveryCodes'])
            ->middleware('security.throttle:5,1');

        Route::get('/trusted-devices', [MfaController::class, 'trustedDevices']);
        Route::delete('/trusted-devices/{id}', [MfaController::class, 'revokeTrustedDevice'])
            ->whereNumber('id');
        Route::post('/trusted-devices/revoke-all', [MfaController::class, 'revokeAllTrustedDevices']);

        Route::post('/passkeys/registration/options', [WebAuthnController::class, 'registrationOptions'])
            ->middleware('security.throttle:5,1');
        Route::post('/passkeys/registration/{challengeId}/verify', [WebAuthnController::class, 'verifyRegistration'])
            ->middleware('security.throttle:5,1');
        Route::get('/passkeys', [WebAuthnController::class, 'credentials']);
        Route::delete('/passkeys/{publicId}', [WebAuthnController::class, 'revoke'])
            ->whereUuid('publicId');
    });
});

Route::prefix('admin/v1')->middleware(['security.throttle:60,1', 'auth:api', 'central.admin'])->group(function (): void {
    Route::get('/dashboard', [AdminController::class, 'dashboard'])->middleware('central.admin.permission:dashboard.read');
    Route::get('/users', [AdminController::class, 'users'])->middleware('central.admin.permission:users.read');
    Route::get('/users/{user}', [AdminController::class, 'showUser'])->middleware('central.admin.permission:users.read');
    Route::patch('/users/{user}/status', [AdminController::class, 'updateUserStatus'])
        ->middleware(['security.throttle:10,1', 'central.admin.permission:users.manage']);
    Route::get('/security/events', [AdminController::class, 'events'])->middleware('central.admin.permission:security.read');
    Route::get('/security/alerts', [AdminController::class, 'alerts'])->middleware('central.admin.permission:security.read');
    Route::get('/security/audit', [AdminController::class, 'audit'])->middleware('central.admin.permission:security.audit');
    Route::get('/oauth-clients', [AdminController::class, 'clients'])->middleware('central.admin.permission:oauth.read');
    Route::post('/oauth-clients/{clientId}/revoke', [AdminController::class, 'revokeClient'])
        ->whereUuid('clientId')->middleware(['security.throttle:5,1', 'central.admin.permission:oauth.manage']);
    Route::get('/security/incidents', [IncidentController::class, 'adminIncidents'])->middleware('central.admin.permission:incidents.read');
    Route::get('/security/incidents/{reference}', [IncidentController::class, 'showAdminIncident'])->whereUuid('reference')->middleware('central.admin.permission:incidents.read');
    Route::patch('/security/incidents/{reference}', [IncidentController::class, 'updateIncident'])
        ->whereUuid('reference')->middleware(['security.throttle:10,1', 'central.admin.permission:incidents.manage']);
    Route::post('/security/incidents/{reference}/entries', [IncidentController::class, 'addInvestigationEntry'])
        ->whereUuid('reference')->middleware(['security.throttle:10,1', 'central.admin.permission:incidents.manage']);
    Route::post('/security/incidents/{reference}/remediate', [IncidentController::class, 'remediateSessions'])
        ->whereUuid('reference')->middleware(['security.throttle:5,1', 'central.admin.permission:incidents.remediate']);
});

Route::post('/oidc/product-access', [OidcController::class, 'productAccess'])
    ->middleware(['security.throttle:30,1', 'product.server'])->name('oidc.product-access');
