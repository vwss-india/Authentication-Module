<?php

use App\Http\Controllers\Api\V1\Auth\AuthController;
use App\Http\Controllers\Api\V1\Auth\MfaController;
use App\Http\Controllers\Api\V1\Auth\PasswordRecoveryController;
use App\Http\Controllers\Api\V1\WebAuthnController;
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
