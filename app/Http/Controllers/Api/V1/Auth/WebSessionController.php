<?php

namespace App\Http\Controllers\Api\V1\Auth;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class WebSessionController extends Controller
{
    private const int MAX_LOGIN_ATTEMPTS = 5;

    private const int LOCKOUT_MINUTES = 15;

    public function create(Request $request): View
    {
        $pending = $request->session()->get('web_auth_pending');

        return view('auth.login', [
            'mfaRequired' => is_array($pending) && ($pending['expires_at'] ?? 0) > now()->timestamp,
            'email' => old('email'),
        ]);
    }

    public function store(Request $request): Response
    {
        $data = $request->validate([
            'email' => ['required', 'email', 'max:254'],
            'password' => ['required', 'string', 'max:128'],
            'code' => ['nullable', 'string', 'max:128'],
        ]);
        $user = User::query()->where('email', mb_strtolower($data['email']))->first();

        if ($user && $user->locked_until?->isFuture()) {
            $this->recordEvent($request, $user, 'auth.web_login', 'blocked', ['reason' => 'account_locked']);

            return response()->view('auth.login', [
                'mfaRequired' => false,
                'email' => $data['email'],
                'error' => 'Sign-in is temporarily unavailable. Try again later.',
            ], 423);
        }

        if ($user && $user->locked_until) {
            $user->forceFill(['failed_login_attempts' => 0, 'locked_until' => null])->save();
        }

        if (! $user || ! Hash::check($data['password'], $user->password)) {
            $this->recordFailedAttempt($request, $user, 'invalid_credentials');

            return response()->view('auth.login', [
                'mfaRequired' => false,
                'email' => $data['email'],
                'error' => 'The supplied credentials are invalid.',
            ], 401);
        }

        if ($user->status !== 'active' || ! $user->email_verified_at) {
            $this->recordEvent($request, $user, 'auth.web_login', 'blocked', [
                'reason' => 'account_not_active_or_unverified',
            ]);

            return response()->view('auth.login', [
                'mfaRequired' => false,
                'email' => $data['email'],
                'error' => 'This account is not active or its email is not verified.',
            ], 403);
        }

        $mfaMethod = DB::table('mfa_methods')
            ->where('user_id', $user->id)
            ->where('type', 'totp')
            ->whereNotNull('verified_at')
            ->whereNull('revoked_at')
            ->first();

        if ($mfaMethod) {
            $pending = $request->session()->get('web_auth_pending');

            if (
                empty($data['code'])
                || ! is_array($pending)
                || ($pending['user_id'] ?? null) !== $user->id
                || ($pending['expires_at'] ?? 0) <= now()->timestamp
            ) {
                $request->session()->put('web_auth_pending', [
                    'user_id' => $user->id,
                    'expires_at' => now()->addMinutes(5)->timestamp,
                ]);
                $this->recordEvent($request, $user, 'auth.web_mfa_challenge', 'issued');

                return response()->view('auth.login', [
                    'mfaRequired' => true,
                    'email' => $data['email'],
                    'error' => empty($data['code']) ? null : 'The MFA challenge expired. Enter your password again.',
                ]);
            }

            if (! $this->verifyMfaCode($user, $mfaMethod, $data['code'])) {
                $this->recordFailedAttempt($request, $user, 'invalid_mfa_code');
                $request->session()->forget('web_auth_pending');

                return response()->view('auth.login', [
                    'mfaRequired' => false,
                    'email' => $data['email'],
                    'error' => 'The verification code is invalid or already used.',
                ], 422);
            }

            $this->recordEvent($request, $user, 'auth.web_mfa_challenge', 'success');
        }

        $request->session()->forget('web_auth_pending');
        $user->forceFill([
            'failed_login_attempts' => 0,
            'locked_until' => null,
            'last_login_at' => now(),
            'last_login_ip' => $request->ip(),
        ])->save();
        Auth::guard('web')->login($user);
        $request->session()->regenerate();
        $this->recordEvent($request, $user, 'auth.web_login', 'success');

        return redirect()->intended('/');
    }

    public function destroy(Request $request): Response
    {
        $user = $request->user();
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        $this->recordEvent($request, $user, 'auth.web_logout', 'success');

        return redirect('/login');
    }

    private function verifyMfaCode(User $user, object $method, string $code): bool
    {
        return DB::transaction(function () use ($user, $method, $code): bool {
            $lockedMethod = DB::table('mfa_methods')
                ->where('id', $method->id)
                ->where('user_id', $user->id)
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->first();

            if (! $lockedMethod) {
                return false;
            }

            if (preg_match('/^\d{6}$/', $code)) {
                try {
                    $secret = Crypt::decryptString($lockedMethod->secret_encrypted);
                    $lastUsed = $lockedMethod->last_used_at ? strtotime((string) $lockedMethod->last_used_at) : 0;
                    $valid = app('pragmarx.google2fa')->verifyKeyNewer(
                        $secret,
                        $code,
                        $lastUsed ?: 0,
                        1
                    );

                    if ($valid !== false) {
                        DB::table('mfa_methods')->where('id', $lockedMethod->id)->update([
                            'last_used_at' => now(),
                            'updated_at' => now(),
                        ]);

                        return true;
                    }
                } catch (Throwable) {
                    return false;
                }
            }

            foreach (DB::table('mfa_recovery_codes')
                ->where('mfa_method_id', $lockedMethod->id)
                ->whereNull('used_at')
                ->lockForUpdate()
                ->get() as $recoveryCode) {
                if (! Hash::check($code, $recoveryCode->code_hash)) {
                    continue;
                }

                return DB::table('mfa_recovery_codes')
                    ->where('id', $recoveryCode->id)
                    ->whereNull('used_at')
                    ->update(['used_at' => now(), 'updated_at' => now()]) === 1;
            }

            return false;
        });
    }

    private function recordFailedAttempt(Request $request, ?User $user, string $reason): void
    {
        if ($user) {
            $attempts = (int) $user->failed_login_attempts + 1;
            $user->forceFill([
                'failed_login_attempts' => $attempts,
                'locked_until' => $attempts >= self::MAX_LOGIN_ATTEMPTS
                    ? now()->addMinutes(self::LOCKOUT_MINUTES)
                    : $user->locked_until,
            ])->save();
        }

        $this->recordEvent($request, $user, 'auth.web_login', 'failure', ['reason' => $reason]);
    }

    private function recordEvent(Request $request, ?User $user, string $type, string $result, array $context = []): void
    {
        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(),
            'user_id' => $user?->id,
            'event_type' => $type,
            'result' => $result,
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 1000, ''),
            'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
            'context' => json_encode($context, JSON_THROW_ON_ERROR),
            'occurred_at' => now(),
        ]);

        AuditLog::recordEntry($request, $user, $type.'.'.$result, $context);
    }
}
