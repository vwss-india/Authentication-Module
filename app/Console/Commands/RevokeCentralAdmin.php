<?php

namespace App\Console\Commands;

use App\Models\AuditLog;
use App\Models\CentralAdmin;
use App\Models\User;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

#[Signature('auth:admin:revoke {email} {--reason=} {--force}')]
#[Description('Revoke Central Auth admin access from an account.')]
class RevokeCentralAdmin extends Command
{
    public function handle(): int
    {
        $email = mb_strtolower((string) $this->argument('email'));
        $reason = trim((string) $this->option('reason'));
        $user = User::query()->where('email', $email)->first();
        $grant = $user ? CentralAdmin::query()->where('user_id', $user->id)->whereNull('revoked_at')->first() : null;

        if (! $user || ! $grant) {
            $this->error('No active administrator grant exists for that account.');

            return self::FAILURE;
        }

        if (mb_strlen($reason) < 5 || mb_strlen($reason) > 500) {
            $this->error('Provide an operator reason of 5 to 500 characters with --reason.');

            return self::FAILURE;
        }

        if (! $this->option('force') && ! $this->confirm("Revoke Central Auth admin access from {$user->email}?")) {
            return self::FAILURE;
        }

        $revoked = DB::transaction(function () use ($grant, $user, $reason): bool {
            CentralAdmin::query()->whereNull('revoked_at')->orderBy('id')->lockForUpdate()->get(['id']);
            $lockedUser = User::query()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            $lockedGrant = CentralAdmin::query()->whereKey($grant->id)->lockForUpdate()->firstOrFail();
            if ($lockedGrant->revoked_at !== null) {
                return false;
            }

            $remainingAdmins = DB::table('central_admins')->join('users', 'users.id', '=', 'central_admins.user_id')
                ->whereNull('central_admins.revoked_at')->where('users.status', 'active')
                ->whereNotNull('users.email_verified_at')->count();
            if ($remainingAdmins <= 1 && $lockedUser->status === 'active' && $lockedUser->email_verified_at) {
                return false;
            }

            $lockedGrant->forceFill(['revoked_at' => now(), 'revoked_by_user_id' => null])->save();
            $request = Request::create('/console/auth-admin', 'DELETE');
            $context = [
                'target_user_id' => $user->id,
                'target_public_id' => $lockedUser->public_id,
                'reason' => $reason,
                'provisioning' => 'console',
            ];
            AuditLog::recordEntry($request, null, 'admin.privilege.revoked', $context);
            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => $user->id,
                'event_type' => 'admin.privilege.revoked',
                'result' => 'success',
                'ip_address' => null,
                'user_agent' => null,
                'request_id' => null,
                'context' => json_encode(['reason' => $reason, 'source' => 'console'], JSON_THROW_ON_ERROR),
                'occurred_at' => now(),
            ]);

            return true;
        });

        if (! $revoked) {
            $this->error('Grant another active, verified administrator before revoking the last active administrator.');

            return self::FAILURE;
        }

        $this->info("Central Auth admin access revoked from {$user->email}.");

        return self::SUCCESS;
    }
}
