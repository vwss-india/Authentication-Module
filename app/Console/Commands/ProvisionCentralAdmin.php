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

#[Signature('auth:admin:grant {email} {--reason=} {--permissions=} {--allow-wildcard} {--force}')]
#[Description('Grant Central Auth admin access to an active, verified account.')]
class ProvisionCentralAdmin extends Command
{
    private const array AVAILABLE_PERMISSIONS = [
        'dashboard.read', 'users.read', 'users.manage', 'security.read', 'security.audit',
        'oauth.read', 'oauth.manage', 'products.read', 'incidents.read', 'incidents.manage', 'incidents.remediate',
    ];

    public function handle(): int
    {
        $email = mb_strtolower((string) $this->argument('email'));
        $reason = trim((string) $this->option('reason'));
        $permissionOption = trim((string) $this->option('permissions'));
        $user = User::query()->where('email', $email)->first();

        if (! $user || $user->status !== 'active' || ! $user->email_verified_at) {
            $this->error('The target must be an existing active account with a verified email.');

            return self::FAILURE;
        }

        if (mb_strlen($reason) < 5 || mb_strlen($reason) > 500) {
            $this->error('Provide an operator reason of 5 to 500 characters with --reason.');

            return self::FAILURE;
        }

        $permissions = array_values(array_unique(array_filter(array_map('trim', explode(',', $permissionOption)))));
        if ($permissions === [] || ($permissions !== ['*'] && array_diff($permissions, self::AVAILABLE_PERMISSIONS))) {
            $this->error('Specify --permissions=* or a comma-separated list of valid least-privilege permissions.');

            return self::FAILURE;
        }

        if (($permissions === ['*']) !== (bool) $this->option('allow-wildcard')) {
            $this->error('Wildcard access requires --allow-wildcard, and that flag is valid only with --permissions=*.');

            return self::FAILURE;
        }

        $confirmation = $permissions === ['*']
            ? "Grant FULL Central Auth admin permissions to {$user->email}?"
            : "Grant Central Auth admin access to {$user->email}?";
        if (! $this->option('force') && ! $this->confirm($confirmation)) {
            return self::FAILURE;
        }

        $granted = DB::transaction(function () use ($user, $reason, $permissions): bool {
            CentralAdmin::query()->orderBy('id')->lockForUpdate()->get(['id']);
            $lockedUser = User::query()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            if ($lockedUser->status !== 'active' || ! $lockedUser->email_verified_at) {
                return false;
            }
            $admin = CentralAdmin::query()->firstOrNew(['user_id' => $user->id]);
            $admin->forceFill([
                'granted_by_user_id' => null,
                'revoked_by_user_id' => null,
                'grant_reason' => $reason,
                'permissions' => $permissions,
                'revoked_at' => null,
            ])->save();

            $request = Request::create('/console/auth-admin', 'POST');
            AuditLog::recordEntry($request, null, 'admin.privilege.granted', [
                'target_user_id' => $user->id,
                'target_public_id' => $lockedUser->public_id,
                'reason' => $reason,
                'permissions' => $permissions,
                'provisioning' => 'console',
            ]);

            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => $user->id,
                'event_type' => 'admin.privilege.granted',
                'result' => 'success',
                'ip_address' => null,
                'user_agent' => null,
                'request_id' => null,
                'context' => json_encode(['reason' => $reason, 'permissions' => $permissions, 'source' => 'console'], JSON_THROW_ON_ERROR),
                'occurred_at' => now(),
            ]);

            return true;
        });

        if (! $granted) {
            $this->error('The target account became inactive or unverified before the grant was saved.');

            return self::FAILURE;
        }

        $this->info("Central Auth admin access granted to {$user->email}.");

        return self::SUCCESS;
    }
}
