<?php

namespace App\Console\Commands;

use App\Models\AuditLog;
use App\Models\User;
use App\Notifications\SecurityAlertNotification;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Throwable;

#[Signature('security:monitor')]
#[Description('Generate and deliver alerts for repeated failed sign-ins.')]
class MonitorSecurityEvents extends Command
{
    public function handle(): int
    {
        $windowMinutes = max(1, (int) config('auth.security_monitoring.window_minutes', 15));
        $threshold = max(3, (int) config('auth.security_monitoring.failed_login_threshold', 5));
        $maxDeliveryAttempts = max(1, (int) config('auth.security_monitoring.alert_delivery_max_attempts', 3));
        $since = now()->subMinutes($windowMinutes);
        $attemptGroups = DB::table('security_events')
            ->where('event_type', 'auth.login')
            ->where('result', 'failure')
            ->whereNotNull('user_id')
            ->where('occurred_at', '>=', $since)
            ->select('user_id', DB::raw('COUNT(*) AS attempts'))
            ->groupBy('user_id')
            ->havingRaw('COUNT(*) >= ?', [$threshold])
            ->get();
        $created = 0;

        foreach ($attemptGroups as $group) {
            $existing = DB::table('security_alerts')
                ->where('user_id', $group->user_id)
                ->where('alert_type', 'repeated_failed_sign_ins')
                ->where('detected_at', '>=', $since)
                ->first();

            if ($existing && (
                $existing->delivery_attempts >= $maxDeliveryAttempts
                || $existing->delivery_status === 'sent'
            )) {
                continue;
            }

            $user = User::query()->find($group->user_id);
            $now = now();
            if ($existing) {
                $rowId = $existing->id;
            } else {
                $alertId = (string) Str::uuid();
                $rowId = DB::table('security_alerts')->insertGetId([
                    'alert_id' => $alertId,
                    'user_id' => $group->user_id,
                    'alert_type' => 'repeated_failed_sign_ins',
                    'severity' => 'high',
                    'status' => 'open',
                    'delivery_status' => 'pending',
                    'delivery_attempts' => 0,
                    'details' => json_encode([
                        'attempt_count' => (int) $group->attempts,
                        'window_minutes' => $windowMinutes,
                    ], JSON_THROW_ON_ERROR),
                    'detected_at' => $now,
                    'delivery_attempted_at' => null,
                    'acknowledged_at' => null,
                    'resolved_at' => null,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);

                AuditLog::recordEntry(request(), $user, 'security.alert.created', [
                    'alert_type' => 'repeated_failed_sign_ins',
                    'alert_id' => $alertId,
                ]);
            }

            if (! $user) {
                $deliveryStatus = 'failed';
            } else {
                try {
                    Notification::send($user, new SecurityAlertNotification('repeated_failed_sign_ins'));
                    $deliveryStatus = 'sent';
                } catch (Throwable) {
                    $deliveryStatus = 'failed';
                }
            }

            DB::table('security_alerts')->where('id', $rowId)->update([
                'delivery_status' => $deliveryStatus,
                'delivery_attempts' => DB::raw('delivery_attempts + 1'),
                'delivery_attempted_at' => now(),
                'updated_at' => now(),
            ]);
            AuditLog::recordEntry(request(), $user, 'security.alert.delivery.'.$deliveryStatus, [
                'alert_type' => 'repeated_failed_sign_ins',
                'attempt' => (int) ($existing->delivery_attempts ?? 0) + 1,
            ]);
            $created++;
        }

        $this->info("Processed {$created} security alert(s).");

        return self::SUCCESS;
    }
}
