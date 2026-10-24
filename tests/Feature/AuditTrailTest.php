<?php

namespace Tests\Feature;

use App\Models\AuditCheckpoint;
use App\Models\AuditLog;
use App\Models\User;
use App\Notifications\SecurityAlertNotification;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use Tests\TestCase;

class AuditTrailTest extends TestCase
{
    use RefreshDatabase;

    public function test_audit_entries_form_a_sequential_hash_chain_and_detect_tampering(): void
    {
        $user = User::factory()->create();
        $request = Request::create('/audit-test', 'POST', server: ['REMOTE_ADDR' => '127.0.0.1']);

        AuditLog::recordEntry($request, $user, 'auth.login.success', ['result' => 'success']);
        AuditLog::recordEntry($request, $user, 'auth.mfa.enabled.success', ['method' => 'totp']);

        $this->assertSame([
            'valid' => true,
            'entries' => 2,
            'last_sequence' => 2,
            'error_sequence' => null,
        ], AuditLog::verifyChain());
        $this->assertDatabaseHas('audit_logs', [
            'sequence_number' => 2,
            'previous_hash' => DB::table('audit_logs')->where('sequence_number', 1)->value('entry_hash'),
        ]);

        DB::table('audit_logs')->where('sequence_number', 1)->update([
            'action' => 'auth.password_reset.success',
        ]);

        $this->assertFalse(AuditLog::verifyChain()['valid']);
        $this->assertSame(1, AuditLog::verifyChain()['error_sequence']);
    }

    public function test_signed_checkpoint_verifies_and_detects_modified_chain_hash(): void
    {
        AuditLog::recordEntry(Request::create('/audit-test', 'POST'), null, 'auth.login.failure');

        $checkpoint = AuditCheckpoint::createForLatestEntry();

        $this->assertNotNull($checkpoint);
        $this->assertSame('RS256', $checkpoint->signature_algorithm);
        $this->assertTrue(AuditCheckpoint::verifyAll());
        $this->assertSame(0, Artisan::call('audit:verify'));

        DB::table('audit_checkpoints')->where('id', $checkpoint->id)->update([
            'chain_hash' => str_repeat('0', 64),
        ]);

        $this->assertFalse(AuditCheckpoint::verifyAll());
        $this->assertSame(1, Artisan::call('audit:verify'));
    }

    public function test_authenticated_users_cannot_read_security_event_records_over_http(): void
    {
        Passport::actingAs(User::factory()->create());

        $this->getJson('/api/v1/auth/security-events')->assertNotFound();
    }

    public function test_security_monitor_creates_and_delivers_one_alert_for_failed_login_burst(): void
    {
        Notification::fake();
        $user = User::factory()->create([
            'status' => 'active',
            'email_verified_at' => now(),
        ]);

        for ($attempt = 0; $attempt < 5; $attempt++) {
            DB::table('security_events')->insert([
                'event_id' => (string) Str::uuid(),
                'user_id' => $user->id,
                'event_type' => 'auth.login',
                'result' => 'failure',
                'ip_address' => '127.0.0.1',
                'user_agent' => null,
                'request_id' => null,
                'context' => json_encode(['reason' => 'invalid_credentials']),
                'occurred_at' => now(),
            ]);
        }

        $this->assertSame(0, Artisan::call('security:monitor'));
        Notification::assertSentTo($user, SecurityAlertNotification::class);
        $this->assertDatabaseHas('security_alerts', [
            'user_id' => $user->id,
            'alert_type' => 'repeated_failed_sign_ins',
            'severity' => 'high',
            'status' => 'open',
            'delivery_status' => 'sent',
        ]);

        DB::table('security_alerts')->update([
            'delivery_status' => 'failed',
            'delivery_attempts' => 1,
        ]);

        $this->assertSame(0, Artisan::call('security:monitor'));
        $this->assertDatabaseCount('security_alerts', 1);
        $this->assertDatabaseHas('security_alerts', [
            'user_id' => $user->id,
            'delivery_status' => 'sent',
            'delivery_attempts' => 2,
        ]);
        $this->assertSame(3, AuditLog::verifyChain()['entries']);
    }
}
