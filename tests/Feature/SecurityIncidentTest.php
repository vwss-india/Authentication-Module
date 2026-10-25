<?php

namespace Tests\Feature;

use App\Models\AuditLog;
use App\Models\CentralAdmin;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

class SecurityIncidentTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
    }

    public function test_user_can_submit_and_view_only_their_own_report(): void
    {
        $reporter = $this->activeUser();
        $other = $this->activeUser('other-reporter@example.test');
        $this->actingAs($reporter)->post(route('incidents.store'), [
            'category' => 'suspected_compromise',
            'description' => 'I noticed an unfamiliar login in my recent account activity.',
        ])->assertRedirect();
        $reference = DB::table('security_incidents')->where('user_id', $reporter->id)->value('reference');

        $this->get(route('incidents.show', $reference))->assertOk()->assertSee($reference)
            ->assertSee('unfamiliar login')->assertDontSee('Internal investigator finding');
        $this->actingAs($other)->get(route('incidents.show', $reference))->assertNotFound();
        $this->actingAs($other)->getJson('/api/admin/v1/security/incidents')->assertUnauthorized();
        $this->assertDatabaseHas('security_events', ['user_id' => $reporter->id, 'event_type' => 'security.incident.reported']);
        $this->assertDatabaseHas('audit_logs', ['action' => 'security.incident.reported']);
    }

    public function test_report_submission_validates_description_and_authentication(): void
    {
        $this->get(route('incidents.index'))->assertRedirect('/login');
        $this->actingAs($this->activeUser())->post(route('incidents.store'), [
            'category' => 'other', 'description' => 'too short',
        ])->assertSessionHasErrors('description');
    }

    public function test_admin_evidence_visibility_transitions_and_investigation_history_are_audited(): void
    {
        $reporter = $this->activeUser();
        $admin = $this->activeUser('incident-admin@example.test');
        $this->grantAdmin($admin);
        $this->actingAs($reporter)->post(route('incidents.store'), [
            'category' => 'unfamiliar_login', 'description' => 'A login appeared from a location I do not recognize.',
        ])->assertRedirect();
        $reference = DB::table('security_incidents')->where('user_id', $reporter->id)->value('reference');
        DB::table('security_events')->insert([
            'event_id' => (string) Str::uuid(), 'user_id' => $reporter->id, 'event_type' => 'auth.login',
            'result' => 'success', 'ip_address' => '192.0.2.10', 'user_agent' => 'Example Browser',
            'request_id' => null, 'context' => json_encode(['factor' => 'password']), 'occurred_at' => now()->subMinute(),
        ]);

        $this->actingAs($admin)->get(route('admin.incidents.show', $reference))->assertOk()
            ->assertSee('192.0.2.10')->assertSee('Example Browser');
        $this->post(route('admin.incidents.update', $reference), [
            'status' => 'investigating', 'severity' => 'high', 'assign_to_self' => '1',
        ])->assertRedirect();
        $this->post(route('admin.incidents.entries', $reference), [
            'entry_type' => 'finding', 'body' => 'The submitted event timing matches a recent successful authentication.',
        ])->assertRedirect();
        $this->assertDatabaseHas('security_incidents', ['reference' => $reference, 'status' => 'investigating', 'severity' => 'high', 'assigned_admin_user_id' => $admin->id]);
        $this->assertDatabaseHas('incident_investigation_entries', ['entry_type' => 'finding']);
        $this->assertDatabaseHas('audit_logs', ['action' => 'admin.incident.updated']);
        $this->assertDatabaseHas('audit_logs', ['action' => 'admin.incident.entry_added']);

        $this->post(route('admin.incidents.update', $reference), ['status' => 'closed'])
            ->assertUnprocessable();
        $this->actingAs($reporter)->get(route('incidents.show', $reference))
            ->assertOk()->assertSee('Investigating')->assertDontSee('matches a recent successful authentication');
        $this->assertTrue(AuditLog::verifyChain()['valid']);
    }

    public function test_admin_remediation_revokes_reported_account_credentials_and_records_action(): void
    {
        config(['session.driver' => 'database']);
        $reporter = $this->activeUser();
        $admin = $this->activeUser('remediation-admin@example.test');
        $this->grantAdmin($admin);
        $this->actingAs($reporter)->post(route('incidents.store'), [
            'category' => 'suspected_compromise', 'description' => 'I did not make the security changes on my profile.',
        ])->assertRedirect();
        $reference = DB::table('security_incidents')->where('user_id', $reporter->id)->value('reference');
        $tokenId = Str::random(80);
        DB::table('oauth_access_tokens')->insert([
            'id' => $tokenId, 'user_id' => $reporter->id, 'client_id' => (string) Str::uuid(),
            'name' => 'test', 'scopes' => '[]', 'revoked' => false, 'created_at' => now(),
            'updated_at' => now(), 'expires_at' => now()->addDay(),
        ]);
        DB::table('oauth_refresh_tokens')->insert([
            'id' => Str::random(80), 'access_token_id' => $tokenId, 'revoked' => false, 'expires_at' => now()->addDay(),
        ]);
        DB::table('sessions')->insert([
            'id' => 'incident-reporter-session', 'user_id' => $reporter->id, 'ip_address' => '192.0.2.11',
            'user_agent' => 'test', 'payload' => base64_encode('session'), 'last_activity' => now()->timestamp,
        ]);
        DB::table('trusted_devices')->insert([
            'public_id' => (string) Str::uuid(), 'user_id' => $reporter->id, 'name' => 'device',
            'token_hash' => bcrypt('secret-token'), 'ip_address' => null, 'user_agent' => null,
            'last_used_at' => now(), 'expires_at' => now()->addDay(), 'revoked_at' => null,
            'created_at' => now(), 'updated_at' => now(),
        ]);

        $this->actingAs($admin)->post(route('admin.incidents.remediate', $reference), ['confirmed' => '1'])->assertRedirect();
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $tokenId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_refresh_tokens', ['access_token_id' => $tokenId, 'revoked' => true]);
        $this->assertDatabaseMissing('sessions', ['id' => 'incident-reporter-session']);
        $this->assertNotNull(DB::table('trusted_devices')->where('user_id', $reporter->id)->value('revoked_at'));
        $this->assertDatabaseHas('incident_investigation_entries', ['entry_type' => 'remediation']);
        $this->assertDatabaseHas('audit_logs', ['action' => 'admin.incident.sessions_revoked']);
    }

    private function activeUser(string $email = 'incident-reporter@example.test'): User
    {
        return User::factory()->create(['email' => $email, 'status' => 'active', 'email_verified_at' => now()]);
    }

    private function grantAdmin(User $user): void
    {
        CentralAdmin::query()->create(['user_id' => $user->id, 'grant_reason' => 'Test provisioning', 'permissions' => ['*']]);
    }
}
