<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class AuthenticationSchemaTest extends TestCase
{
    use RefreshDatabase;

    public function test_identity_event_and_audit_tables_have_required_constraints_and_indexes(): void
    {
        $this->assertTrue(Schema::hasIndex('users', ['email'], 'unique'));
        $this->assertTrue(Schema::hasIndex('users', ['public_id'], 'unique'));
        $this->assertTrue(Schema::hasIndex('security_events', ['event_id'], 'unique'));
        $this->assertTrue(Schema::hasIndex('security_events', ['user_id', 'occurred_at']));
        $this->assertTrue(Schema::hasIndex('security_events', ['event_type', 'occurred_at']));
        $this->assertTrue(Schema::hasIndex('audit_logs', ['sequence_number'], 'unique'));
        $this->assertTrue(Schema::hasIndex('audit_logs', ['entry_hash'], 'unique'));

        $securityEventUserForeignKey = collect(Schema::getForeignKeys('security_events'))
            ->firstWhere('columns', ['user_id']);
        $this->assertSame('users', $securityEventUserForeignKey['foreign_table'] ?? null);
        $this->assertSame('set null', strtolower((string) ($securityEventUserForeignKey['on_delete'] ?? '')));

        $verificationUserForeignKey = collect(Schema::getForeignKeys('verification_challenges'))
            ->firstWhere('columns', ['user_id']);
        $this->assertSame('users', $verificationUserForeignKey['foreign_table'] ?? null);
        $this->assertSame('cascade', strtolower((string) ($verificationUserForeignKey['on_delete'] ?? '')));
    }
}
