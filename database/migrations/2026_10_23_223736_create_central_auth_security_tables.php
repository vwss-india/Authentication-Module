<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Flexible identity metadata
        Schema::create('user_meta', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->string('meta_key', 100);
            $table->jsonb('meta_value')->nullable();
            $table->timestamps();

            $table->unique(['user_id', 'meta_key']);
        });

        // Email, phone and other one-time verification challenges
        Schema::create('verification_challenges', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->string('channel', 20);
            $table->string('purpose', 40);
            $table->string('destination', 254);
            $table->string('token_hash', 255);
            $table->unsignedSmallInteger('attempts')->default(0);
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'purpose', 'expires_at']);
            $table->index(['destination', 'purpose']);
        });

        // MFA methods: TOTP, email, SMS, etc.
        Schema::create('mfa_methods', function (Blueprint $table) {
            $table->id();
            $table->uuid('public_id')->unique();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->string('type', 30);
            $table->string('label', 100)->nullable();
            $table->text('secret_encrypted')->nullable();
            $table->string('destination', 254)->nullable();
            $table->boolean('is_primary')->default(false);
            $table->timestamp('verified_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('disabled_at')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'type', 'disabled_at']);
        });

        // Store only hashes of recovery codes
        Schema::create('mfa_recovery_codes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('mfa_method_id')
                ->constrained('mfa_methods')->cascadeOnDelete();
            $table->string('code_hash', 255)->unique();
            $table->timestamp('used_at')->nullable();
            $table->timestamps();

            $table->index(['mfa_method_id', 'used_at']);
        });

        // Remembered/trusted devices
        Schema::create('trusted_devices', function (Blueprint $table) {
            $table->id();
            $table->uuid('public_id')->unique();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->string('name', 150)->nullable();
            $table->string('token_hash', 255)->unique();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'expires_at', 'revoked_at']);
        });

        // WebAuthn/passkey credentials
        Schema::create('webauthn_credentials', function (Blueprint $table) {
            $table->id();
            $table->uuid('public_id')->unique();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->text('credential_id')->unique();
            $table->text('public_key');
            $table->unsignedBigInteger('sign_count')->default(0);
            $table->string('aaguid', 36)->nullable();
            $table->string('transports', 255)->nullable();
            $table->string('name', 150)->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'revoked_at']);
        });

        // User acceptance of privacy policies and terms
        Schema::create('user_consents', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->string('consent_type', 80);
            $table->string('document_version', 40);
            $table->boolean('accepted');
            $table->timestamp('recorded_at');
            $table->ipAddress('ip_address')->nullable();
            $table->string('user_agent_hash', 64)->nullable();
            $table->timestamps();

            $table->index(['user_id', 'consent_type', 'recorded_at']);
        });

        // Security events: login success/failure, logout, lockout, MFA events
        Schema::create('security_events', function (Blueprint $table) {
            $table->id();
            $table->uuid('event_id')->unique();
            $table->foreignId('user_id')->nullable()
                ->constrained('users')->nullOnDelete();
            $table->string('event_type', 100);
            $table->string('result', 30);
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->string('request_id', 100)->nullable();
            $table->jsonb('context')->nullable();
            $table->timestamp('occurred_at');

            $table->index(['user_id', 'occurred_at']);
            $table->index(['event_type', 'occurred_at']);
            $table->index(['ip_address', 'occurred_at']);
        });

        // Append-only audit trail with hash chaining
        Schema::create('audit_logs', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('sequence_number')->unique();
            $table->uuid('event_id')->unique();
            $table->unsignedBigInteger('actor_user_id')->nullable();
            $table->string('actor_public_id', 36)->nullable();
            $table->string('action', 120);
            $table->string('subject_type', 100)->nullable();
            $table->string('subject_id', 100)->nullable();
            $table->jsonb('details')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->string('request_id', 100)->nullable();
            $table->char('previous_hash', 64)->nullable();
            $table->char('entry_hash', 64)->unique();
            $table->timestamp('occurred_at');

            $table->index(['actor_user_id', 'occurred_at']);
            $table->index(['action', 'occurred_at']);
        });

        // Signed checkpoints for independent audit-chain verification
        Schema::create('audit_checkpoints', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('sequence_number')->unique();
            $table->char('chain_hash', 64);
            $table->string('signature_algorithm', 40);
            $table->text('signature');
            $table->string('key_id', 100);
            $table->timestamp('signed_at');
            $table->timestamps();

            $table->index('signed_at');
        });

        // Security alerts raised by monitoring
        Schema::create('security_alerts', function (Blueprint $table) {
            $table->id();
            $table->uuid('alert_id')->unique();
            $table->foreignId('user_id')->nullable()
                ->constrained('users')->nullOnDelete();
            $table->string('alert_type', 100);
            $table->string('severity', 20);
            $table->string('status', 20)->default('open');
            $table->jsonb('details')->nullable();
            $table->timestamp('detected_at');
            $table->timestamp('acknowledged_at')->nullable();
            $table->timestamp('resolved_at')->nullable();
            $table->timestamps();

            $table->index(['status', 'severity', 'detected_at']);
            $table->index(['user_id', 'detected_at']);
        });

        // OIDC settings attached to Passport OAuth clients.
        // Passport owns oauth_clients; this table stores only OIDC-specific settings.
        Schema::create('oidc_client_settings', function (Blueprint $table) {
            $table->uuid('client_id')->primary();
            $table->boolean('is_oidc_client')->default(false);
            $table->string('subject_type', 20)->default('public');
            $table->jsonb('allowed_claims')->nullable();
            $table->jsonb('post_logout_redirect_uris')->nullable();
            $table->timestamps();

            $table->foreign('client_id')
                ->references('id')
                ->on('oauth_clients')
                ->cascadeOnDelete();
        });

        // Stable OIDC pairwise/public subject identifiers per client
        Schema::create('oidc_subject_identifiers', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->uuid('client_id');
            $table->string('subject_identifier', 255)->unique();
            $table->timestamps();

            $table->foreign('client_id')
                ->references('id')
                ->on('oauth_clients')
                ->cascadeOnDelete();

            $table->unique(['user_id', 'client_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_subject_identifiers');
        Schema::dropIfExists('oidc_client_settings');
        Schema::dropIfExists('security_alerts');
        Schema::dropIfExists('audit_checkpoints');
        Schema::dropIfExists('audit_logs');
        Schema::dropIfExists('security_events');
        Schema::dropIfExists('user_consents');
        Schema::dropIfExists('webauthn_credentials');
        Schema::dropIfExists('trusted_devices');
        Schema::dropIfExists('mfa_recovery_codes');
        Schema::dropIfExists('mfa_methods');
        Schema::dropIfExists('verification_challenges');
        Schema::dropIfExists('user_meta');
    }
};