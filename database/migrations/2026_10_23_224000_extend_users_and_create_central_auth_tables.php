
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        /*
         * This migration must run after the migration that creates
         * the oauth_clients table.
         */

        Schema::create('oidc_client_metadata', function (Blueprint $table) {
            $table->uuid('oauth_client_id')->primary();
            $table->string('client_type', 20)->default('confidential');
            $table->string('application_type', 20)->default('web');
            $table->string('subject_type', 20)->default('public');
            $table->jsonb('allowed_scopes')->nullable();
            $table->jsonb('post_logout_redirect_uris')->nullable();
            $table->jsonb('allowed_origins')->nullable();
            $table->boolean('require_pkce')->default(true);
            $table->boolean('require_consent')->default(true);
            $table->boolean('enabled')->default(true)->index();
            $table->timestamps();

            $table->foreign('oauth_client_id')
                ->references('id')
                ->on('oauth_clients')
                ->cascadeOnDelete();
        });

        Schema::create('oidc_consents', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')
                ->constrained('users')
                ->cascadeOnDelete();

            $table->uuid('oauth_client_id');
            $table->jsonb('granted_scopes');
            $table->timestamp('granted_at')->useCurrent();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->foreign('oauth_client_id')
                ->references('id')
                ->on('oauth_clients')
                ->cascadeOnDelete();

            $table->unique(['user_id', 'oauth_client_id']);
            $table->index(['oauth_client_id', 'revoked_at']);
        });

        Schema::create('oidc_signing_keys', function (Blueprint $table) {
            $table->id();
            $table->string('key_id', 100)->unique();
            $table->string('algorithm', 30)->default('RS256');
            $table->text('public_key_pem');
            $table->text('private_key_encrypted')->nullable();
            $table->timestamp('not_before')->nullable();
            $table->timestamp('expires_at')->nullable()->index();
            $table->timestamp('retired_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_signing_keys');
        Schema::dropIfExists('oidc_consents');
        Schema::dropIfExists('oidc_client_metadata');
    }
};
