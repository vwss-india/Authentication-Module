<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('oidc_authorization_codes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->uuid('oauth_client_id');
            $table->char('code_hash', 64)->unique();
            $table->string('redirect_uri', 2048);
            $table->jsonb('scopes');
            $table->string('nonce', 255);
            $table->string('code_challenge', 128);
            $table->string('code_challenge_method', 10);
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();

            $table->foreign('oauth_client_id')->references('id')->on('oauth_clients')->cascadeOnDelete();
            $table->index(['oauth_client_id', 'expires_at']);
        });

        Schema::create('oidc_access_tokens', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->uuid('oauth_client_id');
            $table->char('token_hash', 64)->unique();
            $table->jsonb('scopes');
            $table->timestamp('expires_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->foreign('oauth_client_id')->references('id')->on('oauth_clients')->cascadeOnDelete();
            $table->index(['user_id', 'oauth_client_id', 'expires_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('oidc_access_tokens');
        Schema::dropIfExists('oidc_authorization_codes');
    }
};
