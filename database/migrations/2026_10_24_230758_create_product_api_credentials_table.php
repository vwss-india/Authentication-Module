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
        Schema::create('product_api_credentials', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->foreignUuid('oauth_client_id')->constrained('oauth_clients')->restrictOnDelete();
            $table->foreignId('product_id')->constrained('products')->restrictOnDelete();
            $table->string('name', 100);
            $table->string('secret_hash', 255);
            $table->timestamp('expires_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->index(['oauth_client_id', 'product_id', 'revoked_at'], 'product_api_credentials_client_product_idx');
            $table->index(['expires_at', 'revoked_at'], 'product_api_credentials_lifecycle_idx');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('product_api_credentials');
    }
};
