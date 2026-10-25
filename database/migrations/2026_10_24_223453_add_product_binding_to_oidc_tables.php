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
        Schema::table('oidc_client_metadata', function (Blueprint $table): void {
            $table->foreignId('product_id')->nullable()->constrained('products')->restrictOnDelete();
        });

        Schema::table('oidc_authorization_codes', function (Blueprint $table): void {
            $table->foreignId('product_id')->nullable()->constrained('products')->restrictOnDelete();
        });

        Schema::table('oidc_access_tokens', function (Blueprint $table): void {
            $table->foreignId('product_id')->nullable()->constrained('products')->restrictOnDelete();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('oidc_access_tokens', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('product_id');
        });

        Schema::table('oidc_authorization_codes', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('product_id');
        });

        Schema::table('oidc_client_metadata', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('product_id');
        });
    }
};
