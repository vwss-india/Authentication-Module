<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('mfa_methods', 'revoked_at')) {
            Schema::table('mfa_methods', function (Blueprint $table): void {
                $table->timestamp('revoked_at')->nullable();
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasColumn('mfa_methods', 'revoked_at')) {
            Schema::table('mfa_methods', function (Blueprint $table): void {
                $table->dropColumn('revoked_at');
            });
        }
    }
};