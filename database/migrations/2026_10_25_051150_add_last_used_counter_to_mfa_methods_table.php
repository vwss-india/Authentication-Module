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
        Schema::table('mfa_methods', function (Blueprint $table) {
            $table->bigInteger('last_used_counter')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('mfa_methods', function (Blueprint $table) {
            $table->dropColumn('last_used_counter');
        });
    }
};
