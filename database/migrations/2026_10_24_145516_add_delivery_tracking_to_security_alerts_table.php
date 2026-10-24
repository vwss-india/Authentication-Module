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
        Schema::table('security_alerts', function (Blueprint $table): void {
            $table->string('delivery_status', 20)->default('pending')->after('status');
            $table->unsignedTinyInteger('delivery_attempts')->default(0)->after('delivery_status');
            $table->timestamp('delivery_attempted_at')->nullable()->after('detected_at');
            $table->index(['delivery_status', 'delivery_attempted_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('security_alerts', function (Blueprint $table): void {
            $table->dropIndex(['delivery_status', 'delivery_attempted_at']);
            $table->dropColumn(['delivery_status', 'delivery_attempts', 'delivery_attempted_at']);
        });
    }
};
