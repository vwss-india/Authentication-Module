<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_incidents', function (Blueprint $table): void {
            $table->id();
            $table->uuid('reference')->unique();
            $table->foreignId('user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('category', 40);
            $table->text('description');
            $table->string('severity', 20)->default('medium');
            $table->string('status', 20)->default('new');
            $table->foreignId('assigned_admin_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('submitted_at');
            $table->timestamps();

            $table->index(['status', 'severity', 'submitted_at']);
            $table->index(['user_id', 'submitted_at']);
        });

        Schema::create('incident_investigation_entries', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_incident_id')->constrained('security_incidents')->cascadeOnDelete();
            $table->foreignId('actor_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('entry_type', 30);
            $table->text('body')->nullable();
            $table->jsonb('details')->nullable();
            $table->timestamp('recorded_at');
            $table->timestamps();

            $table->index(['security_incident_id', 'recorded_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('incident_investigation_entries');
        Schema::dropIfExists('security_incidents');
    }
};
