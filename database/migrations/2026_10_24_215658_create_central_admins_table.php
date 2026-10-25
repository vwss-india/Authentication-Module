<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('central_admins', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->unique()->constrained('users')->cascadeOnDelete();
            $table->foreignId('granted_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->foreignId('revoked_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('grant_reason', 500);
            $table->json('permissions');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->index(['revoked_at', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('central_admins');
    }
};
