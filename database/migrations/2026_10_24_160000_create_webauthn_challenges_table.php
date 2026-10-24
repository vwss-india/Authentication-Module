<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('webauthn_challenges', function (Blueprint $table): void {
            $table->id();
            $table->uuid('public_id')->unique();
            $table->foreignId('user_id')->nullable()->constrained('users')->cascadeOnDelete();
            $table->string('ceremony', 20);
            $table->char('challenge_hash', 64);
            $table->longText('options_encrypted');
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();

            $table->index(['ceremony', 'expires_at', 'consumed_at']);
            $table->index(['user_id', 'ceremony', 'expires_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('webauthn_challenges');
    }
};
