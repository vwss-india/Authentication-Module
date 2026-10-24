<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('oauth_personal_access_clients')) {
            return;
        }

        Schema::create('oauth_personal_access_clients', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->uuid('client_id')->unique();
            $table->timestamps();

            $table->foreign('client_id')
                ->references('id')
                ->on('oauth_clients')
                ->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_personal_access_clients');
    }
};