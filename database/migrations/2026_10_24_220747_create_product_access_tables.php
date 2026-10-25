<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('products', function (Blueprint $table): void {
            $table->id();
            $table->string('slug', 100)->unique();
            $table->string('name', 150);
            $table->string('status', 20)->default('active');
            $table->timestamps();
            $table->index(['status', 'name']);
        });

        Schema::create('product_plans', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('product_id')->constrained('products')->restrictOnDelete();
            $table->string('slug', 100);
            $table->string('name', 150);
            $table->string('status', 20)->default('active');
            $table->unsignedInteger('seat_limit')->nullable();
            $table->string('billing_interval', 20)->nullable();
            $table->timestamps();
            $table->unique(['product_id', 'slug']);
            $table->index(['product_id', 'status']);
        });

        Schema::create('product_entitlements', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('plan_id')->constrained('product_plans')->restrictOnDelete();
            $table->string('feature_key', 120);
            $table->boolean('enabled')->default(true);
            $table->unsignedBigInteger('usage_limit')->nullable();
            $table->timestamps();
            $table->unique(['plan_id', 'feature_key']);
        });

        Schema::create('product_organizations', function (Blueprint $table): void {
            $table->id();
            $table->uuid('public_id')->unique();
            $table->foreignId('product_id')->constrained('products')->restrictOnDelete();
            $table->foreignId('owner_user_id')->constrained('users')->restrictOnDelete();
            $table->string('name', 150);
            $table->string('status', 20)->default('active');
            $table->timestamps();
            $table->index(['product_id', 'status', 'owner_user_id']);
        });

        Schema::create('product_subscriptions', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('organization_id')->constrained('product_organizations')->restrictOnDelete();
            $table->foreignId('plan_id')->constrained('product_plans')->restrictOnDelete();
            $table->string('status', 20);
            $table->timestamp('starts_at');
            $table->timestamp('renews_at')->nullable();
            $table->timestamp('ends_at')->nullable();
            $table->timestamp('canceled_at')->nullable();
            $table->string('provider', 40)->nullable();
            $table->string('provider_subscription_id', 190)->nullable();
            $table->timestamps();
            $table->index(['organization_id', 'status', 'starts_at', 'ends_at']);
            $table->unique(['provider', 'provider_subscription_id']);
        });

        Schema::create('product_roles', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('organization_id')->constrained('product_organizations')->restrictOnDelete();
            $table->string('role_key', 100);
            $table->string('name', 150);
            $table->timestamps();
            $table->unique(['organization_id', 'role_key']);
        });

        Schema::create('product_role_permissions', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('product_role_id')->constrained('product_roles')->cascadeOnDelete();
            $table->string('permission_key', 150);
            $table->timestamps();
            $table->unique(['product_role_id', 'permission_key']);
        });

        Schema::create('product_memberships', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('organization_id')->constrained('product_organizations')->restrictOnDelete();
            $table->foreignId('user_id')->constrained('users')->restrictOnDelete();
            $table->foreignId('product_role_id')->constrained('product_roles')->restrictOnDelete();
            $table->foreignId('invited_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('status', 20)->default('active');
            $table->timestamp('joined_at')->nullable();
            $table->timestamps();
            $table->unique(['organization_id', 'user_id']);
            $table->index(['user_id', 'status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('product_memberships');
        Schema::dropIfExists('product_role_permissions');
        Schema::dropIfExists('product_roles');
        Schema::dropIfExists('product_subscriptions');
        Schema::dropIfExists('product_organizations');
        Schema::dropIfExists('product_entitlements');
        Schema::dropIfExists('product_plans');
        Schema::dropIfExists('products');
    }
};
