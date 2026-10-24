<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Passport::authorizationView('auth.oauth.authorize');
        Passport::deviceUserCodeView('auth.oauth.device.user-code');
        Passport::deviceAuthorizationView('auth.oauth.device.authorize');
    }
}
