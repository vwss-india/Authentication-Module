<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

Schedule::command('security:monitor')->everyMinute()->withoutOverlapping();
Schedule::command('audit:verify --checkpoint')->daily()->withoutOverlapping();
