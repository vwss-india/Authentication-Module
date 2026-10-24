<?php

namespace Tests\Unit;

use Laravel\Passport\Passport;
use Tests\TestCase;

class ProductionConfigurationTest extends TestCase
{
    public function test_environment_example_does_not_enable_debug_by_default(): void
    {
        $environmentExample = file_get_contents(base_path('.env.example'));

        $this->assertIsString($environmentExample);
        $this->assertMatchesRegularExpression('/^APP_DEBUG=false$/m', $environmentExample);
    }

    public function test_environment_example_leaves_the_application_key_unset(): void
    {
        $environmentExample = file_get_contents(base_path('.env.example'));

        $this->assertIsString($environmentExample);
        $this->assertMatchesRegularExpression('/^APP_KEY=$/m', $environmentExample);
    }

    public function test_passport_signing_keys_default_to_ignored_storage_files(): void
    {
        $originalKeyPath = Passport::$keyPath;
        Passport::$keyPath = null;

        try {
            $this->assertSame(storage_path('oauth-private.key'), Passport::keyPath('oauth-private.key'));
            $this->assertSame(storage_path('oauth-public.key'), Passport::keyPath('oauth-public.key'));

            $gitignore = file_get_contents(base_path('.gitignore'));
            $this->assertIsString($gitignore);
            $this->assertStringContainsString('/storage/*.key', $gitignore);
        } finally {
            Passport::$keyPath = $originalKeyPath;
        }
    }
}
