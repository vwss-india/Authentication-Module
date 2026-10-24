<?php

namespace Tests\Unit;

use App\Models\User;
use App\Notifications\AuthEmailVerificationNotification;
use App\Notifications\AuthPasswordResetNotification;
use Tests\TestCase;

class AuthEmailNotificationContentTest extends TestCase
{
    public function test_email_verification_notification_contains_the_token_and_expiry_guidance(): void
    {
        $token = 'verification-token-for-test';
        $user = new User(['email' => 'verify@example.com']);

        $message = (new AuthEmailVerificationNotification($token))->toMail($user);

        $this->assertSame('Verify your VisionWeb account', $message->subject);
        $this->assertContains($token, $message->introLines);
        $this->assertTrue(
            collect($message->introLines)->contains(
                fn (string $line): bool => str_contains($line, 'expires in 30 minutes')
                    && str_contains($line, 'only once')
            )
        );
    }

    public function test_password_reset_notification_links_to_the_reset_endpoint_with_email_and_token(): void
    {
        config(['app.url' => 'https://auth.example.test']);

        $token = 'password-reset-token-for-test';
        $user = new User(['email' => 'reset@example.com']);

        $message = (new AuthPasswordResetNotification($token))->toMail($user);

        $this->assertSame(
            'Reset your VisionWeb Central Authentication password',
            $message->subject
        );
        $this->assertSame('Reset Password', $message->actionText);

        $parts = parse_url($message->actionUrl);
        parse_str($parts['query'] ?? '', $query);

        $this->assertSame('/reset-password', $parts['path'] ?? null);
        $this->assertSame($token, $query['token'] ?? null);
        $this->assertSame($user->email, $query['email'] ?? null);
        $this->assertTrue(
            collect(array_merge($message->introLines, $message->outroLines))
                ->contains(
                    fn (string $line): bool => str_contains($line, 'expires')
                )
        );
    }
}
