<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class AuthPasswordResetNotification extends Notification
{
    use Queueable;

    public function __construct(
        private readonly string $token,
    ) {
    }

    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $baseUrl = rtrim(
            (string) config(
                'services.auth_password_reset_url',
                config('app.url').'/reset-password'
            ),
            '/'
        );

        $resetUrl = $baseUrl.'?'.http_build_query([
            'token' => $this->token,
            'email' => $notifiable->email,
        ]);

        return (new MailMessage())
            ->subject('Reset your VisionWeb Central Authentication password')
            ->greeting('Password reset requested')
            ->line('We received a request to reset your password.')
            ->action('Reset Password', $resetUrl)
            ->line('This link expires according to the configured password reset expiry.')
            ->line('If you did not request this, you can ignore this email.');
    }
}