<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class AuthEmailVerificationNotification extends Notification
{
    use Queueable;

    public function __construct(
        public readonly string $token,
    ) {
    }

    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage())
            ->subject('Verify your VisionWeb account')
            ->greeting('Verify your email address')
            ->line('Use this verification token to activate your account:')
            ->line($this->token)
            ->line('The token expires in 30 minutes and can be used only once.')
            ->line('If you did not create this account, you can ignore this email.');
    }
}