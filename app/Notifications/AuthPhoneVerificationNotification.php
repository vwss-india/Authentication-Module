<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class AuthPhoneVerificationNotification extends Notification
{
    use Queueable;

    public function __construct(public readonly string $code) {}

    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Verify your VisionWeb phone number')
            ->greeting('Phone verification requested')
            ->line('Enter this code in VisionWeb to verify your phone number:')
            ->line($this->code)
            ->line('This code expires in 10 minutes and can be used only once.')
            ->line('This message was delivered to your account email.');
    }
}
