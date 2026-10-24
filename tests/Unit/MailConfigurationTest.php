<?php

namespace Tests\Unit;

use Tests\TestCase;

class MailConfigurationTest extends TestCase
{
    public function test_log_mailer_uses_a_null_channel_to_prevent_message_body_logging(): void
    {
        $configuration = require dirname(__DIR__, 2).'/config/mail.php';

        $this->assertSame('log', $configuration['mailers']['log']['transport']);
        $this->assertSame('null', $configuration['mailers']['log']['channel']);
    }
}
