<?php

namespace App\Console\Commands;

use App\Models\AuditCheckpoint;
use App\Models\AuditLog;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;

#[Signature('audit:verify {--checkpoint : Sign a checkpoint for the latest valid chain entry}')]
#[Description('Verify the audit hash chain and all signed checkpoints.')]
class VerifyAuditChain extends Command
{
    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $verification = AuditLog::verifyChain();

        if (! $verification['valid']) {
            $this->error('Audit chain verification failed at sequence '.$verification['error_sequence'].'.');

            return self::FAILURE;
        }

        if (! AuditCheckpoint::verifyAll()) {
            $this->error('A signed audit checkpoint is invalid.');

            return self::FAILURE;
        }

        if ($this->option('checkpoint')) {
            $checkpoint = AuditCheckpoint::createForLatestEntry();

            if (! $checkpoint) {
                $this->warn('No audit entries are available to checkpoint.');

                return self::SUCCESS;
            }

            $this->info('Signed checkpoint verified at sequence '.$checkpoint->sequence_number.'.');
        }

        $this->info('Verified '.$verification['entries'].' audit entries and all checkpoints.');

        return self::SUCCESS;
    }
}
