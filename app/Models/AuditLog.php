<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class AuditLog extends Model
{
    protected $guarded = [];

    public static function recordEntry(Request $request, ?User $actor, string $action, array $details = []): void
    {
        DB::transaction(function () use ($request, $actor, $action, $details): void {
            $previous = DB::table('audit_logs')->orderByDesc('sequence_number')->lockForUpdate()->first();
            $sequence = ((int) ($previous->sequence_number ?? 0)) + 1;
            $entry = [
                'sequence_number' => $sequence,
                'event_id' => (string) Str::uuid(),
                'actor_user_id' => $actor?->id,
                'actor_public_id' => $actor?->public_id,
                'action' => Str::limit($action, 120, ''),
                'subject_type' => null,
                'subject_id' => null,
                'details' => self::canonicalize($details),
                'ip_address' => $request->ip(),
                'request_id' => Str::limit((string) $request->header('X-Request-ID'), 100, '') ?: null,
                'previous_hash' => $previous->entry_hash ?? null,
                'occurred_at' => now()->utc()->format('Y-m-d H:i:s.u'),
            ];

            DB::table('audit_logs')->insert([
                ...$entry,
                'details' => json_encode($entry['details'], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
                'entry_hash' => self::hashEntry($entry),
            ]);
        });
    }

    /** @return array{valid: bool, entries: int, last_sequence: int, error_sequence: ?int} */
    public static function verifyChain(): array
    {
        $expectedSequence = 1;
        $previousHash = null;

        foreach (DB::table('audit_logs')->orderBy('sequence_number')->cursor() as $row) {
            $details = json_decode((string) $row->details, true) ?: [];
            $entry = [
                'sequence_number' => (int) $row->sequence_number,
                'event_id' => $row->event_id,
                'actor_user_id' => $row->actor_user_id === null ? null : (int) $row->actor_user_id,
                'actor_public_id' => $row->actor_public_id,
                'action' => $row->action,
                'subject_type' => $row->subject_type,
                'subject_id' => $row->subject_id,
                'details' => self::canonicalize($details),
                'ip_address' => $row->ip_address,
                'request_id' => $row->request_id,
                'previous_hash' => $row->previous_hash,
                'occurred_at' => now()->parse($row->occurred_at)->utc()->format('Y-m-d H:i:s.u'),
            ];

            if (
                $entry['sequence_number'] !== $expectedSequence
                || $entry['previous_hash'] !== $previousHash
                || ! hash_equals((string) $row->entry_hash, self::hashEntry($entry))
            ) {
                return [
                    'valid' => false,
                    'entries' => $expectedSequence - 1,
                    'last_sequence' => $expectedSequence - 1,
                    'error_sequence' => (int) $row->sequence_number,
                ];
            }

            $previousHash = $row->entry_hash;
            $expectedSequence++;
        }

        return [
            'valid' => true,
            'entries' => $expectedSequence - 1,
            'last_sequence' => $expectedSequence - 1,
            'error_sequence' => null,
        ];
    }

    public static function hashEntry(array $entry): string
    {
        return hash('sha256', json_encode(self::canonicalize($entry), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    private static function canonicalize(array $value): array
    {
        if (! array_is_list($value)) {
            ksort($value, SORT_STRING);
        }

        foreach ($value as $key => $item) {
            if (is_array($item)) {
                $value[$key] = self::canonicalize($item);
            }
        }

        return $value;
    }
}
