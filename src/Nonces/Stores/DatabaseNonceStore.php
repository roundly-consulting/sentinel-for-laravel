<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Nonces\Stores;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\Enums\NonceKind;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Models\Nonce;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Nonce digests in `sentinel_nonces` (plan §9.9). Consuming is ONE conditional UPDATE —
 * purpose, digest, unused, unexpired and the same subject — so of any number of concurrent
 * attempts exactly one affects the row, and a wrong purpose, subject, an expired, used or
 * unknown nonce are indistinguishable. Remembering is `INSERT … ON CONFLICT DO NOTHING`, with
 * an expired record replaced under its row lock.
 *
 * @internal
 */
final class DatabaseNonceStore implements NonceStore
{
    public function issue(string $purpose, string $digest, CarbonImmutable $expiresAt, ?Model $subject): void
    {
        (new Nonce)->forceFill([
            'purpose' => $purpose,
            'digest' => $digest,
            'kind' => NonceKind::Issued,
            'subject_type' => $subject?->getMorphClass(),
            'subject_id' => $subject?->getKey(),
            'expires_at' => $expiresAt,
            'created_at' => Clock::now(),
        ])->save();
    }

    public function consume(string $purpose, string $digest, CarbonImmutable $now, ?Model $subject): bool
    {
        $query = Nonce::query()
            ->where('purpose', $purpose)
            ->where('digest', $digest)
            ->where('kind', NonceKind::Issued->value)
            ->whereNull('consumed_at')
            ->where('expires_at', '>', Clock::database($now));

        return self::subject($query, $subject)->toBase()->update(['consumed_at' => Clock::database($now)]) === 1;
    }

    public function remember(string $purpose, string $digest, CarbonImmutable $until, CarbonImmutable $now): bool
    {
        $row = [
            'purpose' => $purpose,
            'digest' => $digest,
            'kind' => NonceKind::Seen->value,
            'subject_type' => null,
            'subject_id' => null,
            'expires_at' => Clock::database($until),
            'consumed_at' => null,
            'created_at' => Clock::database($now),
        ];

        if (Nonce::query()->insertOrIgnore($row) === 1) {
            return true;
        }

        return (new Nonce)->getConnection()->transaction(static function () use ($purpose, $digest, $now, $row): bool {
            $existing = Nonce::query()->where('purpose', $purpose)->where('digest', $digest)->lockForUpdate()->first();

            if ($existing !== null) {
                try {
                    $live = $existing->expires_at->gt($now);
                } catch (CorruptRecordException) {
                    $live = true;
                }

                // Still remembered: this is a replay.
                if ($live) {
                    return false;
                }

                Nonce::query()->whereKey($existing->getKey())->toBase()->delete();
            }

            return Nonce::query()->insertOrIgnore($row) === 1;
        });
    }

    public function prune(CarbonImmutable $now): int
    {
        return Nonce::query()->where('expires_at', '<=', Clock::database($now))->toBase()->delete();
    }

    public function countExpired(CarbonImmutable $now): int
    {
        return Nonce::query()->where('expires_at', '<=', Clock::database($now))->count();
    }

    /**
     * Exactly the subject the nonce was issued for — and none means none.
     *
     * @param  Builder<Nonce>  $query
     * @return Builder<Nonce>
     */
    private static function subject(Builder $query, ?Model $subject): Builder
    {
        return $subject === null
            ? $query->whereNull('subject_type')
            : $query->where('subject_type', $subject->getMorphClass())->where('subject_id', $subject->getKey());
    }
}
