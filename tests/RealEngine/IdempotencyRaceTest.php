<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Enums\IdempotencyOutcome;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\Models\Nonce;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Tests\Support\Forks;

/**
 * @param  list<string>  $outcomes
 * @return array<string, int>
 */
function tally(array $outcomes): array
{
    $counts = array_count_values($outcomes);
    ksort($counts);

    return $counts;
}

/**
 * Plan §12.5 items 3, 4 and 8 on the real engines: of eight concurrent first requests for a
 * key exactly one owns it, of eight attempts to use a nonce exactly one succeeds, and
 * `INSERT … ON CONFLICT DO NOTHING` reports what it did on every driver.
 */
it('lets exactly one of eight concurrent requests own an idempotency key', function (): void {
    $outcomes = Forks::run(8, static fn (): string => app(SentinelManager::class)->beginIdempotentRequest(
        new IdempotentRequest('race-digest', 'scope', 'fingerprint', 3600),
    )->outcome->value);

    expect(tally($outcomes))->toBe([IdempotencyOutcome::InProgress->value => 7, IdempotencyOutcome::Proceed->value => 1])
        ->and(IdempotencyKey::query()->count())->toBe(1);
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');

it('lets exactly one of eight concurrent attempts use a nonce', function (): void {
    $nonce = Sentinel::nonces()->issue('race', ttl: 600);

    $outcomes = Forks::run(8, static fn (): string => Sentinel::nonces()->consume('race', $nonce->value) ? 'used' : 'refused');

    expect(tally($outcomes))->toBe(['refused' => 7, 'used' => 1]);
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');

it('lets exactly one of eight concurrent requests claim a client nonce', function (): void {
    $outcomes = Forks::run(8, static fn (): string => app(NonceStore::class)->remember('http:race', 'seen-digest', now()->toImmutable()->addMinute(), now()->toImmutable()) ? 'fresh' : 'replay');

    expect(tally($outcomes))->toBe(['fresh' => 1, 'replay' => 7])
        ->and(Nonce::query()->count())->toBe(1);
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');

it('counts insert-or-ignore rows on every engine', function (): void {
    $row = ['purpose' => 'count', 'digest' => 'd', 'kind' => 'seen', 'expires_at' => '2030-01-01 00:00:00.000000', 'created_at' => '2026-01-01 00:00:00.000000'];

    expect(Nonce::query()->insertOrIgnore($row))->toBe(1)
        ->and(Nonce::query()->insertOrIgnore($row))->toBe(0)
        ->and(Nonce::query()->insertOrIgnore([$row, [...$row, 'digest' => 'e']]))->toBe(1);
});
