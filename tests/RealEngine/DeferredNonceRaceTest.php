<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Nonce;
use RoundlyConsulting\Sentinel\Tests\Support\Forks;

/**
 * Verify now, commit later — on the real engines: copies of one signed request that all
 * verified with the nonce deferred race to commit it, and exactly one wins.
 */
beforeEach(function (): void {
    partnerRing();
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_000));
});

afterEach(fn () => Carbon::setTestNow());

it('lets exactly one of eight concurrent commits of one nonce succeed', function (): void {
    $signed = signedPartnerRequest();
    $deferred = array_map(static fn (): mixed => Sentinel::signatures()->verifyDeferred(received($signed)), range(1, 8));

    expect(Nonce::query()->count())->toBe(0);

    $outcomes = Forks::run(8, static function (int $racer) use ($deferred): string {
        try {
            Sentinel::signatures()->commitNonce($deferred[$racer]);

            return 'committed';
        } catch (HttpSignatureException $exception) {
            return $exception->reason()->value;
        }
    });

    expect(tally($outcomes))->toBe(['committed' => 1, 'replayed' => 7])
        ->and(Nonce::query()->count())->toBe(1);
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');

it('lets exactly one of eight concurrent verify-then-commit copies through', function (): void {
    $signed = signedPartnerRequest();

    $outcomes = Forks::run(8, static function () use ($signed): string {
        try {
            Sentinel::signatures()->commitNonce(Sentinel::signatures()->verifyDeferred(received($signed)));

            return 'committed';
        } catch (HttpSignatureException $exception) {
            return $exception->reason()->value;
        }
    });

    expect(tally($outcomes))->toBe(['committed' => 1, 'replayed' => 7])
        ->and(Nonce::query()->count())->toBe(1);
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');
