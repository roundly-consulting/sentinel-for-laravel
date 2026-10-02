<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Tests\Support\Forks;

/**
 * I-1 on the real engines: of concurrent imports of one kid exactly one is stored; every
 * other one is refused as taken — by the lookup, or by the unique index when it raced past it.
 */
it('stores exactly one of eight concurrent imports of one kid', function (): void {
    $outcomes = Forks::run(8, static function (): string {
        try {
            Sentinel::keys()->ring('http')->import('raced-import', Algorithm::HmacSha256, PARTNER_SECRET);

            return 'imported';
        } catch (KeyDriverException $exception) {
            return str_contains($exception->getMessage(), 'already has a key [raced-import]') ? 'taken' : $exception->getMessage();
        }
    });

    expect(tally($outcomes))->toBe(['imported' => 1, 'taken' => 7])
        ->and(Key::query()->where('kid', 'raced-import')->count())->toBe(1);
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');
