<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Tests\Support\Forks;

/**
 * Chat review C-15 on the real engines: concurrent rotations of one ring each demote every key
 * that could still sign, under the ring's row locks — so exactly one key is left signing.
 */
it('leaves exactly one signing key after concurrent rotations', function (): void {
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'raced-rotation');

    $outcomes = Forks::run(4, static function (): string {
        Sentinel::keys()->ring('http')->rotate();

        return 'rotated';
    });

    expect(tally($outcomes))->toBe(['rotated' => 4])
        ->and(Key::query()->where('ring', 'http')->count())->toBe(5)
        ->and(Key::query()->where('ring', 'http')->whereNull('signs_until')->count())->toBe(1);
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');
