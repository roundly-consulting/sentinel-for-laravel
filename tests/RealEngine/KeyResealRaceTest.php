<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Tests\Support\Forks;

/**
 * `sentinel:key:reseal` re-reads each row under its lock before it writes: a re-seal racing a
 * revocation can never write the row's pre-revocation state back (un-revoke it).
 */
it('never un-revokes a key that is revoked while sentinel:key:reseal runs', function (): void {
    legacyKey('http', 'raced', 'ACME');

    $outcomes = Forks::run(8, static function (int $racer): string {
        if ($racer === 3) {
            return Sentinel::keys()->ring('http')->revoke('raced', 'compromised')->status->value;
        }

        return 'reseal:'.Artisan::call('sentinel:key:reseal', ['--ring' => 'http']);
    });

    app(KeyStoreManager::class)->flush();

    expect(tally($outcomes))->toBe(['reseal:0' => 7, 'revoked' => 1])
        ->and(envelopeOf('http', 'raced')['format'] ?? null)->toBe('sentinel.key/2')
        ->and(envelopeOf('http', 'raced')['status'] ?? null)->toBe('revoked')
        ->and(Sentinel::keys()->ring('http')->find('raced')?->status)->toBe(KeyStatus::Revoked)
        ->and(Sentinel::keys()->ring('http')->find('raced')?->label)->toBe('ACME');
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');
