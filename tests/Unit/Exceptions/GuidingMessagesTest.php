<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * I-17: error messages say what to do — and never echo material or unsanitised input.
 */
it('lists the declared seals of a model', function (): void {
    expect(fn () => Sentinel::for(invoice(), 'finanical'))->toThrow(SealingMisconfiguredException::class, 'declares no seal [finanical]; declared: financial, identity.')
        ->and(fn () => Sentinel::model(Invoice::class)->definition("evil\n"))->toThrow(SealingMisconfiguredException::class, 'declares no seal [(invalid)]; declared: financial, identity.')
        ->and(SealingMisconfiguredException::unknownSeal(Invoice::class, 'x')->getMessage())->toBe('['.Invoice::class.'] declares no seal [x].');
});

it('names the environment variables of a config ring that cannot sign', function (string $ring, string $variables): void {
    config()->set('app.env', 'production');
    config()->set("sentinel.keys.rings.{$ring}.driver", 'config');
    config()->set("sentinel.keys.rings.{$ring}.key", null);
    app(KeyStoreManager::class)->flush();

    try {
        app(KeyStoreManager::class)->signingKey($ring);
        test()->fail('expected NoSigningKeyException');
    } catch (NoSigningKeyException $exception) {
        expect($exception->getMessage())->toBe("Key ring [{$ring}] has no active signing key. Generate one with `php artisan sentinel:key:generate --ring={$ring}` and set {$variables} from the lines it prints.")
            ->not->toContain(substr(TestCase::ROOT_KEY, 7));
    }
})->with([
    'default' => ['default', 'SENTINEL_KEY_ID and SENTINEL_KEY'],
    'http' => ['http', 'SENTINEL_HTTP_KEY_ID and SENTINEL_HTTP_KEY'],
]);

it('names the config keys of a custom config ring, and nothing for a database ring', function (): void {
    config()->set('app.env', 'production');
    config()->set('sentinel.keys.rings.partners', ['driver' => 'chain', 'drivers' => ['config', 'database'], 'algorithms' => ['hmac-sha256']]);

    expect(NoSigningKeyException::forRing('partners')->getMessage())->toContain('and set sentinel.keys.rings.partners.key_id and .key from the lines it prints.')
        ->and(NoSigningKeyException::forRing('http')->getMessage())->toBe('Key ring [http] has no active signing key. Generate one with `php artisan sentinel:key:generate --ring=http`.')
        ->and(NoSigningKeyException::forRing('nowhere')->getMessage())->toBe('Key ring [nowhere] has no active signing key. Generate one with `php artisan sentinel:key:generate --ring=nowhere`.');
});

it('points a test suite at WithSentinelKeys or the fake', function (): void {
    config()->set('app.env', 'testing');

    expect(NoSigningKeyException::forRing('default')->getMessage())
        ->toEndWith('In tests, use RoundlyConsulting\\Sentinel\\Testing\\WithSentinelKeys (real throwaway keys) or Sentinel::fake().');
});

it('explains how a read-only ring takes verify-only keys', function (string $ring, string $hint): void {
    expect(KeyDriverException::readOnly($ring)->getMessage())->toContain("sentinel.keys.rings.{$ring}.previous as kid|algorithm|base64:…{$hint}, or set the ring's driver to database or chain.");
})->with([
    'default' => ['default', ' (SENTINEL_PREVIOUS_KEYS in the shipped config)'],
    'http' => ['http', ' (SENTINEL_HTTP_KEYS in the shipped config)'],
    'custom' => ['partners', ''],
]);
