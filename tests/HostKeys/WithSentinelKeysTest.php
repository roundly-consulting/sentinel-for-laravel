<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Testing\SentinelTestKeys;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * I-4: a host suite with no Sentinel key in its environment seals for real through
 * `WithSentinelKeys` (or `SentinelTestKeys::install()`), instead of failing on every factory.
 */
it('seals and verifies real seals with no key configured', function (): void {
    $invoice = invoice();

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::keys()->ring()->current()->keyId)->toBe('test-default')
        ->and(config('sentinel.keys.rings.default.key'))->not->toBe(TestCase::ROOT_KEY)->toStartWith('base64:');

    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.01']);

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Tampered);
});

it('installs a fresh key per test', function (): void {
    $first = config('sentinel.keys.rings.default.key');

    config()->set('sentinel.keys.rings.default.key', null);
    SentinelTestKeys::install(app());

    expect(config('sentinel.keys.rings.default.key'))->not->toBe($first)->toStartWith('base64:');
});

it('leaves a ring that already has a key alone', function (): void {
    config()->set('sentinel.keys.rings.default.key', TestCase::ROOT_KEY);
    config()->set('sentinel.keys.rings.default.key_id', 'pinned');

    SentinelTestKeys::install(app());
    SentinelTestKeys::install(app(), rings: ['default']);

    expect(config('sentinel.keys.rings.default.key'))->toBe(TestCase::ROOT_KEY)
        ->and(config('sentinel.keys.rings.default.key_id'))->toBe('pinned');
});

it('leaves database rings alone unless named, then chains a config key in front', function (): void {
    expect(config('sentinel.keys.rings.http.driver'))->toBe('database')
        ->and(fn () => Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example/'), 'test-http'))->toThrow(Exception::class);

    SentinelTestKeys::install(app(), rings: ['http']);

    expect(config('sentinel.keys.rings.http.driver'))->toBe('chain')
        ->and(config('sentinel.keys.rings.http.drivers'))->toBe(['config', 'database'])
        ->and(Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example/'), 'test-http')->getHeaderLine('Signature-Input'))->toContain('keyid="test-http"');
});

it('puts a config slot in front of a chain that has none', function (): void {
    config()->set('sentinel.keys.rings.http.driver', 'chain');
    config()->set('sentinel.keys.rings.http.drivers', ['database']);

    SentinelTestKeys::install(app(), rings: ['http']);

    expect(config('sentinel.keys.rings.http.drivers'))->toBe(['config', 'database'])
        ->and(Sentinel::keys()->ring('http')->current()->keyId)->toBe('test-http');
});

it('installs asymmetric keys too', function (): void {
    config()->set('sentinel.keys.rings.default.key', null);

    SentinelTestKeys::install(app(), Algorithm::Ed25519);

    $invoice = invoice();

    expect(Sentinel::keys()->ring()->current()->algorithm)->toBe(Algorithm::Ed25519)
        ->and(Sentinel::verify($invoice)->isIntact())->toBeTrue()
        ->and(config('sentinel.keys.rings.default.public_key'))->toStartWith('base64:');
});

it('flushes a key store resolved before the install', function (): void {
    config()->set('sentinel.keys.rings.default.key', null);
    config()->set('sentinel.keys.rings.default.key_id', null);
    app(KeyStoreManager::class)->flush();

    expect(fn () => app(KeyStoreManager::class)->signingKey('default'))->toThrow(NoSigningKeyException::class);

    SentinelTestKeys::install(app());

    expect(app(KeyStoreManager::class)->signingKey('default')->keyId)->toBe('test-default');
});

it('refuses an algorithm the ring does not allow, and an unknown ring', function (): void {
    expect(fn () => SentinelTestKeys::install(app(), Algorithm::HmacSha512, ['http']))->toThrow(AlgorithmNotAllowedException::class)
        ->and(fn () => SentinelTestKeys::install(app(), rings: ['nowhere']))->toThrow(SealingMisconfiguredException::class);
});

it('seals through model factories and the facade alike', function (): void {
    $invoice = Invoice::query()->create(['number' => 'H-1']);

    expect(Sentinel::for($invoice)->because('host test')->seal()->version)->toBe(2);
});
