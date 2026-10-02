<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;
use RoundlyConsulting\Sentinel\Events\KeyGenerated;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * §10 item 32: key material never surfaces in exceptions, dumps, serialization, events,
 * `about` or command output.
 */
it('keeps the root key out of dumps, events, about and the key inventory', function (): void {
    $secret = substr(TestCase::ROOT_KEY, 7);
    Event::fake();

    $key = app(KeyStoreManager::class)->signingKey('default');
    $generated = Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256);
    $config = Sentinel::keys()->ring()->generate(Algorithm::HmacSha256, destination: KeyDestination::Config);

    Artisan::call('about', ['--only' => 'sentinel']);
    $about = Artisan::output();
    Artisan::call('sentinel:key:list');
    $inventory = Artisan::output();

    $events = serialize(array_map(static fn (array $dispatched): array => $dispatched, Event::dispatched(KeyGenerated::class)->all()));

    expect(print_r($key, true))->not->toContain($secret)
        ->and(print_r($config, true))->not->toContain((string) $config->envSnippet)->toContain('[redacted]')
        ->and(print_r(app(KeyStoreManager::class)->ring('default'), true))->not->toContain($secret)
        ->and($about.$inventory.$events)->not->toContain($secret)->not->toContain('base64:')
        ->and(fn () => serialize($config))->toThrow(LogicException::class)
        ->and(fn () => serialize($generated->info))->not->toThrow(LogicException::class);
});

it('never puts material into exception messages', function (): void {
    config()->set('sentinel.keys.rings.default.key', 'base64:'.base64_encode('a-passphrase-that-is-not-random!!'));
    config()->set('sentinel.keys.rings.default.previous', 'old|ed25519|base64:'.base64_encode(base64_decode(substr(TestCase::ROOT_KEY, 7)).'!'));
    app(KeyStoreManager::class)->flush();

    try {
        app(KeyStoreManager::class)->signingKey('default');
    } catch (Throwable $exception) {
        expect($exception->getMessage())->not->toContain('passphrase')->not->toContain('YS1wYXNz');
    }

    config()->set('sentinel.keys.rings.default.key', TestCase::ROOT_KEY);
    app(KeyStoreManager::class)->flush();

    try {
        app(KeyStoreManager::class)->find('default', 'old');
        $this->fail('expected a configuration error');
    } catch (Throwable $exception) {
        expect($exception->getMessage())->toContain('entry #1')->not->toContain(substr(TestCase::ROOT_KEY, 7, 20));
    }
});
