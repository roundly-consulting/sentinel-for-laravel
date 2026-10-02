<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Contracts\KeyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\GeneratedKey;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotationResult;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\UnknownKeyException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\EnvelopeData;
use RoundlyConsulting\Sentinel\Keys\KeyLookup;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\ThrowingOwner;

it('redacts generated and rotated key results and refuses to (un)serialize them', function (): void {
    $info = new KeyInfo('default', 'k', Algorithm::HmacSha256, KeyStatus::Active, 'config', true);
    $generated = new GeneratedKey($info, 'SENTINEL_KEY="base64:secret"', null);
    $rotated = new RotationResult($info, $info, 'SENTINEL_KEY="base64:secret"');

    expect(print_r($generated, true).print_r($rotated, true))->not->toContain('base64:secret')->toContain('[redacted]')
        ->and(print_r(new RotationResult($info), true))->not->toContain('[redacted]')
        ->and(fn () => serialize($rotated))->toThrow(LogicException::class)
        ->and(fn () => unserialize('O:'.strlen(GeneratedKey::class).':"'.GeneratedKey::class.'":0:{}'))->toThrow(LogicException::class)
        ->and(fn () => unserialize('O:'.strlen(RotationResult::class).':"'.RotationResult::class.'":0:{}'))->toThrow(LogicException::class)
        ->and(print_r(new EnvelopeData('r', 'k', 'hmac-sha256', 'base64:secret', null, 'active', Clock::now()), true))->not->toContain('base64:secret');
});

it('turns a lost insert race into a taken key id', function (): void {
    $store = app(KeyStoreManager::class)->writableStore('http');
    $store->insert('raced', KeyMaterial::generate(Algorithm::HmacSha256), Clock::now(), null, null);

    expect(fn () => $store->insert('raced', KeyMaterial::generate(Algorithm::HmacSha256), Clock::now(), null, null))
        ->toThrow(KeyDriverException::class, 'already has a key [raced]');
});

it('refuses to update a key row that vanished', function (): void {
    expect(fn () => app(KeyStoreManager::class)->writableStore('http')->update('gone', static fn (EnvelopeData $data): EnvelopeData => $data))
        ->toThrow(UnknownKeyException::class);
});

it('misses cleanly across every chained driver', function (): void {
    config()->set('sentinel.keys.rings.default.driver', 'chain');

    expect(app(KeyStoreManager::class)->lookup('default', 'nowhere'))->toEqual(new KeyLookup(null, KeyLookup::NOT_FOUND));
});

it('rejects an envelope whose dates are not in canonical form', function (): void {
    $key = Key::factory()->ring('http')->create(['kid' => 'k']);
    $plain = app('encrypter')->decryptString($key->getRawOriginal('envelope'));
    $tampered = (string) preg_replace('/"activates_at":"[^"]+"/', '"activates_at":"yesterday"', $plain);
    Key::query()->whereKey($key->id)->update(['envelope' => app('encrypter')->encryptString($tampered)]);

    expect(app(KeyStoreManager::class)->lookup('http', 'k')->failure)->toBe(KeyLookup::INTEGRITY);
});

it('marks custom-driver keys on the revocation list as revoked in the inventory', function (): void {
    $material = KeyMaterial::generate(Algorithm::HmacSha256);
    Sentinel::extend('memory', static fn (): KeyStore => new class($material) implements KeyStore
    {
        public function __construct(private readonly KeyMaterial $material) {}

        public function signingKey(): SealingKey
        {
            return new SealingKey('memory', 'm1', $this->material, KeyStatus::Active, 'memory');
        }

        public function find(string $keyId): ?SealingKey
        {
            return null;
        }

        public function all(): array
        {
            return [KeyInfo::fromKey($this->signingKey())];
        }

        public function supportsWrites(): bool
        {
            return false;
        }
    });

    config()->set('sentinel.keys.rings.memory', [...config('sentinel.keys.rings.default'), 'driver' => 'memory']);
    config()->set('sentinel.keys.revoked', 'memory:m1');

    $keys = Sentinel::listKeys('memory');

    expect($keys[0]->status)->toBe(KeyStatus::Revoked)->and($keys[0]->canSign)->toBeFalse();
});

it('reports an owner lookup that blows up as not found', function (): void {
    // ThrowingOwner's table does not exist: the lookup throws, and the command says so cleanly.
    $this->artisan('sentinel:key:generate', ['--owner-type' => ThrowingOwner::class, '--owner-id' => '1'])
        ->expectsOutputToContain('model was not found')
        ->assertFailed();
});
