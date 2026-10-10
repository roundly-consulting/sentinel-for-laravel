<?php

declare(strict_types=1);

use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Sentinel\Contracts\KeyStore;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyLookup;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Stores\ChainKeyStore;
use RoundlyConsulting\Sentinel\Keys\Stores\ConfigKeyStore;
use RoundlyConsulting\Sentinel\Keys\Stores\DatabaseKeyStore;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Tests\TestCase;

function keyStores(): KeyStoreManager
{
    return app(KeyStoreManager::class);
}

it('builds the store each ring driver names', function (): void {
    config()->set('sentinel.keys.rings.chained', [...config('sentinel.keys.rings.default'), 'driver' => 'chain']);

    expect(keyStores()->ring('default'))->toBeInstanceOf(ConfigKeyStore::class)
        ->and(keyStores()->ring('http'))->toBeInstanceOf(DatabaseKeyStore::class)
        ->and(keyStores()->ring('chained'))->toBeInstanceOf(ChainKeyStore::class)
        ->and(keyStores()->ring('default'))->toBe(keyStores()->ring('default'));
});

it('signs with the default ring test key', function (): void {
    $key = keyStores()->signingKey('default');

    expect($key->keyId)->toBe(TestCase::ROOT_KEY_ID)->and($key->canSign())->toBeTrue();
});

it('chains drivers: first signing key wins, a kid resolves in the first store that knows it', function (): void {
    config()->set('sentinel.keys.rings.default.driver', 'chain');
    config()->set('sentinel.keys.rings.default.drivers', ['database', 'config']);
    keyStores()->flush();

    expect(keyStores()->signingKey('default')->driver)->toBe('config');

    $stored = Key::factory()->create(['kid' => 'db-key']);

    expect(keyStores()->signingKey('default')->keyId)->toBe('db-key')
        ->and(keyStores()->find('default', TestCase::ROOT_KEY_ID)?->driver)->toBe('config')
        ->and(keyStores()->find('default', 'db-key')?->driver)->toBe('database')
        ->and(keyStores()->all('default'))->toHaveCount(2)
        ->and(keyStores()->ring('default')->supportsWrites())->toBeTrue()
        ->and(keyStores()->writableStore('default'))->toBeInstanceOf(DatabaseKeyStore::class)
        ->and($stored->kid)->toBe('db-key');

    config()->set('sentinel.keys.rings.default.drivers', ['config']);
    config()->set('sentinel.keys.rings.default.key', null);
    keyStores()->flush();

    expect(fn () => keyStores()->signingKey('default'))->toThrow(NoSigningKeyException::class)
        ->and(keyStores()->ring('default')->supportsWrites())->toBeFalse();
});

it('refuses writes to rings without a database driver', function (): void {
    expect(keyStores()->hasWritableStore('default'))->toBeFalse()
        ->and(keyStores()->hasWritableStore('http'))->toBeTrue()
        ->and(fn () => keyStores()->writableStore('default'))->toThrow(KeyDriverException::class, 'no database driver');
});

it('registers custom drivers and applies the revocation list on top of them', function (): void {
    $material = KeyMaterial::fromEncoded(Algorithm::HmacSha256, TestCase::ROOT_KEY);
    $custom = new class($material) implements KeyStore
    {
        public function __construct(private readonly KeyMaterial $material) {}

        public function signingKey(): SealingKey
        {
            return new SealingKey('vault', 'kms-1', $this->material, KeyStatus::Active, 'kms');
        }

        public function find(string $keyId): ?SealingKey
        {
            return $keyId === 'kms-1' ? $this->signingKey() : null;
        }

        public function all(): array
        {
            return [];
        }

        public function supportsWrites(): bool
        {
            return false;
        }
    };

    $received = null;
    Sentinel::extend('kms', function (Container $app, string $ring, array $config) use ($custom, &$received): KeyStore {
        $received = [$ring, $config['driver']];

        return $custom;
    });

    config()->set('sentinel.keys.rings.vault', [...config('sentinel.keys.rings.default'), 'driver' => 'kms']);

    expect(keyStores()->signingKey('vault')->keyId)->toBe('kms-1')
        ->and($received)->toBe(['vault', 'kms']);

    config()->set('sentinel.keys.revoked', 'vault:kms-1');

    expect(keyStores()->find('vault', 'kms-1')?->status)->toBe(KeyStatus::Revoked)
        ->and(fn () => keyStores()->signingKey('vault'))->toThrow(NoSigningKeyException::class);
});

/**
 * Chat review C-16: a chain moves on past a revoked key of a custom driver, as it does past a
 * built-in store's (which apply the list themselves).
 */
it('falls back to the next chained store when a custom driver\'s key is revoked', function (): void {
    $material = KeyMaterial::generate(Algorithm::HmacSha256);
    Sentinel::extend('vault', static fn (): KeyStore => new class($material) implements KeyStore
    {
        public function __construct(private readonly KeyMaterial $material) {}

        public function signingKey(): SealingKey
        {
            return new SealingKey('default', 'vault-1', $this->material, KeyStatus::Active, 'vault');
        }

        public function find(string $keyId): ?SealingKey
        {
            return $keyId === 'vault-1' ? $this->signingKey() : null;
        }

        public function all(): array
        {
            return [];
        }

        public function supportsWrites(): bool
        {
            return false;
        }
    });
    config()->set('sentinel.keys.rings.default.driver', 'chain');
    config()->set('sentinel.keys.rings.default.drivers', ['vault', 'config']);

    expect(keyStores()->signingKey('default')->keyId)->toBe('vault-1');

    config()->set('sentinel.keys.revoked', 'default:vault-1');
    keyStores()->flush();

    expect(keyStores()->signingKey('default')->keyId)->toBe(TestCase::ROOT_KEY_ID)
        ->and(Sentinel::currentKey()->keyId)->toBe(TestCase::ROOT_KEY_ID);

    // With no other store to fall back to, a revoked key still signs nothing.
    config()->set('sentinel.keys.rings.default.drivers', ['vault']);
    keyStores()->flush();

    expect(fn () => keyStores()->signingKey('default'))->toThrow(NoSigningKeyException::class);
});

it('refuses a custom driver factory that returns no key store', function (): void {
    Sentinel::extend('broken', static fn (): stdClass => new stdClass);
    config()->set('sentinel.keys.rings.broken', [...config('sentinel.keys.rings.default'), 'driver' => 'broken']);

    expect(fn () => keyStores()->ring('broken'))->toThrow(InvalidSentinelConfigurationException::class, 'keys.rings.broken.driver');
});

it('reports why a key cannot be found', function (): void {
    expect(keyStores()->lookup('default', 'nope'))->toEqual(new KeyLookup(null, KeyLookup::NOT_FOUND))
        ->and(keyStores()->lookup('default', TestCase::ROOT_KEY_ID)->key?->keyId)->toBe(TestCase::ROOT_KEY_ID);

    Key::factory()->ring('http')->create(['kid' => 'partner']);
    Key::query()->where('kid', 'partner')->update(['algorithm' => 'hmac-sha512']);

    expect(keyStores()->lookup('http', 'partner'))->toEqual(new KeyLookup(null, KeyLookup::INTEGRITY));
});

it('refuses unknown rings everywhere', function (): void {
    expect(fn () => keyStores()->ring('nope'))->toThrow(SealingMisconfiguredException::class, '[nope]')
        ->and(fn () => Sentinel::keys()->ring('nope'))->toThrow(SealingMisconfiguredException::class)
        ->and(fn () => Sentinel::listKeys('nope'))->toThrow(SealingMisconfiguredException::class)
        ->and(fn () => keyStores()->ring("Bad\nring"))->toThrow(SealingMisconfiguredException::class, '(invalid)');
});

it('lists every ring and folds the revocation list into the inventory', function (): void {
    Key::factory()->ring('http')->ed25519()->create(['kid' => 'partner']);
    config()->set('sentinel.keys.revoked', 'default:'.TestCase::ROOT_KEY_ID);

    $keys = keyStores()->all();

    expect(array_map(static fn ($key): string => "{$key->ring}:{$key->keyId}:{$key->status->value}", $keys))
        ->toBe(['default:'.TestCase::ROOT_KEY_ID.':revoked', 'http:partner:active']);
});
