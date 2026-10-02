<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * §10 item 57: invalid configuration throws at first use, naming the key — never a silent
 * fallback on a security-relevant value.
 */
it('refuses invalid key configuration with the key name', function (string $key, mixed $value, string $named): void {
    config()->set($key, $value);
    app(KeyStoreManager::class)->flush();

    expect(fn () => app(KeyStoreManager::class)->signingKey('default'))
        ->toThrow(InvalidSentinelConfigurationException::class, $named);
})->with([
    'unknown driver' => ['sentinel.keys.rings.default.driver', 'vault', 'keys.rings.default.driver'],
    'empty driver' => ['sentinel.keys.rings.default.driver', '', 'keys.rings.default.driver'],
    'none in the algorithm list' => ['sentinel.keys.rings.default.algorithms', ['hmac-sha256', 'none'], 'keys.rings.default.algorithms'],
    'HS256 in the algorithm list' => ['sentinel.keys.rings.default.algorithms', ['HS256'], 'keys.rings.default.algorithms'],
    'empty algorithm list' => ['sentinel.keys.rings.default.algorithms', [], 'keys.rings.default.algorithms'],
    'algorithm map instead of list' => ['sentinel.keys.rings.default.algorithms', ['a' => 'hmac-sha256'], 'keys.rings.default.algorithms'],
    'unknown pinned algorithm' => ['sentinel.keys.rings.default.algorithm', 'rsa-pss-sha512', 'keys.rings.default.algorithm'],
    'invalid key id' => ['sentinel.keys.rings.default.key_id', 'bad kid', 'keys.rings.default.key_id'],
    'non-string key' => ['sentinel.keys.rings.default.key', ['x'], 'keys.rings.default.key'],
    'non-string previous' => ['sentinel.keys.rings.default.previous', ['x'], 'keys.rings.default.previous'],
    'bad previous entry' => ['sentinel.keys.rings.default.previous', 'kid-only', 'keys.rings.default.previous'],
    'nested chain' => ['sentinel.keys.rings.default.drivers', ['chain'], 'keys.rings.default.drivers'],
    'empty chain' => ['sentinel.keys.rings.default.drivers', [], 'keys.rings.default.drivers'],
    'chain is not a list' => ['sentinel.keys.rings.default.drivers', 'config', 'keys.rings.default.drivers'],
    'bad revocation entry' => ['sentinel.keys.revoked', 'default', 'keys.revoked'],
    'rings is not an array' => ['sentinel.keys.rings', 'default', 'keys.rings'],
    'bad ring name' => ['sentinel.keys.rings.Bad', [], 'keys.rings'],
]);

it('validates the scalar settings', function (): void {
    config()->set('sentinel.database.connection', ['x']);
    expect(fn () => Settings::keyConnection())->toThrow(InvalidSentinelConfigurationException::class, 'database.connection');

    config()->set('sentinel.database.connection', '');
    expect(Settings::keyConnection())->toBeNull();

    config()->set('sentinel.database.connection', 'tenant');
    expect(Settings::keyConnection())->toBe('tenant');

    // The migrations read it too — teardown must not chase a connection that does not exist.
    config()->set('sentinel.database.connection', null);

    config()->set('sentinel.keys.default_ring', 'Not A Ring');
    expect(fn () => Settings::defaultRing())->toThrow(InvalidSentinelConfigurationException::class, 'keys.default_ring');
});

it('uses the default chain order and algorithm when a ring omits them', function (): void {
    config()->set('sentinel.keys.rings.minimal', ['driver' => 'config', 'algorithms' => ['ed25519']]);

    $ring = Settings::ring('minimal');

    expect($ring->drivers)->toBe(['config', 'database'])
        ->and($ring->algorithm->value)->toBe('hmac-sha256')
        ->and($ring->previous)->toBe('')
        ->and(print_r($ring, true))->toContain('[redacted]');
});

it('refuses an invalid outbound signing configuration with the key name', function (string $key, mixed $value, Closure $read): void {
    config()->set("sentinel.signatures.outbound.{$key}", $value);

    expect($read)->toThrow(InvalidSentinelConfigurationException::class, "signatures.outbound.{$key}");
})->with([
    'unknown ring' => ['ring', 'partners', static fn () => Settings::outboundRing()],
    'non-string ring' => ['ring', ['http'], static fn () => Settings::outboundRing()],
    'invalid label' => ['label', 'Sig 1', static fn () => Settings::outboundLabel()],
    'non-printable tag' => ['tag', "app\n", static fn () => Settings::outboundTag()],
    'non-string tag' => ['tag', 7, static fn () => Settings::outboundTag()],
]);
