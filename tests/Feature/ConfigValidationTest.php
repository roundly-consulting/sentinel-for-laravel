<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\DigestAlgorithm;
use RoundlyConsulting\Sentinel\Enums\HealthStatus;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Signatures\ProfileResolver;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Ledger\AnchorManager;
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

it('refuses a mistyped boolean instead of reading it as the default (dual-review O-30 / F-3)', function (string $key, Closure $read): void {
    config()->set("sentinel.{$key}", 'disabled');

    expect($read)->toThrow(InvalidSentinelConfigurationException::class, "sentinel.{$key}")
        ->and(Sentinel::check()->get('configuration')?->status)->toBe(HealthStatus::Failure);

    config()->set("sentinel.{$key}", 'off');

    expect($read())->toBeFalse();

    config()->set("sentinel.{$key}", 'YES');

    expect($read())->toBeTrue();
})->with([
    'sealing.auto' => ['sealing.auto', static fn (): bool => Settings::autoSeal()],
    'sealing.allow_suspension' => ['sealing.allow_suspension', static fn (): bool => Settings::allowSuspension()],
    'sealing.field_tags' => ['sealing.field_tags', static fn (): bool => Settings::fieldTags()],
    'verification.check_ledger' => ['verification.check_ledger', static fn (): bool => Settings::checkLedger()],
    'verification.outdated_is_intact' => ['verification.outdated_is_intact', static fn (): bool => Settings::outdatedIsIntact()],
    'verification.retrieve_checks_ledger' => ['verification.retrieve_checks_ledger', static fn (): bool => Settings::retrieveChecksLedger()],
    'ledger.enabled' => ['ledger.enabled', static fn (): bool => Settings::ledgerEnabled()],
    'idempotency.accept_unquoted' => ['idempotency.accept_unquoted', static fn (): bool => Settings::idempotencyAcceptsUnquoted()],
    'idempotency.store_client_errors' => ['idempotency.store_client_errors', static fn (): bool => Settings::storesClientErrors()],
    'idempotency.store_server_errors' => ['idempotency.store_server_errors', static fn (): bool => Settings::storesServerErrors()],
    'idempotency.transactional' => ['idempotency.transactional', static fn (): bool => Settings::idempotencyTransactional()],
    'idempotency.encrypt' => ['idempotency.encrypt', static fn (): bool => Settings::idempotencyEncrypt()],
    'signatures.outbound.include_alg' => ['signatures.outbound.include_alg', static fn (): bool => Settings::outboundIncludesAlg()],
    'signatures.advertise' => ['signatures.advertise', static fn (): bool => Settings::advertisesSignatures()],
    'schedule.enabled' => ['schedule.enabled', static fn (): bool => Settings::scheduleEnabled()],
    'signatures.profiles.default.require_nonce' => ['signatures.profiles.default.require_nonce', static fn (): bool => ProfileResolver::resolve()->requireNonce],
    'signatures.profiles.default.require_query' => ['signatures.profiles.default.require_query', static fn (): bool => ProfileResolver::resolve()->requireQuery],
    'signatures.profiles.default.require_content_digest' => ['signatures.profiles.default.require_content_digest', static fn (): bool => ProfileResolver::resolve()->requireContentDigest],
    'signatures.profiles.default.accept_signing_keys' => ['signatures.profiles.default.accept_signing_keys', static fn (): bool => ProfileResolver::resolve()->acceptSigningKeys],
]);

it('never runs a suspension behind a mistyped allow_suspension (dual-review O-30)', function (): void {
    config()->set('sentinel.sealing.allow_suspension', 'disabled');

    expect(fn () => Sentinel::withoutSealing(static fn (): string => 'ran unsealed', 'import'))->toThrow(InvalidSentinelConfigurationException::class);
});

it('refuses a non-string optional setting instead of reading it as unset (strict config)', function (string $key, Closure $read): void {
    config()->set("sentinel.{$key}", ['x']);

    expect($read)->toThrow(InvalidSentinelConfigurationException::class, $key);
})->with([
    'log channel' => ['verification.log_channel', static fn () => Settings::logChannel()],
    'acknowledgement ability' => ['acknowledgement.ability', static fn () => Settings::acknowledgementAbility()],
]);

it('reads a blank optional setting as unset (strict config)', function (): void {
    config()->set('sentinel.verification.log_channel', '  ');
    config()->set('sentinel.acknowledgement.ability', '');

    expect(Settings::logChannel())->toBeNull()
        ->and(Settings::acknowledgementAbility())->toBeNull();
});

it('refuses a signature profile ring it cannot check against the sealing rings (strict config)', function (string $key, mixed $value, string $named): void {
    config()->set($key, $value);

    expect(fn () => Settings::signatureRings())->toThrow(InvalidSentinelConfigurationException::class, $named);
})->with([
    'profiles not an array' => ['sentinel.signatures.profiles', 'default', 'signatures.profiles'],
    'profile not an array' => ['sentinel.signatures.profiles', ['partner' => 'http'], 'signatures.profiles.partner.ring'],
    'profile ring not a string' => ['sentinel.signatures.profiles', ['partner' => ['ring' => 42]], 'signatures.profiles.partner.ring'],
    'outbound ring not a string' => ['sentinel.signatures.outbound.ring', ['http'], 'signatures.outbound.ring'],
]);

it('refuses a mistyped anchor setting instead of anchoring with the default (strict config)', function (string $anchor, string $key, mixed $value): void {
    config()->set('sentinel.ledger.anchors', $anchor);
    config()->set("sentinel.ledger.anchor_drivers.{$anchor}.{$key}", $value);

    expect(fn () => app(AnchorManager::class)->build($anchor))
        ->toThrow(InvalidSentinelConfigurationException::class, "ledger.anchor_drivers.{$anchor}.{$key}");
})->with([
    'cache store not a string' => ['cache', 'store', ['redis']],
    'cache key not a string' => ['cache', 'key', ['sentinel']],
    'filesystem disk not a string' => ['filesystem', 'disk', 5],
    'filesystem path not a string' => ['filesystem', 'path', 7],
    'log channel not a string' => ['log', 'channel', false],
]);

/*
 * Owner decision (blank means not set): a host's blank value — `SENTINEL_X=` puts `''` in
 * config — is the same as leaving the key out, so the shipped default applies. Junk still
 * throws (covered above); only blank changed.
 */
it('reads blank scalar settings as not set, so the shipped defaults apply (strict config)', function (string $blank): void {
    foreach ([
        'sentinel.context', 'sentinel.database.connection', 'sentinel.keys.default_ring',
        'sentinel.sealing.on_tampered_write', 'sentinel.verification.retrieve_reaction', 'sentinel.ledger.ring',
        'sentinel.middleware.verified_reaction', 'sentinel.idempotency.store', 'sentinel.idempotency.header',
        'sentinel.idempotency.replay_header', 'sentinel.idempotency.methods', 'sentinel.idempotency.replayed_headers',
        'sentinel.nonces.store', 'sentinel.signatures.outbound.ring', 'sentinel.signatures.outbound.label',
        'sentinel.signatures.outbound.digest', 'sentinel.signatures.outbound.expires_in', 'sentinel.signatures.outbound.tag',
        'sentinel.signatures.default_profile',
    ] as $key) {
        config()->set($key, $blank);
    }

    expect(Settings::context())->toBe('')
        ->and(Settings::keyConnection())->toBeNull()
        ->and(Settings::defaultRing())->toBe('default')
        ->and(Settings::onTamperedWrite())->toBe(TamperedWritePolicy::Refuse)
        ->and(Settings::retrieveReaction())->toBe(Reaction::Throw)
        ->and(Settings::ledgerRing())->toBe('default')
        ->and(Settings::verifiedAborts())->toBeTrue()
        ->and(Settings::idempotencyStore())->toBe('database')
        ->and(Settings::idempotencyHeader())->toBe('Idempotency-Key')
        ->and(Settings::replayHeader())->toBe('Idempotent-Replayed')
        ->and(Settings::idempotencyMethods())->toBe(['POST', 'PATCH'])
        ->and(Settings::replayedHeaders())->toBe([])
        ->and(Settings::nonceStore())->toBe('database')
        ->and(Settings::outboundRing())->toBe('http')
        ->and(Settings::outboundLabel())->toBe('sig1')
        ->and(Settings::outboundDigest())->toBe(DigestAlgorithm::Sha256)
        ->and(Settings::outboundExpiresIn())->toBeNull()
        ->and(Settings::outboundTag())->toBeNull()
        ->and(ProfileResolver::defaultProfile())->toBe('default');
})->with(['empty' => [''], 'whitespace' => ['  ']]);

it('reads blank ring settings as not set (strict config)', function (): void {
    config()->set('sentinel.keys.rings.default.key_id', '');
    config()->set('sentinel.keys.rings.default.algorithm', ' ');
    config()->set('sentinel.keys.rings.default.public_key', '');
    config()->set('sentinel.keys.rings.default.previous', '');

    $ring = Settings::ring('default');

    expect($ring->keyId)->toBeNull()
        ->and($ring->algorithm)->toBe(Algorithm::HmacSha256)
        ->and($ring->publicKey)->toBeNull()
        ->and($ring->previous)->toBe('');

    // The driver has no default: blank is missing, and missing still throws.
    config()->set('sentinel.keys.rings.default.driver', '');
    expect(fn () => Settings::ring('default'))->toThrow(InvalidSentinelConfigurationException::class, 'keys.rings.default.driver');
});

it('reads blank signature profile settings as not set (strict config)', function (): void {
    config()->set('sentinel.signatures.profiles.default.ring', '');
    config()->set('sentinel.signatures.profiles.default.label', '');
    config()->set('sentinel.signatures.profiles.default.tag', ' ');
    config()->set('sentinel.signatures.profiles.default.max_age', '');
    config()->set('sentinel.signatures.profiles.default.clock_skew', ' ');

    $profile = ProfileResolver::resolve();

    expect($profile->ring)->toBe('http')
        ->and($profile->label)->toBeNull()
        ->and($profile->tag)->toBeNull()
        ->and($profile->maxAge)->toBe(300)
        ->and($profile->clockSkew)->toBe(30)
        ->and(Settings::signatureRings())->toContain('http');
});

it('reads a blank anchor key or path as the shipped one (strict config)', function (string $anchor, string $key): void {
    config()->set('sentinel.ledger.anchors', $anchor);
    config()->set("sentinel.ledger.anchor_drivers.{$anchor}.{$key}", '');

    expect(app(AnchorManager::class)->build($anchor))->not->toBeNull();
})->with([
    'cache key' => ['cache', 'key'],
    'filesystem path' => ['filesystem', 'path'],
]);
