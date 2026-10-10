<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Canonical\Jcs;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\MacRejection;
use RoundlyConsulting\Sentinel\Events\KeyIntegrityViolated;
use RoundlyConsulting\Sentinel\Exceptions\KeyIntegrityException;
use RoundlyConsulting\Sentinel\Exceptions\MacVerificationException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\EnvelopeData;
use RoundlyConsulting\Sentinel\Keys\KeyEnvelope;
use RoundlyConsulting\Sentinel\Keys\KeyLookup;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\StorageCipher;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

/**
 * 1.2 binds a database key's label into its envelope (`sentinel.key/2`), the way the owner
 * always was. Rows a 1.1 node wrote (`sentinel.key/1`) keep opening — their label read from the
 * column — until `sentinel:key:reseal` upgrades them and `sentinel.keys.require_bound_label`
 * refuses what is left.
 */
function requireBoundLabel(bool $on = true): void
{
    config()->set('sentinel.keys.require_bound_label', $on);
    app(KeyStoreManager::class)->flush();
}

function freshLookup(string $ring, string $kid): KeyLookup
{
    $keys = app(KeyStoreManager::class);
    $keys->flush();

    return $keys->lookup($ring, $kid);
}

function labelMacRefusal(Closure $verify): ?MacRejection
{
    try {
        $verify();

        return null;
    } catch (MacVerificationException $exception) {
        return $exception->reason();
    }
}

it('keeps verifying a key Sentinel 1.1.2 wrote until require_bound_label is turned on', function (): void {
    Event::fake([KeyIntegrityViolated::class]);
    macRing();
    $fixture = legacyFixture();
    DB::table('sentinel_keys')->insert($fixture['row']);
    $message = '{"service":"billing","seq":1}';
    $mac = peerMac($fixture['secret'], $message);

    $info = Sentinel::keys()->ring('logs')->verifyMac('billing-legacy', $message, $mac);

    expect(config('app.key'))->toBe($fixture['app_key'])
        ->and(envelopeOf('logs', 'billing-legacy')['format'] ?? null)->toBe('sentinel.key/1')
        ->and($info->label)->toBe('billing service')
        ->and($info->ownerType)->toBe(User::class)
        ->and((string) $info->ownerId)->toBe('1')
        ->and($info->status)->toBe(KeyStatus::VerifyOnly);

    Event::assertNotDispatched(KeyIntegrityViolated::class);

    requireBoundLabel();

    expect(labelMacRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('billing-legacy', $message, $mac)))->toBe(MacRejection::UnknownKey)
        ->and(freshLookup('logs', 'billing-legacy'))->toEqual(new KeyLookup(null, KeyLookup::INTEGRITY));

    Event::assertDispatched(KeyIntegrityViolated::class, static fn (KeyIntegrityViolated $event): bool => $event->ring === 'logs' && $event->keyId === 'billing-legacy');
});

it('reads a legacy key\'s label from its column, and refuses the row under require_bound_label', function (): void {
    Event::fake([KeyIntegrityViolated::class]);
    legacyKey('http', 'old', 'ACME');

    expect(freshLookup('http', 'old')->key?->label)->toBe('ACME');

    Event::assertNotDispatched(KeyIntegrityViolated::class);

    requireBoundLabel();

    expect(freshLookup('http', 'old'))->toEqual(new KeyLookup(null, KeyLookup::INTEGRITY));

    Event::assertDispatched(KeyIntegrityViolated::class, static fn (KeyIntegrityViolated $event): bool => $event->keyId === 'old');
});

it('never opens a sentinel.key/2 row through the legacy path, require_bound_label off (downgrade)', function (): void {
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'bound', label: 'ACME');

    expect(envelopeOf('http', 'bound')['format'] ?? null)->toBe('sentinel.key/2')
        ->and(envelopeOf('http', 'bound')['label'] ?? null)->toBe('ACME');

    DB::table('sentinel_keys')->where('kid', 'bound')->update(['label' => 'Evil Corp']);

    expect(freshLookup('http', 'bound'))->toEqual(new KeyLookup(null, KeyLookup::INTEGRITY))
        ->and(envelopeOf('http', 'bound'))->toBeNull();
});

it('re-seals a legacy key as sentinel.key/2 when it is revoked, keeping its label', function (): void {
    legacyKey('http', 'old', 'ACME');

    $revoked = Sentinel::keys()->ring('http')->revoke('old', 'compromised');

    expect($revoked->status)->toBe(KeyStatus::Revoked)
        ->and($revoked->label)->toBe('ACME')
        ->and(envelopeOf('http', 'old')['format'] ?? null)->toBe('sentinel.key/2')
        ->and(envelopeOf('http', 'old')['label'] ?? null)->toBe('ACME')
        ->and(keyRow('http', 'old')['label'])->toBe('ACME')
        ->and(keyRow('http', 'old')['revocation_reason'])->toBe('compromised');

    DB::table('sentinel_keys')->where('kid', 'old')->update(['label' => 'Evil Corp']);

    expect(freshLookup('http', 'old'))->toEqual(new KeyLookup(null, KeyLookup::INTEGRITY));
});

it('re-seals a legacy key on every other write too: rotation and retirement', function (): void {
    config()->set('sentinel.keys.rings.default.driver', 'database');
    config()->set('sentinel.keys.rings.default.key', null);
    config()->set('sentinel.keys.rings.default.key_id', null);
    legacyKey('default', 'signer', 'main');
    legacyKey('http', 'partner');

    $rotation = Sentinel::keys()->ring()->rotate();
    Sentinel::keys()->ring('http')->retire('partner');

    expect($rotation->previous?->keyId)->toBe('signer')
        ->and($rotation->previous?->label)->toBe('main')
        ->and(envelopeOf('default', 'signer')['format'] ?? null)->toBe('sentinel.key/2')
        ->and(envelopeOf('default', 'signer')['label'] ?? null)->toBe('main')
        ->and(envelopeOf('default', $rotation->current->keyId)['format'] ?? null)->toBe('sentinel.key/2')
        ->and(envelopeOf('http', 'partner')['format'] ?? null)->toBe('sentinel.key/2')
        ->and(envelopeOf('http', 'partner'))->toHaveKey('label', null);
});

it('opens every key 1.2 writes under require_bound_label', function (): void {
    requireBoundLabel();
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'fresh', label: 'Fresh');
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'bare');

    expect(freshLookup('http', 'fresh')->key?->label)->toBe('Fresh')
        ->and(freshLookup('http', 'bare')->key?->label)->toBeNull()
        ->and(Sentinel::keys()->ring('http')->revoke('fresh', 'rotated out')->label)->toBe('Fresh');
});

it('accepts legacy envelopes unless the host opts in: require_bound_label is off by default', function (): void {
    expect(config('sentinel.keys.require_bound_label'))->toBeFalse()
        ->and(Settings::requireBoundLabel())->toBeFalse();

    config()->set('sentinel.keys.require_bound_label', ' ');

    expect(Settings::requireBoundLabel())->toBeFalse();

    config()->set('sentinel.keys.require_bound_label', 'on');

    expect(Settings::requireBoundLabel())->toBeTrue();
});

it('keeps the label through EnvelopeData::with()', function (): void {
    $data = new EnvelopeData('http', 'k', 'hmac-sha256', 'base64:secret', null, 'active', Clock::now(), label: 'ACME');

    expect($data->with(status: 'revoked', revokedAt: Clock::now())->label)->toBe('ACME')
        ->and((new EnvelopeData('http', 'k', 'hmac-sha256', null, null, 'active', Clock::now()))->label)->toBeNull();
});

/*
 * Downgrade guards: the format is in the associated data and must equal the one the plaintext
 * declares, so no envelope opens as the other format — and a bound label that disagrees with
 * the column is refused like any other bound field.
 */
it('opens an envelope only as the format its plaintext declares', function (string $sealedAs, Closure $forge, bool $opens): void {
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'k', label: 'ACME');
    $row = keyRow('http', 'k');
    $plaintext = envelopeOf('http', 'k') ?? [];
    unset($plaintext['format']);

    DB::table('sentinel_keys')->where('kid', 'k')->update([
        'envelope' => app(StorageCipher::class)->encrypt(StorageCipher::KEY_ENVELOPE, Jcs::encode($forge($plaintext)), keyIdentity($row, $sealedAs)),
    ]);

    expect(freshLookup('http', 'k')->failure)->toBe($opens ? null : KeyLookup::INTEGRITY);
})->with([
    'control: the genuine plaintext, re-encrypted' => ['sentinel.key/2', static fn (array $plaintext): array => $plaintext, true],
    'a sentinel.key/1 plaintext sealed as sentinel.key/2' => ['sentinel.key/2', static fn (array $plaintext): array => [...array_diff_key($plaintext, ['label' => true]), 'v' => 'sentinel.key/1'], false],
    'a sentinel.key/2 plaintext sealed as sentinel.key/1' => ['sentinel.key/1', static fn (array $plaintext): array => $plaintext, false],
    'sentinel.key/2 members declaring sentinel.key/1' => ['sentinel.key/2', static fn (array $plaintext): array => [...$plaintext, 'v' => 'sentinel.key/1'], false],
    'sentinel.key/1 members declaring sentinel.key/2' => ['sentinel.key/1', static fn (array $plaintext): array => [...array_diff_key($plaintext, ['label' => true]), 'v' => 'sentinel.key/2'], false],
    'a bound label that disagrees with the column' => ['sentinel.key/2', static fn (array $plaintext): array => [...$plaintext, 'label' => 'Evil Corp'], false],
    'a label that is not a string' => ['sentinel.key/2', static fn (array $plaintext): array => [...$plaintext, 'label' => 7], false],
]);

it('tells which format a stored envelope opens as, whatever require_bound_label says', function (): void {
    requireBoundLabel();
    $envelopes = app(KeyEnvelope::class);
    $cipher = app(StorageCipher::class);
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'current', label: 'ACME');
    legacyKey('http', 'legacy', 'ACME');
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'relabelled', label: 'ACME');
    DB::table('sentinel_keys')->where('kid', 'relabelled')->update(['label' => 'Evil Corp']);

    // Authenticated, but forged with the key: a plaintext that disagrees, and one that is no JSON.
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'forged', label: 'ACME');
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'garbled', label: 'ACME');
    $forged = [...(envelopeOf('http', 'forged') ?? []), 'status' => 'revoked'];
    unset($forged['format']);
    DB::table('sentinel_keys')->where('kid', 'forged')->update(['envelope' => $cipher->encrypt(StorageCipher::KEY_ENVELOPE, Jcs::encode($forged), keyIdentity(keyRow('http', 'forged'), 'sentinel.key/2'))]);
    DB::table('sentinel_keys')->where('kid', 'garbled')->update(['envelope' => $cipher->encrypt(StorageCipher::KEY_ENVELOPE, 'not json', keyIdentity(keyRow('http', 'garbled'), 'sentinel.key/2'))]);

    $version = static fn (string $kid): ?string => $envelopes->version(Key::query()->where('ring', 'http')->where('kid', $kid)->firstOrFail());

    expect($version('current'))->toBe(KeyEnvelope::VERSION)
        ->and($version('legacy'))->toBe(KeyEnvelope::LEGACY_VERSION)
        ->and($version('relabelled'))->toBeNull()
        ->and($version('forged'))->toBeNull()
        ->and($version('garbled'))->toBeNull()
        ->and(fn () => $envelopes->open(Key::query()->where('kid', 'forged')->firstOrFail()))->toThrow(KeyIntegrityException::class, '(status)')
        ->and(fn () => $envelopes->open(Key::query()->where('kid', 'garbled')->firstOrFail()))->toThrow(KeyIntegrityException::class, '(envelope)')
        ->and(fn () => $envelopes->open(Key::query()->where('kid', 'legacy')->firstOrFail()))->toThrow(KeyIntegrityException::class, '(envelope)');
});

it('still opens a legacy key whose label is not UTF-8 (only SQLite can store one)', function (): void {
    if (! corrupt(static fn () => legacyKey('http', 'binary', "caf\xE9"))) {
        return;
    }

    expect(freshLookup('http', 'binary')->key?->label)->toBe("caf\xE9");
});
