<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\DataTransferObjects\IssuedMac;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\MacRejection;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\MacVerificationException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

/**
 * `verifyMac()` / `mac()` under `Sentinel::fake()`: recorded and asserted, production's
 * checks kept — the ring, the key's status and algorithm, the MAC's encoding — and only the MAC
 * itself (which needs key material the fake never holds) assumed or scripted.
 */
const FAKE_MAC_SECRET = 'base64:QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=';

function fakeMacRefusal(Closure $verify): ?MacRejection
{
    try {
        $verify();

        return null;
    } catch (MacVerificationException $exception) {
        return $exception->reason();
    }
}

beforeEach(fn () => macRing());

it('records MAC verifications through the facade, the handle and an injected manager', function (): void {
    $fake = Sentinel::fake();
    $vector = macVector();

    Sentinel::verifyMac('logs', 'billing-1', 'a', $vector['mac']);
    Sentinel::keys()->ring('logs')->verifyMac('billing-1', 'b', $vector['mac']);
    app(SentinelManager::class)->verifyMac('logs', 'billing-1', 'c', $vector['mac']);

    expect(app(SentinelManager::class))->toBeInstanceOf(SentinelFake::class)
        ->and($fake->recorded('verifyMac'))->toHaveCount(3)
        ->and($fake->recorded('verifyMac')[1]->arguments)->toBe(['logs', 'billing-1', 'b', $vector['mac']])
        ->and($fake->recorded('verifyMac')[1]->result)->toBeInstanceOf(KeyInfo::class);

    $fake->assertMacVerified();
    $fake->assertMacVerified('logs');
    Sentinel::assertMacVerified('logs', 'billing-1');
    Sentinel::assertMacNotVerified('logs', 'billing-2');
});

it('returns the key the ring holds — the real store\'s, or one imported under the fake', function (): void {
    Sentinel::fake();
    $service = User::query()->create(['name' => 'billing']);
    Sentinel::keys()->ring('logs')->import('billing-2', Algorithm::HmacSha256, FAKE_MAC_SECRET, owner: $service, label: 'billing');
    $mac = macVector()['mac'];

    $real = Sentinel::keys()->ring('logs')->verifyMac('billing-1', 'anything', $mac);
    $imported = Sentinel::keys()->ring('logs')->verifyMac('billing-2', 'anything', $mac);

    expect($real->driver)->toBe('config')
        ->and($real->status)->toBe(KeyStatus::Active)
        ->and($imported->label)->toBe('billing')
        ->and($imported->ownerType)->toBe($service->getMorphClass())
        ->and((string) $imported->ownerId)->toBe((string) $service->getKey())
        ->and($imported->status)->toBe(KeyStatus::VerifyOnly)
        ->and(Key::query()->count())->toBe(0);
});

it('keeps production\'s checks of the ring, the key and the encoding', function (Closure $arrange, Closure $verify, string|MacRejection $expected): void {
    Sentinel::fake();
    $arrange();

    is_string($expected)
        ? expect($verify)->toThrow($expected)
        : expect(fakeMacRefusal($verify))->toBe($expected);
})->with([
    'an unconfigured ring' => [static function (): void {}, fn () => Sentinel::verifyMac('nope', 'k', 'm', 'AAAA'), SealingMisconfiguredException::class],
    'a sealing ring' => [static function (): void {}, fn () => Sentinel::verifyMac('default', 'k', 'm', 'AAAA'), SealingMisconfiguredException::class],
    'an unknown kid' => [static function (): void {}, fn () => Sentinel::verifyMac('logs', 'nobody', 'm', macVector()['mac']), MacRejection::UnknownKey],
    'a kid that is no kid' => [static function (): void {}, fn () => Sentinel::verifyMac('logs', "bad\n", 'm', macVector()['mac']), MacRejection::UnknownKey],
    'a key revoked under the fake' => [function (): void {
        Sentinel::keys()->ring('logs')->import('leaked', Algorithm::HmacSha256, FAKE_MAC_SECRET);
        Sentinel::keys()->ring('logs')->revoke('leaked', 'secret leaked');
    }, fn () => Sentinel::verifyMac('logs', 'leaked', 'm', macVector()['mac']), MacRejection::RevokedKey],
    'a key revoked through the revocation list' => [
        fn () => config()->set('sentinel.keys.revoked', 'logs:billing-1'),
        fn () => Sentinel::verifyMac('logs', 'billing-1', 'm', macVector()['mac']),
        MacRejection::RevokedKey,
    ],
    'a key that is no HMAC key' => [
        fn () => Sentinel::keys()->ring('logs')->import('signer', Algorithm::Ed25519, (string) KeyMaterial::generate(Algorithm::Ed25519)->encodedPublic()),
        fn () => Sentinel::verifyMac('logs', 'signer', 'm', macVector()['mac']),
        MacRejection::UnsupportedAlgorithm,
    ],
    'a padded MAC' => [static function (): void {}, fn () => Sentinel::verifyMac('logs', 'billing-1', 'm', macVector()['mac'].'='), MacRejection::Malformed],
    'a MAC of the wrong length' => [static function (): void {}, fn () => Sentinel::verifyMac('logs', 'billing-1', 'm', macVector()['malformed'][7]['mac']), MacRejection::Malformed],
]);

it('records a refused verification without counting it as verified', function (): void {
    $fake = Sentinel::fake();

    fakeMacRefusal(fn () => Sentinel::verifyMac('logs', 'nobody', 'm', macVector()['mac']));

    expect($fake->recorded('verifyMac'))->toHaveCount(1)
        ->and($fake->recorded('verifyMac')[0]->result)->toBe(MacRejection::UnknownKey);

    $fake->assertMacNotVerified();
    fails(fn () => $fake->assertMacVerified(), 'Expected a MAC to be verified, but none was.');
});

it('scripts a refusal with rejectMacs()', function (): void {
    $fake = Sentinel::fake()->rejectMacs(MacRejection::Mismatch);

    expect(fakeMacRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('billing-1', 'm', macVector()['mac'])))->toBe(MacRejection::Mismatch)
        // The ring is still checked first, as in production.
        ->and(fn () => Sentinel::verifyMac('http', 'k', 'm', 'AAAA'))->toThrow(SealingMisconfiguredException::class);

    $fake->assertMacNotVerified('logs');
});

it('scripts the verified key with fakeVerifiedMac(), which also lifts a scripted refusal', function (): void {
    $fake = Sentinel::fake()->rejectMacs(MacRejection::Mismatch);
    $service = new KeyInfo('logs', 'svc-9', Algorithm::HmacSha256, KeyStatus::VerifyOnly, 'database', false, label: 'billing');

    $fake->fakeVerifiedMac($service);
    $scripted = Sentinel::verifyMac('logs', 'whatever', 'm', 'not even base64url!');
    $fake->fakeVerifiedMac();
    $synthetic = Sentinel::verifyMac('logs', 'unknown-kid', 'm', 'AAAA');

    expect($scripted)->toBe($service)
        ->and([$synthetic->ring, $synthetic->keyId, $synthetic->algorithm, $synthetic->status, $synthetic->driver, $synthetic->canSign])
        ->toBe(['logs', 'unknown-kid', Algorithm::HmacSha256, KeyStatus::Active, 'fake', false])
        ->and(fn () => Sentinel::verifyMac('default', 'k', 'm', 'AAAA'))->toThrow(SealingMisconfiguredException::class);

    $fake->assertMacVerified('logs', 'whatever');
    $fake->assertMacVerified('logs', 'unknown-kid');
});

it('passes and fails assertMacVerified and assertMacNotVerified', function (): void {
    $fake = Sentinel::fake();
    $fake->assertMacNotVerified();
    fails(fn () => $fake->assertMacVerified('logs'), 'Expected a MAC to be verified in ring [logs], but none was.');

    Sentinel::verifyMac('logs', 'billing-1', 'm', macVector()['mac']);

    fails(fn () => $fake->assertMacVerified('logs', 'billing-2'), 'Expected a MAC to be verified with key [billing-2] in ring [logs], but none was.');
    fails(fn () => $fake->assertMacVerified(keyId: 'billing-2'), 'Expected a MAC to be verified with key [billing-2], but none was.');
    fails(fn () => $fake->assertMacNotVerified(), 'Expected no MAC to be verified, but 1 was.');
    fails(fn () => $fake->assertMacNotVerified('logs'), 'Expected no MAC to be verified in ring [logs], but 1 was.');
    fails(fn () => $fake->assertMacNotVerified('logs', 'billing-1'), 'Expected no MAC to be verified with key [billing-1] in ring [logs], but 1 was.');
    $fake->assertMacNotVerified('logs', 'billing-2');
});

it('records mac() and returns a well-formed placeholder from the ring\'s current key', function (): void {
    $fake = Sentinel::fake();
    $fake->assertNoMacsComputed();
    fails(fn () => $fake->assertMacComputed(), 'Expected a MAC to be computed, but none was.');

    $issued = Sentinel::keys()->ring('logs')->mac(macVector()['message']);
    $again = app(SentinelManager::class)->mac('logs', macVector()['message']);

    expect($issued)->toBeInstanceOf(IssuedMac::class)
        ->and([$issued->ring, $issued->keyId, $issued->algorithm])->toBe(['logs', 'billing-1', Algorithm::HmacSha256])
        ->and($issued->mac)->toMatch('/^[A-Za-z0-9_-]{43}$/')
        // A placeholder — the fake holds no key material — but a stable one, never the real MAC.
        ->and($issued->mac)->not->toBe(macVector()['mac'])
        ->and($again->mac)->toBe($issued->mac)
        ->and(Sentinel::mac('logs', 'other')->mac)->not->toBe($issued->mac)
        ->and($fake->recorded('mac')[0]->arguments)->toBe(['logs', macVector()['message']]);

    $fake->assertMacComputed();
    Sentinel::assertMacComputed('logs');
    fails(fn () => $fake->assertMacComputed('http'), 'Expected a MAC to be computed in ring [http], but none was.');
    fails(fn () => $fake->assertNoMacsComputed(), 'Expected no MAC to be computed, but 3 were.');
});

it('MACs under the fake with a key generated under the fake', function (): void {
    Sentinel::fake();
    macRing(['driver' => 'database', 'key_id' => null, 'key' => null, 'algorithms' => ['hmac-sha384']]);

    Sentinel::keys()->ring('logs')->generate(Algorithm::HmacSha384, 'wide-1');
    $issued = Sentinel::keys()->ring('logs')->mac('m');

    expect([$issued->keyId, $issued->algorithm])->toBe(['wide-1', Algorithm::HmacSha384])
        ->and($issued->mac)->toMatch('/^[A-Za-z0-9_-]{64}$/');
});

it('keeps production\'s checks on mac() under the fake', function (Closure $arrange, Closure $call, string $exception): void {
    Sentinel::fake();
    $arrange();

    expect($call)->toThrow($exception);
})->with([
    'a sealing ring' => [static function (): void {}, fn () => Sentinel::mac('default', 'm'), SealingMisconfiguredException::class],
    'no signing key' => [fn () => macRing(['key_id' => null, 'key' => null]), fn () => Sentinel::mac('logs', 'm'), NoSigningKeyException::class],
    'an Ed25519 signing key' => [fn () => macRing(['key_id' => 'ed-1', 'algorithm' => 'ed25519', 'key' => KeyMaterial::generate(Algorithm::Ed25519)->encodedPrivate()]), fn () => Sentinel::mac('logs', 'm'), AlgorithmNotAllowedException::class],
    'an algorithm the ring no longer allows' => [
        fn () => config()->set('sentinel.keys.rings.logs.algorithms', ['hmac-sha384']),
        fn () => Sentinel::mac('logs', 'm'),
        AlgorithmNotAllowedException::class,
    ],
]);
