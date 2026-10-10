<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Hash\Hmac;
use RoundlyConsulting\Sentinel\Actions\Keys\ComputeMacAction;
use RoundlyConsulting\Sentinel\Actions\Keys\VerifyMacAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssuedMac;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\MacRejection;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\MacVerificationException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;
use RoundlyConsulting\Sentinel\Tests\Support\SourceScan;

/**
 * Raw-secret MACs over arbitrary bytes on a key ring (`verifyMac()` / `mac()`): a peer holding
 * the shared secret — PHP or not — computes `base64url(HMAC(secret, message))` and Sentinel
 * verifies it with the key the kid names in that ring, and nowhere else.
 */
const MAC_SERVICE_SECRET = 'base64:QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=';

function macRefusal(Closure $verify): ?MacRejection
{
    try {
        $verify();

        return null;
    } catch (MacVerificationException $exception) {
        return $exception->reason();
    }
}

beforeEach(fn () => macRing());

it('verifies a MAC and returns the key — its identity, never its material', function (): void {
    $vector = macVector();

    $info = Sentinel::keys()->ring('logs')->verifyMac($vector['key_id'], $vector['message'], $vector['mac']);

    expect($info)->toBeInstanceOf(KeyInfo::class)
        ->and($info->ring)->toBe('logs')
        ->and($info->keyId)->toBe('billing-1')
        ->and($info->algorithm)->toBe(Algorithm::HmacSha256)
        ->and($info->status)->toBe(KeyStatus::Active)
        ->and($info->driver)->toBe('config')
        ->and(array_map(static fn (ReflectionProperty $property): string => $property->getName(), (new ReflectionClass(KeyInfo::class))->getProperties()))
        ->toBe(['ring', 'keyId', 'algorithm', 'status', 'driver', 'canSign', 'activatesAt', 'signsUntil', 'verifiesUntil', 'revokedAt', 'label', 'ownerType', 'ownerId'])
        ->and(print_r($info, true).serialize($info))->not->toContain(substr($vector['secret_config'], 7))->not->toContain($vector['secret_hex']);
});

it('returns the owner and label an imported per-service key is bound to', function (): void {
    $service = User::query()->create(['name' => 'billing']);
    Sentinel::keys()->ring('logs')->import('billing-2', Algorithm::HmacSha256, MAC_SERVICE_SECRET, owner: $service, label: 'billing');
    $message = '{"service":"billing","seq":3}';

    $info = Sentinel::keys()->ring('logs')->verifyMac('billing-2', $message, peerMac(MAC_SERVICE_SECRET, $message));

    expect($info->keyId)->toBe('billing-2')
        ->and($info->label)->toBe('billing')
        ->and($info->ownerType)->toBe($service->getMorphClass())
        ->and((string) $info->ownerId)->toBe((string) $service->getKey())
        ->and($info->status)->toBe(KeyStatus::VerifyOnly)
        ->and($info->canSign)->toBeFalse()
        ->and($info->driver)->toBe('database');
});

it('accepts a verify-only key — a rotated-out config key included', function (): void {
    $vector = macVector();
    macRing(['key_id' => 'billing-3', 'key' => MAC_SERVICE_SECRET, 'previous' => "billing-1|hmac-sha256|{$vector['secret_config']}"]);

    expect(Sentinel::keys()->ring('logs')->verifyMac('billing-1', $vector['message'], $vector['mac'])->status)->toBe(KeyStatus::VerifyOnly);
});

it('runs one API through the facade, the handle, an injected manager and the raw actions', function (): void {
    $vector = macVector();
    $verify = [
        Sentinel::verifyMac('logs', $vector['key_id'], $vector['message'], $vector['mac']),
        Sentinel::keys()->ring('logs')->verifyMac($vector['key_id'], $vector['message'], $vector['mac']),
        app(SentinelManager::class)->verifyMac('logs', $vector['key_id'], $vector['message'], $vector['mac']),
        app(VerifyMacAction::class)->execute('logs', $vector['key_id'], $vector['message'], $vector['mac']),
    ];
    $sign = [
        Sentinel::mac('logs', $vector['message']),
        Sentinel::keys()->ring('logs')->mac($vector['message']),
        app(SentinelManager::class)->mac('logs', $vector['message']),
        app(ComputeMacAction::class)->execute('logs', $vector['message']),
    ];

    expect(array_map(static fn (KeyInfo $info): string => $info->keyId, $verify))->toBe(array_fill(0, 4, 'billing-1'))
        ->and(array_map(static fn (IssuedMac $mac): string => $mac->mac, $sign))->toBe(array_fill(0, 4, $vector['mac']));
});

it('resolves the MAC actions through the container so a host override applies', function (string $action, Closure $call): void {
    app()->bind($action, static fn (): never => throw new RuntimeException('overridden'));

    expect($call)->toThrow(RuntimeException::class, 'overridden');
})->with([
    'verify' => [VerifyMacAction::class, fn () => Sentinel::keys()->ring('logs')->verifyMac('billing-1', 'm', 'AAAA')],
    'mac' => [ComputeMacAction::class, fn () => Sentinel::keys()->ring('logs')->mac('m')],
]);

it('computes a MAC with the ring\'s current signing key that a peer reproduces', function (): void {
    $vector = macVector();

    $issued = Sentinel::keys()->ring('logs')->mac($vector['message']);

    expect($issued)->toBeInstanceOf(IssuedMac::class)
        ->and($issued->ring)->toBe('logs')
        ->and($issued->keyId)->toBe('billing-1')
        ->and($issued->algorithm)->toBe(Algorithm::HmacSha256)
        ->and($issued->mac)->toBe($vector['mac'])
        ->and($issued->mac)->toBe(peerMac($vector['secret_config'], $vector['message']))
        ->and(print_r($issued, true))->not->toContain(substr($vector['secret_config'], 7));
});

it('MACs and verifies with hmac-sha384 when the ring allows it', function (): void {
    $secret = 'base64:'.base64_encode(implode('', array_map(chr(...), range(100, 147))));
    macRing(['key_id' => 'wide-1', 'algorithm' => 'hmac-sha384', 'key' => $secret]);

    $issued = Sentinel::keys()->ring('logs')->mac('payload');

    expect($issued->algorithm)->toBe(Algorithm::HmacSha384)
        ->and($issued->mac)->toHaveLength(64)
        ->and($issued->mac)->toBe(peerMac($secret, 'payload', 'sha384'))
        ->and(Sentinel::keys()->ring('logs')->verifyMac('wide-1', 'payload', $issued->mac)->algorithm)->toBe(Algorithm::HmacSha384)
        // A SHA-256-length MAC for a SHA-384 key is the wrong length — malformed, never compared short.
        ->and(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('wide-1', 'payload', peerMac($secret, 'payload'))))->toBe(MacRejection::Malformed);
});

it('uses the raw shared secret — no HKDF subkey, so seals and MACs never share a key', function (): void {
    $vector = macVector();
    $key = app(KeyStoreManager::class)->signingKey('logs');
    $signers = new Signers;

    expect(rtrim(strtr(base64_encode($signers->sign($key, Purpose::Mac, $vector['message'])), '+/', '-_'), '='))->toBe($vector['mac'])
        ->and($signers->sign($key, Purpose::Mac, 'x'))->toBe($signers->sign($key, Purpose::Http, 'x'))
        ->and($signers->sign($key, Purpose::Mac, 'x'))->not->toBe($signers->sign($key, Purpose::Seal, 'x'));
});

// ── refusals ──────────────────────────────────────────────────────────────────

it('refuses each MAC it cannot vouch for, with a typed reason', function (Closure $arrange, MacRejection $reason): void {
    [$keyId, $message, $mac] = $arrange();

    try {
        Sentinel::keys()->ring('logs')->verifyMac($keyId, $message, $mac);
        test()->fail('expected MacVerificationException');
    } catch (MacVerificationException $exception) {
        expect($exception->reason())->toBe($reason)
            ->and($exception->ring())->toBe('logs')
            ->and($exception->keyId())->toBe($keyId)
            ->and($exception->getMessage())->not->toContain(substr(macVector()['secret_config'], 7))->not->toContain(substr(MAC_SERVICE_SECRET, 7));

        if ($mac !== '') {
            expect($exception->getMessage())->not->toContain($mac);
        }
    }
})->with([
    'an unknown kid' => [fn () => ['nobody', 'm', peerMac(MAC_SERVICE_SECRET, 'm')], MacRejection::UnknownKey],
    'a kid that is no kid' => [fn () => ["bad kid\n", 'm', peerMac(MAC_SERVICE_SECRET, 'm')], MacRejection::UnknownKey],
    'a pending key' => [function (): array {
        Sentinel::keys()->ring('logs')->import('later', Algorithm::HmacSha256, MAC_SERVICE_SECRET, activatesAt: Clock::now()->addDay());

        return ['later', 'm', peerMac(MAC_SERVICE_SECRET, 'm')];
    }, MacRejection::PendingKey],
    'a retired key' => [function (): array {
        Sentinel::keys()->ring('logs')->import('old', Algorithm::HmacSha256, MAC_SERVICE_SECRET);
        Sentinel::keys()->ring('logs')->retire('old');

        return ['old', 'm', peerMac(MAC_SERVICE_SECRET, 'm')];
    }, MacRejection::RetiredKey],
    'a revoked key' => [function (): array {
        Sentinel::keys()->ring('logs')->import('leaked', Algorithm::HmacSha256, MAC_SERVICE_SECRET);
        Sentinel::keys()->ring('logs')->revoke('leaked', 'secret leaked');

        return ['leaked', 'm', peerMac(MAC_SERVICE_SECRET, 'm')];
    }, MacRejection::RevokedKey],
    'a key that is no HMAC key' => [function (): array {
        Sentinel::keys()->ring('logs')->import('signer', Algorithm::Ed25519, (string) KeyMaterial::generate(Algorithm::Ed25519)->encodedPublic());

        return ['signer', 'm', rtrim(strtr(base64_encode(str_repeat("\1", 32)), '+/', '-_'), '=')];
    }, MacRejection::UnsupportedAlgorithm],
    'an algorithm the ring no longer allows' => [function (): array {
        $secret = 'base64:'.base64_encode(implode('', array_map(chr(...), range(100, 147))));
        Sentinel::keys()->ring('logs')->import('wide', Algorithm::HmacSha384, $secret);
        config()->set('sentinel.keys.rings.logs.algorithms', ['hmac-sha256']);

        return ['wide', 'm', peerMac($secret, 'm', 'sha384')];
    }, MacRejection::AlgorithmNotAllowed],
    'a MAC of another message' => [fn () => ['billing-1', macVector()['message'], peerMac(macVector()['secret_config'], 'another message')], MacRejection::Mismatch],
    'a MAC with one bit flipped' => [function (): array {
        $raw = (string) base64_decode(strtr(macVector()['mac'], '-_', '+/').'=', true);
        $raw[0] = chr(ord($raw[0]) ^ 1);

        return ['billing-1', macVector()['message'], rtrim(strtr(base64_encode($raw), '+/', '-_'), '=')];
    }, MacRejection::Mismatch],
    'a MAC under another secret' => [fn () => ['billing-1', macVector()['message'], peerMac(MAC_SERVICE_SECRET, macVector()['message'])], MacRejection::Mismatch],
    'the message with one more byte' => [fn () => ['billing-1', macVector()['message'].' ', macVector()['mac']], MacRejection::Mismatch],
]);

it('refuses every malformed MAC encoding of the vector', function (string $why, string $mac): void {
    $vector = macVector();

    expect(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac($vector['key_id'], $vector['message'], $mac)))->toBe(MacRejection::Malformed);
})->with(array_map(static fn (array $case): array => [$case['why'], $case['mac']], macVector()['malformed']));

it('refuses non-ASCII and stray characters in the MAC', function (string $mac): void {
    expect(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('billing-1', 'm', $mac)))->toBe(MacRejection::Malformed);
})->with([
    'non-ASCII' => [substr(macVector()['mac'], 0, -2).'é'],
    'a tab' => ["\t".macVector()['mac']],
    'a NUL byte' => [macVector()['mac']."\0"],
    'a dot' => [substr(macVector()['mac'], 0, -1).'.'],
]);

it('resolves a kid only inside its own ring', function (): void {
    // The partner ring holds `partner` with the same secret; the logs ring does not know it.
    partnerRing(material: MAC_SERVICE_SECRET);
    macRing();
    $message = '{"service":"billing"}';

    expect(Sentinel::keys()->ring('partner')->current()->keyId)->toBe('partner')
        ->and(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('partner', $message, peerMac(MAC_SERVICE_SECRET, $message))))->toBe(MacRejection::UnknownKey);
});

it('refuses a key revoked through SENTINEL_REVOKED_KEYS', function (): void {
    $vector = macVector();
    $previous = getenv('SENTINEL_REVOKED_KEYS');
    putenv('SENTINEL_REVOKED_KEYS=logs:billing-1');

    try {
        $shipped = (require __DIR__.'/../../../config/sentinel.php')['keys']['revoked'];
    } finally {
        putenv($previous === false ? 'SENTINEL_REVOKED_KEYS' : "SENTINEL_REVOKED_KEYS={$previous}");
    }

    config()->set('sentinel.keys.revoked', $shipped);

    expect($shipped)->toBe('logs:billing-1')
        ->and(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('billing-1', $vector['message'], $vector['mac'])))->toBe(MacRejection::RevokedKey)
        ->and(fn () => Sentinel::keys()->ring('logs')->mac($vector['message']))->toThrow(NoSigningKeyException::class);
});

it('names what to fix without echoing the MAC, the secret or an attacker-shaped kid', function (): void {
    expect(MacVerificationException::rejected(MacRejection::UnknownKey, 'logs', 'nobody')->getMessage())->toBe('Key ring [logs] has no key [nobody] to verify a MAC with.')
        ->and(MacVerificationException::rejected(MacRejection::UnknownKey, 'logs', "<x>\n")->getMessage())->toBe('Key ring [logs] has no key [(invalid)] to verify a MAC with.')
        ->and(MacVerificationException::rejected(MacRejection::PendingKey, 'logs', 'k')->getMessage())->toBe('Key [k] of ring [logs] is pending and verifies no MAC.')
        ->and(MacVerificationException::rejected(MacRejection::RetiredKey, 'logs', 'k')->getMessage())->toBe('Key [k] of ring [logs] is retired and verifies no MAC.')
        ->and(MacVerificationException::rejected(MacRejection::RevokedKey, 'logs', 'k')->getMessage())->toBe('Key [k] of ring [logs] is revoked and verifies no MAC.')
        ->and(MacVerificationException::rejected(MacRejection::UnsupportedAlgorithm, 'logs', 'k')->getMessage())->toBe('Key [k] of ring [logs] is not an HMAC key; a MAC needs an hmac-* key.')
        ->and(MacVerificationException::rejected(MacRejection::AlgorithmNotAllowed, 'logs', 'k')->getMessage())->toBe('The algorithm of key [k] is not allowed in key ring [logs].')
        ->and(MacVerificationException::rejected(MacRejection::Malformed, 'logs', 'k')->getMessage())->toBe('The MAC for key [k] of ring [logs] is malformed: send the HMAC as unpadded base64url (RFC 4648 §5) of the full hash length.')
        ->and(MacVerificationException::rejected(MacRejection::Mismatch, 'logs', 'k')->getMessage())->toBe('The MAC does not match the message for key [k] of ring [logs].')
        ->and(MacVerificationException::rejected(MacRejection::Mismatch, 'logs', 'k'))->toBeInstanceOf(SentinelException::class);
});

// ── rings ─────────────────────────────────────────────────────────────────────

it('refuses rings whose keys seals, the ledger or HTTP signatures use', function (Closure $arrange, string $ring): void {
    $arrange();

    expect(fn () => Sentinel::keys()->ring($ring)->verifyMac('k', 'm', 'AAAA'))->toThrow(SealingMisconfiguredException::class, "Key ring [{$ring}] cannot")
        ->and(fn () => Sentinel::keys()->ring($ring)->mac('m'))->toThrow(SealingMisconfiguredException::class, "Key ring [{$ring}] cannot")
        ->and(fn () => Sentinel::verifyMac($ring, 'k', 'm', 'AAAA'))->toThrow(SealingMisconfiguredException::class);
})->with([
    'the default ring (seals)' => [static function (): void {}, 'default'],
    'the ledger ring' => [static function (): void {
        archiveRing();
        config()->set('sentinel.ledger.ring', 'archive');
    }, 'archive'],
    'the outbound signature ring' => [static function (): void {}, 'http'],
    'a signature profile ring' => [static function (): void {
        archiveRing();
        config()->set('sentinel.signatures.profiles.partners', [...(array) config('sentinel.signatures.profiles.default'), 'ring' => 'archive']);
    }, 'archive'],
]);

it('refuses a ring that is not configured', function (): void {
    expect(fn () => Sentinel::verifyMac('nope', 'k', 'm', 'AAAA'))->toThrow(SealingMisconfiguredException::class, 'Key ring [nope] is not configured')
        ->and(fn () => Sentinel::mac('nope', 'm'))->toThrow(SealingMisconfiguredException::class, 'Key ring [nope] is not configured');
});

it('refuses to MAC without an HMAC signing key the ring allows', function (Closure $arrange, string $exception, string $message): void {
    $arrange();

    expect(fn () => Sentinel::keys()->ring('logs')->mac('m'))->toThrow($exception, $message);
})->with([
    'no signing key' => [fn () => macRing(['key_id' => null, 'key' => null]), NoSigningKeyException::class, 'Key ring [logs] has no active signing key'],
    'an Ed25519 signing key' => [fn () => macRing([
        'key_id' => 'ed-1', 'algorithm' => 'ed25519', 'key' => KeyMaterial::generate(Algorithm::Ed25519)->encodedPrivate(),
    ]), AlgorithmNotAllowedException::class, 'The signing key [ed-1] of key ring [logs] is an [ed25519] key; a MAC needs an hmac-* key.'],
    'an algorithm the ring no longer allows' => [function (): void {
        macRing(['algorithms' => ['hmac-sha256', 'hmac-sha384']]);
        app(KeyStoreManager::class)->signingKey('logs');
        config()->set('sentinel.keys.rings.logs.algorithms', ['hmac-sha384']);
    }, AlgorithmNotAllowedException::class, 'The algorithm [hmac-sha256] is not allowed in key ring [logs].'],
]);

// ── timing ────────────────────────────────────────────────────────────────────

it('checks the MAC\'s length only after the full HMAC and its constant-time compare', function (): void {
    $vector = macVector();
    $short = $vector['malformed'][7]['mac'];   // 31 bytes: a prefix of the right MAC
    $long = $vector['malformed'][8]['mac'];    // 33 bytes: the right MAC plus one byte
    Sentinel::keys()->ring('logs')->import('leaked', Algorithm::HmacSha256, MAC_SERVICE_SECRET);
    Sentinel::keys()->ring('logs')->revoke('leaked', 'secret leaked');

    // A wrong length never short-circuits ahead of the key: what is wrong with the key is
    // reported first, exactly as for a MAC of the right length.
    expect(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('nobody', $vector['message'], $short)))->toBe(MacRejection::UnknownKey)
        ->and(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('leaked', $vector['message'], $long)))->toBe(MacRejection::RevokedKey)
        ->and(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('nobody', $vector['message'], $vector['mac'].'=')))->toBe(MacRejection::UnknownKey)
        // …and neither a prefix nor an extension of the right MAC is accepted.
        ->and(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('billing-1', $vector['message'], $short)))->toBe(MacRejection::Malformed)
        ->and(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('billing-1', $vector['message'], $long)))->toBe(MacRejection::Malformed);
});

it('compares through Signers → crypto Hmac::verify → ConstantTime::equals, before any length check', function (): void {
    $action = (string) (new ReflectionClass(VerifyMacAction::class))->getFileName();
    $hmac = (string) (new ReflectionClass(Hmac::class))->getFileName();
    $tokens = array_values(array_filter(
        PhpToken::tokenize((string) file_get_contents($action)),
        static fn (PhpToken $token): bool => ! $token->isIgnorable(),
    ));
    $at = static function (string $text) use ($tokens): int {
        foreach ($tokens as $index => $token) {
            if ($token->text === $text) {
                return $index;
            }
        }

        return -1;
    };

    // The one compare: Signers::verify, whose HMAC branch is crypto's Hmac::verify, which
    // compares with ConstantTime::equals (hash_equals over the full computed MAC).
    expect(SourceScan::staticCalls($hmac, ['ConstantTime'], 'equals'))->toBe(1)
        ->and((new ReflectionMethod(Hmac::class, 'verify'))->getNumberOfParameters())->toBe(3)
        ->and(class_exists(ConstantTime::class))->toBeTrue()
        ->and(SourceScan::functionCalls($action, 'hash_equals'))->toBe(0)
        ->and(SourceScan::imports($action))->toContain(Signers::class)
        // The length is looked at only after the compare has run.
        ->and($at('verify'))->toBeGreaterThan(0)
        ->and($at('strlen'))->toBeGreaterThan($at('verify'))
        ->and($at('hashLength'))->toBeGreaterThan($at('verify'));
});

it('refuses a key until it activates, then accepts its MACs', function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-10-10 12:00:00', 'UTC'));

    try {
        Sentinel::keys()->ring('logs')->import('fresh', Algorithm::HmacSha256, MAC_SERVICE_SECRET, activatesAt: Clock::now()->addMinute());
        $mac = peerMac(MAC_SERVICE_SECRET, 'm');

        expect(macRefusal(fn () => Sentinel::keys()->ring('logs')->verifyMac('fresh', 'm', $mac)))->toBe(MacRejection::PendingKey);

        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-10-10 12:01:00', 'UTC'));
        app(KeyStoreManager::class)->flush();

        expect(Sentinel::keys()->ring('logs')->verifyMac('fresh', 'm', $mac)->status)->toBe(KeyStatus::VerifyOnly);
    } finally {
        CarbonImmutable::setTestNow();
    }
});
