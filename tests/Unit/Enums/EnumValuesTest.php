<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Signature\Algorithm as CryptoAlgorithm;
use RoundlyConsulting\Enums\Helpers;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\DigestAlgorithm;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\PersistOperation;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
use RoundlyConsulting\Sentinel\Enums\TypeKind;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Tests\Support\SourceScan;

/**
 * Enum values are frozen at 1.0.0: hosts persist them (seal, key and ledger rows) and switch
 * on them. Changing one is a major release.
 */
it('freezes every enum value', function (string $enum, array $values): void {
    expect(array_map(static fn (BackedEnum $case): string => (string) $case->value, $enum::cases()))->toBe($values);
})->with([
    'Algorithm' => [Algorithm::class, ['hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'ed25519', 'ecdsa-p256-sha256', 'ecdsa-p384-sha384']],
    'TypeKind' => [TypeKind::class, ['auto', 'str', 'int', 'dec', 'flt', 'bool', 'dt', 'date', 'json', 'bin', 'null', 'plain']],
    'SealEvent' => [SealEvent::class, ['sealed', 'resealed', 'acknowledged', 'baseline', 'rotated', 'deleted', 'unsealed']],
    'VerificationStatus' => [VerificationStatus::class, ['intact', 'outdated', 'unsealed', 'tampered', 'missing', 'stale', 'unknown_key', 'revoked_key', 'retired_key', 'algorithm_not_allowed', 'algorithm_mismatch', 'malformed', 'unverifiable']],
    'KeyStatus' => [KeyStatus::class, ['pending', 'active', 'verify_only', 'retired', 'revoked']],
    'DigestAlgorithm' => [DigestAlgorithm::class, ['sha-256', 'sha-512']],
    'Purpose' => [Purpose::class, ['seal', 'ledger']],
    'KeyDestination' => [KeyDestination::class, ['config', 'database']],
    'VerificationContext' => [VerificationContext::class, ['api', 'middleware', 'retrieve', 'command', 'rule', 'collection', 'write']],
    'Reaction' => [Reaction::class, ['throw', 'event', 'log']],
    'TamperedWritePolicy' => [TamperedWritePolicy::class, ['refuse', 'reseal', 'skip']],
    'PersistOperation' => [PersistOperation::class, ['save', 'delete', 'increment']],
    'LedgerFindingKind' => [LedgerFindingKind::class, ['checkpoint_gap', 'checkpoint_invalid', 'checkpoint_mismatch', 'chain_broken', 'anchor_ahead', 'anchor_mismatch', 'anchor_invalid', 'anchor_unreachable', 'entry_invalid', 'entity_deleted', 'seal_rolled_back', 'seal_missing', 'backlog']],
]);

it('treats every ledger finding but a backlog and an unreachable anchor as a violation', function (): void {
    $harmless = array_values(array_filter(LedgerFindingKind::cases(), static fn (LedgerFindingKind $kind): bool => ! $kind->isViolation()));

    expect($harmless)->toBe([LedgerFindingKind::AnchorUnreachable, LedgerFindingKind::Backlog]);
});

it('uses the enums Helpers trait on every package enum', function (): void {
    $enums = array_filter(array_keys(SourceScan::classes()), enum_exists(...));

    expect($enums)->not->toBeEmpty();

    foreach ($enums as $enum) {
        expect(class_uses($enum))->toContain(Helpers::class);
    }
});

it('pins each algorithm to its hash, crypto algorithm and RFC 9421 registration', function (Algorithm $algorithm, bool $hmac, HashAlgorithm $hash, int $length, CryptoAlgorithm $crypto, bool $http): void {
    expect($algorithm->isHmac())->toBe($hmac)
        ->and($algorithm->isAsymmetric())->toBe(! $hmac)
        ->and($algorithm->hashAlgorithm())->toBe($hash)
        ->and($algorithm->hashName())->toBe($hash->value)
        ->and($algorithm->hashLength())->toBe($length)
        ->and($algorithm->cryptoAlgorithm())->toBe($crypto)
        ->and($algorithm->isHttpRegistered())->toBe($http);
})->with([
    [Algorithm::HmacSha256, true, HashAlgorithm::Sha256, 32, CryptoAlgorithm::HS256, true],
    [Algorithm::HmacSha384, true, HashAlgorithm::Sha384, 48, CryptoAlgorithm::HS384, false],
    [Algorithm::HmacSha512, true, HashAlgorithm::Sha512, 64, CryptoAlgorithm::HS512, false],
    [Algorithm::Ed25519, false, HashAlgorithm::Sha512, 64, CryptoAlgorithm::EdDSA, true],
    [Algorithm::EcdsaP256Sha256, false, HashAlgorithm::Sha256, 32, CryptoAlgorithm::ES256, true],
    [Algorithm::EcdsaP384Sha384, false, HashAlgorithm::Sha384, 48, CryptoAlgorithm::ES384, true],
]);

it('refuses names that are not algorithms', function (string $name): void {
    expect(Algorithm::tryFrom($name))->toBeNull();
})->with(['none', 'HS256', 'rsa-pss-sha512', 'rsa-v1_5-sha256', 'HMAC-SHA256', '']);

it('lets only active keys sign and active or verify-only keys verify', function (KeyStatus $status, bool $sign, bool $verify): void {
    expect($status->canSign())->toBe($sign)->and($status->canVerify())->toBe($verify);
})->with([
    [KeyStatus::Pending, false, false],
    [KeyStatus::Active, true, true],
    [KeyStatus::VerifyOnly, false, true],
    [KeyStatus::Retired, false, false],
    [KeyStatus::Revoked, false, false],
]);

it('counts intact, unsealed and (configurably) outdated as intact', function (): void {
    expect(VerificationStatus::Intact->isIntact())->toBeTrue()
        ->and(VerificationStatus::Unsealed->isIntact())->toBeTrue()
        ->and(VerificationStatus::Outdated->isIntact())->toBeTrue()
        ->and(VerificationStatus::Outdated->isIntact(false))->toBeFalse()
        ->and(VerificationStatus::Outdated->isFailure(false))->toBeTrue();

    $failures = array_filter(VerificationStatus::cases(), static fn (VerificationStatus $status): bool => $status->isFailure());

    expect(count($failures))->toBe(10);
});

it('marks only deleted and unsealed as tombstones', function (): void {
    $tombstones = array_values(array_filter(SealEvent::cases(), static fn (SealEvent $event): bool => $event->isTombstone()));

    expect($tombstones)->toBe([SealEvent::Deleted, SealEvent::Unsealed]);
});

it('knows which type kinds carry a scale and which can be declared', function (): void {
    expect(TypeKind::Decimal->hasScale())->toBeTrue()
        ->and(TypeKind::Float->hasScale())->toBeTrue()
        ->and(TypeKind::String->hasScale())->toBeFalse()
        ->and(TypeKind::Null->isDeclarable())->toBeFalse()
        ->and(TypeKind::Plaintext->isDeclarable())->toBeTrue();
});

it('maps content digests to their hash', function (): void {
    expect(DigestAlgorithm::Sha256->hashAlgorithm())->toBe(HashAlgorithm::Sha256)
        ->and(DigestAlgorithm::Sha512->hashAlgorithm())->toBe(HashAlgorithm::Sha512);
});
