<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Keys\Hkdf;

/**
 * RFC 5869 Appendix A test cases 1–3 (SHA-256).
 */
it('matches the RFC 5869 SHA-256 test vectors', function (string $ikm, string $salt, string $info, int $length, string $okm): void {
    expect(bin2hex(Hkdf::raw(HashAlgorithm::Sha256, (string) hex2bin($ikm), $length, (string) hex2bin($info), (string) hex2bin($salt))))
        ->toBe($okm);
})->with([
    'A.1 basic' => [
        str_repeat('0b', 22), '000102030405060708090a0b0c', 'f0f1f2f3f4f5f6f7f8f9', 42,
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    ],
    'A.2 long inputs' => [
        implode('', array_map(static fn (int $b): string => sprintf('%02x', $b), range(0x00, 0x4F))),
        implode('', array_map(static fn (int $b): string => sprintf('%02x', $b), range(0x60, 0xAF))),
        implode('', array_map(static fn (int $b): string => sprintf('%02x', $b), range(0xB0, 0xFF))),
        82,
        'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
    ],
    'A.3 empty salt and info' => [
        str_repeat('0b', 22), '', '', 42,
        '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    ],
]);

it('derives SHA-384 and SHA-512 subkeys under the fixed Sentinel salt (independent oracle)', function (HashAlgorithm $hash, int $length): void {
    $root = str_repeat("\x42\x17", 24);
    $info = Hkdf::sealInfo('default', 'kid-1', Algorithm::HmacSha512);

    expect(Hkdf::derive($hash, $root, $length, $info))->toBe(hash_hkdf($hash->value, $root, $length, $info, 'sentinel.hkdf/1'))
        ->and(strlen(Hkdf::derive($hash, $root, $length, $info)))->toBe($length);
})->with([
    [HashAlgorithm::Sha384, 48],
    [HashAlgorithm::Sha512, 64],
]);

it('separates purposes, rings, kids and algorithms in the info strings', function (): void {
    expect(Hkdf::sealInfo('default', 'k1', Algorithm::HmacSha256))->toBe("sentinel/1/seal\0default\0k1\0hmac-sha256")
        ->and(Hkdf::ledgerInfo('default', 'k1', Algorithm::HmacSha256))->toBe("sentinel/1/ledger\0default\0k1\0hmac-sha256")
        ->and(Hkdf::fieldInfo('default', 'k1'))->toBe("sentinel/1/field\0default\0k1");
});

it('refuses empty keying material and impossible lengths', function (string $ikm, int $length): void {
    expect(fn (): string => Hkdf::derive(HashAlgorithm::Sha256, $ikm, $length, 'info'))->toThrow(InvalidKeyMaterialException::class);
})->with([
    'empty ikm' => ['', 32],
    'zero length' => ['secret', 0],
    'beyond 255 blocks' => ['secret', 255 * 32 + 1],
]);
