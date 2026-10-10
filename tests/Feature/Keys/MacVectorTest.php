<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Enums\MacRejection;
use RoundlyConsulting\Sentinel\Exceptions\MacVerificationException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;

/**
 * The cross-language MAC vector (tests/Fixtures/mac-vector.json): a fixed secret, exact message
 * bytes (non-ASCII included) and the MAC every peer must produce. Other implementations reuse
 * these values as they are, so the fixture is proven here independently of Sentinel — with
 * plain hash_hmac, and with node:crypto when Node is installed — not merely self-consistent.
 */
it('ships the vector as 4-space JSON with a trailing newline', function (): void {
    $raw = (string) file_get_contents(__DIR__.'/../../Fixtures/mac-vector.json');

    expect($raw)->toBe(json_encode(macVector(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n")
        ->and(macVector())->toHaveKeys(['algorithm', 'ring', 'key_id', 'secret_hex', 'secret_config', 'message', 'message_hex', 'mac', 'mac_hex', 'malformed']);
});

it('proves the vector with plain hash_hmac over the raw secret', function (): void {
    $vector = macVector();
    $secret = (string) hex2bin($vector['secret_hex']);
    $message = (string) hex2bin($vector['message_hex']);
    $raw = hash_hmac('sha256', $message, $secret, true);

    expect($vector['algorithm'])->toBe('hmac-sha256')
        ->and(strlen($secret))->toBe(32)
        ->and($vector['secret_config'])->toBe('base64:'.base64_encode($secret))
        ->and($vector['message'])->toBe($message)
        ->and(preg_match('/[^\x00-\x7F]/', $message))->toBe(1)
        ->and(mb_check_encoding($message, 'UTF-8'))->toBeTrue()
        ->and(bin2hex($raw))->toBe($vector['mac_hex'])
        ->and(rtrim(strtr(base64_encode($raw), '+/', '-_'), '='))->toBe($vector['mac'])
        // The MAC uses both URL-safe characters, so a standard-base64 peer cannot pass it.
        ->and($vector['mac'])->toContain('-')->toContain('_')->toHaveLength(43);
});

it('proves the vector with node:crypto', function (): void {
    $vector = macVector();
    $script = 'const c=require("node:crypto");process.stdout.write(c.createHmac("sha256",Buffer.from(process.argv[1],"hex")).update(Buffer.from(process.argv[2],"hex")).digest("base64url"))';
    $command = 'node -e '.escapeshellarg($script).' '.escapeshellarg($vector['secret_hex']).' '.escapeshellarg($vector['message_hex']).' 2>/dev/null';

    expect(trim((string) shell_exec($command)))->toBe($vector['mac']);
})->skip(fn (): bool => trim((string) shell_exec('command -v node 2>/dev/null')) === '', 'Node is not installed');

it('verifies and reproduces the vector through the public API', function (): void {
    $vector = macVector();
    macRing();

    $info = Sentinel::keys()->ring($vector['ring'])->verifyMac($vector['key_id'], $vector['message'], $vector['mac']);
    $issued = Sentinel::keys()->ring($vector['ring'])->mac($vector['message']);

    expect($info->keyId)->toBe($vector['key_id'])
        ->and($info->algorithm->value)->toBe($vector['algorithm'])
        ->and($issued->keyId)->toBe($vector['key_id'])
        ->and($issued->mac)->toBe($vector['mac']);
});

it('refuses every malformed entry of the vector as malformed_mac', function (): void {
    $vector = macVector();
    macRing();
    $reasons = [];

    foreach ($vector['malformed'] as $case) {
        try {
            Sentinel::keys()->ring($vector['ring'])->verifyMac($vector['key_id'], $vector['message'], $case['mac']);
            $reasons[$case['why']] = 'accepted';
        } catch (MacVerificationException $exception) {
            $reasons[$case['why']] = $exception->reason()->value;
        }
    }

    expect($reasons)->toHaveCount(11)
        ->and(array_unique(array_values($reasons)))->toBe([MacRejection::Malformed->value])
        ->and(MacRejection::Malformed->value)->toBe('malformed_mac');
});
