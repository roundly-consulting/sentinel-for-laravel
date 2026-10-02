<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Signature\Ec\Der;
use RoundlyConsulting\Sentinel\Canonical\AnchorMessage;
use RoundlyConsulting\Sentinel\Canonical\CheckpointMessage;
use RoundlyConsulting\Sentinel\Canonical\FieldTagger;
use RoundlyConsulting\Sentinel\Canonical\FieldValue;
use RoundlyConsulting\Sentinel\Canonical\LedgerMessage;
use RoundlyConsulting\Sentinel\Canonical\SealMessage;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\MaterialCodec;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;

/**
 * The frozen known-answer vectors of format v1 (plan §12.3). Generated ONCE on 2026-10-02,
 * cross-checked against raw-PHP oracles, then frozen: a failure here means the canonical
 * format drifted — that is format `/2`, never an edit of the fixture.
 *
 * @return array<string, mixed>
 */
function formatVectors(): array
{
    static $vectors = null;

    return $vectors ??= json_decode((string) file_get_contents(__DIR__.'/../Fixtures/vectors/format-v1.json'), true, 64, JSON_THROW_ON_ERROR);
}

function vectorKey(string $algorithm): SealingKey
{
    $definition = formatVectors()['keys'][$algorithm];

    return new SealingKey('default', $definition['kid'], KeyMaterial::fromEncoded(
        Algorithm::from($algorithm),
        $definition['material'] ?? null,
        $definition['public'] ?? null,
    ));
}

/**
 * The independent oracle: raw hash_hkdf + hash_hmac, libsodium, OpenSSL — never Sentinel.
 */
function oracleVerifies(string $algorithm, string $purpose, string $bytes, string $mac): bool
{
    $key = formatVectors()['keys'][$algorithm];
    $signature = Base64Url::decode($mac);

    if (str_starts_with($algorithm, 'hmac-')) {
        $hash = substr($algorithm, 5);
        $length = strlen(hash($hash, '', true));
        $subkey = hash_hkdf($hash, MaterialCodec::decode($key['material']), $length, "sentinel/1/{$purpose}\0default\0{$key['kid']}\0{$algorithm}", 'sentinel.hkdf/1');

        return hash_equals(hash_hmac($hash, $bytes, $subkey, true), $signature);
    }

    if ($algorithm === 'ed25519') {
        return sodium_crypto_sign_verify_detached($signature, $bytes, MaterialCodec::decode($key['public']));
    }

    $coordinate = $algorithm === 'ecdsa-p256-sha256' ? 32 : 48;

    return openssl_verify($bytes, Der::fromRaw($signature, $coordinate), MaterialCodec::decode($key['public']), $coordinate === 32 ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA384) === 1;
}

function vectorAt(): CarbonImmutable
{
    return CarbonImmutable::parse(formatVectors()['at']);
}

it('ships enough frozen vectors to mean something', function (): void {
    expect(formatVectors()['format'])->toBe('sentinel.seal/1')
        ->and(formatVectors()['seal'])->toHaveCount(13)
        ->and(formatVectors()['ledger'])->toHaveCount(3)
        ->and(formatVectors()['checkpoint'])->toHaveCount(2)
        ->and(formatVectors()['anchor'])->toHaveCount(2)
        ->and(formatVectors()['field_tags'])->toHaveCount(6);
});

it('rebuilds every seal document byte for byte and reproduces its MAC or signature', function (): void {
    $signers = new Signers;
    $checked = 0;

    foreach (formatVectors()['seal'] as $case) {
        foreach ($case['documents'] as $algorithm => $document) {
            $key = vectorKey($algorithm);
            $message = new SealMessage($case['ctx'], $case['type'], $case['table'], $case['id'], $case['scope'], $case['seal'], $case['ver'],
                $case['prev'], 'default', $key->keyId, Algorithm::from($algorithm), vectorAt(),
                array_map(static fn (array $field): FieldValue => new FieldValue(...$field), $case['fields']));

            expect($message->bytes())->toBe($document['bytes'], "{$case['name']} / {$algorithm}")
                ->and($signers->verify($key, Purpose::Seal, $document['bytes'], Base64Url::decode($document['mac'])))->toBeTrue()
                ->and(oracleVerifies($algorithm, 'seal', $document['bytes'], $document['mac']))->toBeTrue()
                ->and($signers->verify($key, Purpose::Seal, $document['bytes'].' ', Base64Url::decode($document['mac'])))->toBeFalse();

            if (! str_starts_with($algorithm, 'ecdsa-')) {
                // HMAC and Ed25519 are deterministic: the frozen bytes are reproduced exactly.
                expect(Base64Url::encode($signers->sign($key, Purpose::Seal, $document['bytes'])))->toBe($document['mac']);
            }

            $checked++;
        }
    }

    expect($checked)->toBe(13 * 6);
});

it('reproduces the frozen field tags', function (): void {
    $tagger = new FieldTagger;
    $cases = array_column(formatVectors()['seal'], null, 'name');

    foreach (formatVectors()['field_tags'] as $vector) {
        $case = $cases[$vector['case']];
        $key = vectorKey($vector['key']);
        $message = new SealMessage($case['ctx'], $case['type'], $case['table'], $case['id'], $case['scope'], $case['seal'], $case['ver'],
            $case['prev'], 'default', $key->keyId, Algorithm::from($vector['key']), vectorAt(),
            array_map(static fn (array $field): FieldValue => new FieldValue(...$field), $case['fields']));

        expect($tagger->tags($key, $message))->toBe($vector['tags']);
    }
});

it('rebuilds every ledger entry and reproduces its entry MAC', function (): void {
    $signers = new Signers;

    foreach (formatVectors()['ledger'] as $case) {
        foreach ($case['documents'] as $algorithm => $document) {
            $key = vectorKey($algorithm);
            $message = new LedgerMessage($case['ctx'], $case['type'], $case['id'], $case['seal'], $case['ver'], SealEvent::from($case['event']),
                'default', $key->keyId, Algorithm::from($algorithm), $case['mac'], $case['prev'], $case['changed'],
                $case['previous_status'] === null ? null : VerificationStatus::from($case['previous_status']), $case['actor'], $case['reason'], vectorAt());

            expect($message->bytes())->toBe($document['bytes'])
                ->and($signers->verify($key, Purpose::Ledger, $document['bytes'], Base64Url::decode($document['mac'])))->toBeTrue()
                ->and(oracleVerifies($algorithm, 'ledger', $document['bytes'], $document['mac']))->toBeTrue()
                // A seal-purpose key can never vouch for a ledger entry.
                ->and(str_starts_with($algorithm, 'hmac-') ? $signers->verify($key, Purpose::Seal, $document['bytes'], Base64Url::decode($document['mac'])) : false)->toBeFalse();
        }
    }
});

it('rebuilds every checkpoint and anchor document', function (): void {
    $signers = new Signers;

    foreach (formatVectors()['checkpoint'] as $case) {
        foreach ($case['documents'] as $algorithm => $document) {
            $key = vectorKey($algorithm);
            $message = new CheckpointMessage($case['ctx'], $case['seq'], $case['first'], $case['last'], $case['n'], $case['root'], $case['prev'],
                'default', $key->keyId, Algorithm::from($algorithm), vectorAt());

            expect($message->bytes())->toBe($document['bytes'])
                ->and($signers->verify($key, Purpose::Ledger, $document['bytes'], Base64Url::decode($document['mac'])))->toBeTrue()
                ->and(oracleVerifies($algorithm, 'ledger', $document['bytes'], $document['mac']))->toBeTrue();
        }
    }

    foreach (formatVectors()['anchor'] as $case) {
        $message = new AnchorMessage($case['conn'], $case['seq'], $case['root'], vectorAt(), 'default', $case['kid'], Algorithm::from($case['alg']), $case['mac']);

        expect($message->bytes())->toBe($case['bytes']);
    }
});
