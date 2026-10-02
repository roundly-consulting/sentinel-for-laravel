<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Ledger;

use Carbon\CarbonImmutable;
use JsonException;
use RoundlyConsulting\Sentinel\Canonical\AnchorMessage;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Models\Checkpoint;

/**
 * Anchor payloads as stored outside the database: the canonical `sentinel.anchor/1` JSON
 * text, parsed back strictly (anything else is an invalid anchor, never a guess).
 *
 * @internal
 */
final class AnchorCodec
{
    public static function encode(AnchorPayload $payload): string
    {
        return self::message($payload)->bytes();
    }

    /**
     * @return array<string, string>
     */
    public static function toArray(AnchorPayload $payload): array
    {
        return [
            'v' => AnchorMessage::VERSION,
            'conn' => $payload->connection,
            'seq' => (string) $payload->seq,
            'root' => $payload->root,
            'at' => $payload->at->format('Y-m-d\TH:i:s.u\Z'),
            'ring' => $payload->ring,
            'kid' => $payload->keyId,
            'alg' => $payload->algorithm->value,
            'mac' => $payload->mac,
        ];
    }

    /**
     * @throws CorruptRecordException
     */
    public static function decode(string $json): AnchorPayload
    {
        try {
            $data = json_decode($json, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw CorruptRecordException::anchor('not JSON');
        }

        if (! is_array($data)) {
            throw CorruptRecordException::anchor('not an object');
        }

        $fields = [];

        foreach (['v', 'conn', 'seq', 'root', 'at', 'ring', 'kid', 'alg', 'mac'] as $member) {
            $value = $data[$member] ?? null;

            if (! is_string($value) || $value === '' || strlen($value) > 255) {
                throw CorruptRecordException::anchor("member [{$member}] is missing or not a string");
            }

            $fields[$member] = $value;
        }

        $algorithm = Algorithm::tryFrom($fields['alg']);

        if ($fields['v'] !== AnchorMessage::VERSION || preg_match('/^[1-9][0-9]{0,18}$/D', $fields['seq']) !== 1 || $algorithm === null) {
            throw CorruptRecordException::anchor('unknown version, sequence or algorithm');
        }

        return new AnchorPayload(
            $fields['conn'], (int) $fields['seq'], $fields['root'], self::at($fields['at']), $fields['ring'], $fields['kid'], $algorithm, $fields['mac'],
        );
    }

    /**
     * The payload of a stored checkpoint (null when the row is unreadable).
     */
    public static function fromCheckpoint(Checkpoint $checkpoint, string $connection): ?AnchorPayload
    {
        $algorithm = Algorithm::tryFrom((string) $checkpoint->getRawOriginal('algorithm'));

        try {
            $at = (new UtcDateTime)->get($checkpoint, 'created_at', $checkpoint->getRawOriginal('created_at'), []);
        } catch (CorruptRecordException) {
            $at = null;
        }

        if ($algorithm === null || $at === null) {
            return null;
        }

        return new AnchorPayload(
            $connection,
            (int) $checkpoint->getRawOriginal('seq'),
            (string) $checkpoint->getRawOriginal('root'),
            $at,
            (string) $checkpoint->getRawOriginal('ring'),
            (string) $checkpoint->getRawOriginal('key_id'),
            $algorithm,
            (string) $checkpoint->getRawOriginal('mac'),
        );
    }

    private static function message(AnchorPayload $payload): AnchorMessage
    {
        return new AnchorMessage(
            $payload->connection, $payload->seq, $payload->root, $payload->at, $payload->ring, $payload->keyId, $payload->algorithm, $payload->mac,
        );
    }

    private static function at(string $value): CarbonImmutable
    {
        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/D', $value) !== 1) {
            throw CorruptRecordException::anchor('member [at] is not a UTC timestamp');
        }

        try {
            $at = (new UtcDateTime)->get(new Checkpoint, 'at', $value, []);
        } catch (CorruptRecordException) {
            throw CorruptRecordException::anchor('member [at] is not a UTC timestamp');
        }

        return $at ?? throw CorruptRecordException::anchor('member [at] is not a UTC timestamp');
    }
}
