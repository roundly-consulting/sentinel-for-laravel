<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use Illuminate\Http\Request;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Exceptions\StructuredFieldException;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parser;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * The `Idempotency-Key` header: an RFC 9651 sf-string (`"8e03978e-40d5-…"`), or — with
 * `accept_unquoted` — a bare printable token as many clients send it. Its length must be
 * within `min_length`..`max_length` (≥ 128 bits for a UUID). Several header lines, control
 * characters or any other item type are invalid (400).
 *
 * @internal
 */
final class KeyParser
{
    /**
     * The key, or null when the header is absent.
     *
     * @throws InvalidIdempotencyKeyException
     */
    public static function fromRequest(Request $request): ?string
    {
        $lines = $request->headers->all(strtolower(Settings::idempotencyHeader()));

        if ($lines === []) {
            return null;
        }

        if (count($lines) !== 1 || ! is_string($lines[0])) {
            throw InvalidIdempotencyKeyException::make();
        }

        return self::parse($lines[0]);
    }

    /**
     * @throws InvalidIdempotencyKeyException
     */
    public static function parse(string $value): string
    {
        $value = trim($value, ' ');

        try {
            $item = Parser::item($value)->value;
        } catch (StructuredFieldException) {
            $item = null;
        }

        // Not an sf-string: accept the bare value as sent, when configured to.
        $key = is_string($item) ? $item : (
            Settings::idempotencyAcceptsUnquoted() && preg_match('/^[\x21-\x7E]+$/D', $value) === 1 && ! str_starts_with($value, '"') ? $value : null
        );

        if (! is_string($key) || strlen($key) < Settings::idempotencyMinLength() || strlen($key) > Settings::idempotencyMaxLength()) {
            throw InvalidIdempotencyKeyException::make();
        }

        return $key;
    }
}
