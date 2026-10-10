<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands\Concerns;

use RoundlyConsulting\Sentinel\Support\Identifiers;

/**
 * Text read from a stored key row, shown so the operator can check it and the console never
 * interprets it. A label is quoted, with every control and invisible formatting character
 * escaped (an ANSI sequence, a right-to-left override, a zero-width space) and `<` / `>` too
 * (a console style tag). A key id is shown as is when it is a valid key id — Sentinel never
 * writes another — and escaped like a label when a database writer planted one.
 */
trait ShowsKeyLabels
{
    protected static function shownLabel(?string $label, string $none): string
    {
        if ($label === null) {
            return $none;
        }

        // JSON escapes the quotes, `<`, `>` and the C0 controls; then DEL, the C1 controls and
        // the Unicode format characters.
        $shown = (string) json_encode($label, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_INVALID_UTF8_SUBSTITUTE);

        return (string) preg_replace_callback('/[\p{Cc}\p{Cf}]/u', static fn (array $match): string => sprintf('\u%04x', mb_ord($match[0], 'UTF-8')), $shown);
    }

    protected static function shownKeyId(string $keyId): string
    {
        return Identifiers::isKeyId($keyId) ? $keyId : self::shownLabel($keyId, '');
    }
}
