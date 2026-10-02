<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use SensitiveParameter;

/**
 * Environment lines for config-driver keys. They carry secret material: printed to stdout
 * once by the key commands, never written to `.env`, never logged.
 *
 * The default ring uses `SENTINEL_*`, every other ring `SENTINEL_<RING>_*` (the shipped
 * `http` ring: `SENTINEL_HTTP_*`, its verify-only list `SENTINEL_HTTP_KEYS`).
 *
 * @internal
 */
final class EnvSnippet
{
    public static function prefix(string $ring): string
    {
        return $ring === 'default' ? 'SENTINEL_' : 'SENTINEL_'.strtoupper(str_replace('-', '_', $ring)).'_';
    }

    public static function previousVariable(string $ring): string
    {
        return $ring === 'http' ? 'SENTINEL_HTTP_KEYS' : self::prefix($ring).'PREVIOUS_KEYS';
    }

    public static function forKey(string $ring, string $keyId, #[SensitiveParameter] KeyMaterial $material): string
    {
        $prefix = self::prefix($ring);
        $lines = [
            "{$prefix}KEY_ID={$keyId}",
            "{$prefix}ALGORITHM={$material->algorithm->value}",
            "{$prefix}KEY=\"{$material->encodedPrivate()}\"",
        ];

        if ($material->encodedPublic() !== null) {
            $lines[] = "{$prefix}PUBLIC_KEY=\"{$material->encodedPublic()}\"";
        }

        return implode("\n", $lines);
    }

    /**
     * @param  list<string>  $entries  `kid|alg|base64:…`
     */
    public static function previous(string $ring, #[SensitiveParameter] array $entries): string
    {
        return self::previousVariable($ring).'="'.implode(',', $entries).'"';
    }

    /**
     * The verify-only entry of a key: the secret for HMAC, the public half otherwise.
     */
    public static function entry(string $keyId, #[SensitiveParameter] KeyMaterial $material): string
    {
        return "{$keyId}|{$material->algorithm->value}|".($material->encodedPublic() ?? $material->encodedPrivate());
    }
}
