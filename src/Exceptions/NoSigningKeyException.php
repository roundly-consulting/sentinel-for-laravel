<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * A ring has no key that may sign right now (none configured, only public material, or the
 * current key is revoked, retired or not yet active). Verify-only nodes see this on purpose.
 */
final class NoSigningKeyException extends SentinelException
{
    /** The key variables of the rings the shipped config/sentinel.php declares. */
    private const array ENV = [
        'default' => 'SENTINEL_KEY_ID and SENTINEL_KEY',
        'http' => 'SENTINEL_HTTP_KEY_ID and SENTINEL_HTTP_KEY',
    ];

    public static function forRing(string $ring): self
    {
        $message = "Key ring [{$ring}] has no active signing key. Generate one with `php artisan sentinel:key:generate --ring={$ring}`";

        if (self::readsConfig($ring)) {
            $message .= ' and set '.(self::ENV[$ring] ?? "sentinel.keys.rings.{$ring}.key_id and .key").' from the lines it prints';
        }

        $message .= '.';

        if (config('app.env') === 'testing') {
            $message .= ' In tests, use RoundlyConsulting\\Sentinel\\Testing\\WithSentinelKeys (real throwaway keys) or Sentinel::fake().';
        }

        return new self($message);
    }

    private static function readsConfig(string $ring): bool
    {
        try {
            $config = Settings::ring($ring);
        } catch (SentinelException) {
            return false;
        }

        return $config->driver === 'config' || ($config->driver === 'chain' && in_array('config', $config->drivers, true));
    }
}
