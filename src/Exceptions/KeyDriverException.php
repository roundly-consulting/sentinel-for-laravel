<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A key-lifecycle operation the ring's driver cannot perform.
 */
final class KeyDriverException extends SentinelException
{
    public static function readOnly(string $ring): self
    {
        // The env variables of the rings the shipped config/sentinel.php declares.
        $env = match ($ring) {
            'default' => ' (SENTINEL_PREVIOUS_KEYS in the shipped config)',
            'http' => ' (SENTINEL_HTTP_KEYS in the shipped config)',
            default => '',
        };

        return new self("Key ring [{$ring}] has no database driver to write keys to; its keys are managed in the environment. Generate one with `sentinel:key:generate`, list verify-only keys in sentinel.keys.rings.{$ring}.previous as kid|algorithm|base64:…{$env}, or set the ring's driver to database or chain.");
    }

    /**
     * The ring signs with a key a custom driver holds: Sentinel can neither write it nor print
     * its replacement, so the key store that owns it rotates it.
     */
    public static function customDriver(string $ring, string $driver): self
    {
        $shown = preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $driver) === 1 ? $driver : '(invalid)';

        return new self("Key ring [{$ring}] signs with a key from the custom driver [{$shown}]; Sentinel cannot rotate it — rotate it in that key store.");
    }

    public static function notStoredInDatabase(string $ring, string $keyId): self
    {
        return new self("The key [{$ring}:{$keyId}] comes from configuration, not the database; change it in the environment instead.");
    }

    /**
     * Another rotation of the ring held its lock past the database's lock wait timeout.
     */
    public static function ringBusy(string $ring): self
    {
        return new self("Another rotation of key ring [{$ring}] is still running; retry once it has finished.");
    }

    public static function keyIdTaken(string $ring, string $keyId): self
    {
        return new self("Key ring [{$ring}] already has a key [{$keyId}].");
    }

    public static function reasonRequired(): self
    {
        return new self('A non-empty reason (at most 1000 characters) is required.');
    }

    public static function invalidKeyId(string $ring): self
    {
        return new self("A key id in ring [{$ring}] must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}.");
    }

    /**
     * The label is bound into the key's envelope (canonical JSON), so it is text.
     */
    public static function invalidLabel(): self
    {
        return new self('A key label must be valid UTF-8 of at most 191 characters.');
    }
}
