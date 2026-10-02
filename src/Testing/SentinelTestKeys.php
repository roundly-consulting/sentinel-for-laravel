<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Testing;

use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Real, throwaway keys for a host's test suite, so factories of sealable models seal for real
 * instead of throwing `NoSigningKeyException` — the alternative to `Sentinel::fake()` when a
 * test wants real seals. Each targeted ring gets a fresh key (kid `test-<ring>`) in its
 * config slot; a ring that already has a configured key is never touched. Process memory
 * only — nothing is written to `.env` or the database.
 */
final class SentinelTestKeys
{
    /**
     * @param  list<string>|null  $rings  null = every ring whose driver reads config (config or chain) and has no key;
     *                                    a ring named here that reads only the database (or a custom driver) becomes a
     *                                    chain of config and that driver
     */
    public static function install(Container $app, Algorithm $algorithm = Algorithm::HmacSha256, ?array $rings = null): void
    {
        $config = $app->make('config');

        foreach ($rings ?? self::configRings() as $ring) {
            $ringConfig = Settings::ring($ring);

            if ($ringConfig->key !== null) {
                continue;
            }

            if (! $ringConfig->allows($algorithm)) {
                throw AlgorithmNotAllowedException::forRing($ring, $algorithm);
            }

            if ($ringConfig->driver !== 'config' && $ringConfig->driver !== 'chain') {
                $config->set("sentinel.keys.rings.{$ring}.driver", 'chain');
                $config->set("sentinel.keys.rings.{$ring}.drivers", ['config', $ringConfig->driver]);
            } elseif ($ringConfig->driver === 'chain' && ! in_array('config', $ringConfig->drivers, true)) {
                $config->set("sentinel.keys.rings.{$ring}.drivers", ['config', ...$ringConfig->drivers]);
            }

            $material = KeyMaterial::generate($algorithm);
            $config->set("sentinel.keys.rings.{$ring}.key_id", "test-{$ring}");
            $config->set("sentinel.keys.rings.{$ring}.algorithm", $algorithm->value);
            $config->set("sentinel.keys.rings.{$ring}.key", $material->encodedPrivate());
            $config->set("sentinel.keys.rings.{$ring}.public_key", $material->encodedPublic());
        }

        $app->make(KeyStoreManager::class)->flush();
    }

    /**
     * @return list<string>
     */
    private static function configRings(): array
    {
        return array_values(array_filter(Settings::rings(), static function (string $ring): bool {
            $config = Settings::ring($ring);

            return $config->key === null && ($config->driver === 'config' || ($config->driver === 'chain' && in_array('config', $config->drivers, true)));
        }));
    }
}
