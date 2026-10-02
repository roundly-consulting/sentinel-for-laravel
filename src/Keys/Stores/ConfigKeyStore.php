<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys\Stores;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Contracts\KeyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStatusResolver;
use RoundlyConsulting\Sentinel\Keys\MaterialCodec;
use RoundlyConsulting\Sentinel\Keys\RingConfig;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use SensitiveParameter;

/**
 * Keys from config/env (the default driver): the current key (`key_id` + `key` /
 * `public_key`) and verify-only `previous` keys (`kid|alg|base64:…,…`). Keys live outside
 * the database, so a database writer can never touch them. Read-only by nature:
 * generate/rotate print environment lines instead.
 *
 * @internal
 */
final class ConfigKeyStore implements KeyStore
{
    /** @var array<string, SealingKey>|null */
    private ?array $keys = null;

    /**
     * @param  list<string>  $revoked
     */
    public function __construct(
        private readonly RingConfig $config,
        private readonly array $revoked,
        private readonly CarbonImmutable $now,
    ) {}

    public function signingKey(): SealingKey
    {
        $current = $this->config->keyId === null ? null : ($this->keys()[$this->config->keyId] ?? null);

        if ($current === null || ! $current->canSign()) {
            throw NoSigningKeyException::forRing($this->config->name);
        }

        return $current;
    }

    public function find(string $keyId): ?SealingKey
    {
        return $this->keys()[$keyId] ?? null;
    }

    public function all(): array
    {
        return array_values(array_map(KeyInfo::fromKey(...), $this->keys()));
    }

    public function supportsWrites(): bool
    {
        return false;
    }

    /**
     * @return array<string, SealingKey>
     */
    private function keys(): array
    {
        if ($this->keys !== null) {
            return $this->keys;
        }

        $ring = $this->config->name;
        $keys = [];

        if ($this->config->key !== null || $this->config->publicKey !== null) {
            if ($this->config->keyId === null) {
                throw InvalidSentinelConfigurationException::invalidValue("keys.rings.{$ring}.key_id", 'is required when a key is configured');
            }

            $material = KeyMaterial::fromEncoded($this->config->algorithm, $this->config->key, $this->config->publicKey);
            $keys[$this->config->keyId] = $this->key($this->config->keyId, $material, ! $material->canSign());
        }

        foreach (Identifiers::csv($this->config->previous) as $position => $entry) {
            $key = $this->previous($entry, $position + 1);

            if (isset($keys[$key->keyId])) {
                throw InvalidSentinelConfigurationException::invalidValue("keys.rings.{$ring}.previous", "repeats the key id [{$key->keyId}]");
            }

            $keys[$key->keyId] = $key;
        }

        return $this->keys = $keys;
    }

    private function key(string $keyId, #[SensitiveParameter] KeyMaterial $material, bool $verifyOnly): SealingKey
    {
        $status = KeyStatusResolver::resolve($this->config->name, $keyId, $this->revoked, $this->now, verifyOnly: $verifyOnly);

        return new SealingKey($this->config->name, $keyId, $material, $status, 'config');
    }

    /**
     * One `kid|algorithm|base64:material` entry; the material is a secret (HMAC, Ed25519
     * secret key, EC private PEM) or a public key (Ed25519 32 bytes, EC public PEM).
     */
    private function previous(#[SensitiveParameter] string $entry, int $position): SealingKey
    {
        $key = "keys.rings.{$this->config->name}.previous";
        $parts = explode('|', $entry, 3);
        $algorithm = Algorithm::tryFrom($parts[1] ?? '');

        if (count($parts) !== 3 || ! Identifiers::isKeyId($parts[0]) || $algorithm === null) {
            throw InvalidSentinelConfigurationException::invalidPreviousKey($key, $position);
        }

        try {
            $material = $this->isPublic($algorithm, $parts[2])
                ? KeyMaterial::fromEncoded($algorithm, null, $parts[2])
                : KeyMaterial::fromEncoded($algorithm, $parts[2]);
        } catch (InvalidKeyMaterialException) {
            throw InvalidSentinelConfigurationException::invalidPreviousKey($key, $position);
        }

        return $this->key($parts[0], $material, true);
    }

    private function isPublic(Algorithm $algorithm, #[SensitiveParameter] string $encoded): bool
    {
        $bytes = MaterialCodec::decode($encoded);

        return match ($algorithm) {
            Algorithm::Ed25519 => strlen($bytes) === 32,
            Algorithm::EcdsaP256Sha256, Algorithm::EcdsaP384Sha384 => ! str_contains($bytes, 'PRIVATE KEY'),
            default => false,
        };
    }
}
