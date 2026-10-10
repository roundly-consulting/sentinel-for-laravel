<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Accessors;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\GeneratedKey;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\ImportKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssuedMac;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotationResult;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;
use RoundlyConsulting\Sentinel\Exceptions\MacVerificationException;
use RoundlyConsulting\Sentinel\SentinelManager;
use SensitiveParameter;

/**
 * `Sentinel::keys()->ring('financial')` — one ring. Scoped: a kid of another ring is unknown
 * here (`UnknownKeyException`), which is what keeps an HTTP partner key from ever touching
 * seals.
 */
final readonly class KeyRingHandle
{
    public function __construct(
        private SentinelManager $manager,
        private string $ring,
    ) {}

    public function name(): string
    {
        return $this->ring;
    }

    /**
     * The current signing key (`NoSigningKeyException` when there is none).
     */
    public function current(): KeyInfo
    {
        return $this->manager->currentKey($this->ring);
    }

    public function find(string $keyId): ?KeyInfo
    {
        return $this->manager->findKey($this->ring, $keyId);
    }

    /**
     * @return list<KeyInfo>
     */
    public function all(): array
    {
        return $this->manager->listKeys($this->ring);
    }

    public function generate(
        Algorithm $algorithm,
        ?string $keyId = null,
        KeyDestination $destination = KeyDestination::Database,
        ?CarbonInterface $activatesAt = null,
        ?Model $owner = null,
        ?string $label = null,
    ): GeneratedKey {
        return $this->manager->generateKey(new GenerateKeyRequest(
            $this->ring, $algorithm, $keyId, $destination,
            $activatesAt === null ? null : CarbonImmutable::instance($activatesAt), $owner, $label,
        ));
    }

    /**
     * Import a key — PEM or `base64:` material — into this ring's database store, bound to
     * its owner (e.g. the partner model). Verify-only unless `signing` is true.
     */
    public function import(
        string $keyId,
        Algorithm $algorithm,
        #[SensitiveParameter] string $material,
        bool $signing = false,
        ?CarbonInterface $activatesAt = null,
        ?Model $owner = null,
        ?string $label = null,
    ): KeyInfo {
        return $this->manager->importKey(new ImportKeyRequest(
            $this->ring, $keyId, $algorithm, $material, $signing,
            $activatesAt === null ? null : CarbonImmutable::instance($activatesAt), $owner, $label,
        ));
    }

    public function rotate(?Algorithm $algorithm = null, ?CarbonInterface $activatesAt = null): RotationResult
    {
        return $this->manager->rotateKey(new RotateKeyRequest(
            $this->ring, $algorithm, $activatesAt === null ? null : CarbonImmutable::instance($activatesAt),
        ));
    }

    public function revoke(string $keyId, string $reason, ?Model $actor = null): KeyInfo
    {
        return $this->manager->revokeKey(new RevokeKeyRequest($this->ring, $keyId, $reason, $actor));
    }

    public function retire(string $keyId): KeyInfo
    {
        return $this->manager->retireKey($this->ring, $keyId);
    }

    /**
     * Verify a MAC a peer computed over `$message` with this ring's key `$keyId`:
     * `base64url-no-padding(HMAC(raw secret, message bytes))`, the algorithm taken from the key.
     * Active and verify-only keys verify; the returned key carries no material.
     *
     * @throws MacVerificationException with the reason a MAC is refused
     */
    public function verifyMac(string $keyId, string $message, #[SensitiveParameter] string $mac): KeyInfo
    {
        return $this->manager->verifyMac($this->ring, $keyId, $message, $mac);
    }

    /**
     * MAC `$message` with this ring's current signing key; send the returned kid and MAC along.
     */
    public function mac(string $message): IssuedMac
    {
        return $this->manager->mac($this->ring, $message);
    }
}
