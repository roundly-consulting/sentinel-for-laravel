<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Macs;

use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Keys\SecretMacRules;
use RoundlyConsulting\Sentinel\Keys\Signers;
use SensitiveParameter;

/**
 * MAC a message with a secret the caller holds (a webhook endpoint's secret, a partner's):
 * the plain `HMAC(secret, message)` — no HKDF, no purpose label — so a peer in any language
 * reproduces it. Raw bytes out (32 / 48 / 64); the wire encoding is the caller's.
 */
final readonly class SignWithSecretAction
{
    public function __construct(private Signers $signers) {}

    /**
     * @throws AlgorithmNotAllowedException for Ed25519 / ECDSA
     * @throws InvalidKeyMaterialException for an empty secret
     */
    public function execute(string $message, #[SensitiveParameter] string $secret, Algorithm $algorithm = Algorithm::HmacSha256): string
    {
        SecretMacRules::algorithm($algorithm);
        SecretMacRules::secret($secret);

        return $this->signers->macWithSecret($algorithm, $message, $secret);
    }
}
