<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Macs;

use InvalidArgumentException;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Keys\SecretMacRules;
use RoundlyConsulting\Sentinel\Keys\Signers;
use SensitiveParameter;

/**
 * Check a raw MAC against up to 8 caller-held secrets (current first, then the ones still in
 * their grace period) and say which one matched.
 *
 * Constant time over the list: the MAC of **every** secret is computed and compared, the loop
 * never breaks, and the lowest matching index is picked from the accumulated result after the
 * loop — timing tells neither which secret matched nor whether any did. A MAC of the wrong
 * length (empty included) is compared against zeros of the right length, so it costs what a
 * wrong one does, and is never an error.
 */
final readonly class VerifyWithSecretsAction
{
    public function __construct(private Signers $signers) {}

    /**
     * The index of the lowest secret the MAC matches, or null.
     *
     * @param  non-empty-list<string>  $secrets
     *
     * @throws AlgorithmNotAllowedException for Ed25519 / ECDSA
     * @throws InvalidKeyMaterialException for no secrets, more than 8, or an empty one
     * @throws InvalidArgumentException for a non-list or a non-string secret
     */
    public function execute(string $message, #[SensitiveParameter] string $mac, #[SensitiveParameter] array $secrets, Algorithm $algorithm = Algorithm::HmacSha256): ?int
    {
        $secrets = SecretMacRules::secrets($algorithm, $secrets);
        $length = $algorithm->hashLength();
        $wellFormed = strlen($mac) === $length;
        $candidate = $wellFormed ? $mac : str_repeat("\0", $length);

        // One bit per secret (at most 8): set where the MAC matched.
        $matches = 0;

        foreach ($secrets as $index => $secret) {
            $matches |= ((int) ConstantTime::equals($this->signers->macWithSecret($algorithm, $message, $secret), $candidate)) << $index;
        }

        // A wrong-length MAC never matches, even should a MAC equal the zero buffer.
        $matches &= -(int) $wellFormed;

        // The lowest set bit is the lowest matching index.
        return $matches === 0 ? null : strlen(decbin($matches & -$matches)) - 1;
    }
}
