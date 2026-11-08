<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use InvalidArgumentException;
use RoundlyConsulting\Sentinel\Accessors\MacsAccessor;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use SensitiveParameter;

/**
 * The rules of MACs with caller-held secrets (`Sentinel::macs()`), shared by the actions and
 * the fake: an `hmac-*` algorithm, any non-empty secret (no 32-byte floor — that floor is the
 * key rings'; HMAC hashes an over-long key), and 1–8 secrets to verify against. Every rule is
 * checked before any MAC is computed. Messages never carry a secret, a MAC or the message.
 *
 * @internal
 */
final class SecretMacRules
{
    /**
     * @throws AlgorithmNotAllowedException for Ed25519 / ECDSA
     */
    public static function algorithm(Algorithm $algorithm): void
    {
        if (! $algorithm->isHmac()) {
            throw AlgorithmNotAllowedException::notHmacForMacs($algorithm);
        }
    }

    /**
     * @throws InvalidKeyMaterialException for an empty secret
     */
    public static function secret(#[SensitiveParameter] string $secret): void
    {
        if ($secret === '') {
            throw InvalidKeyMaterialException::emptySecret();
        }
    }

    /**
     * The secrets as a checked list.
     *
     * @param  array<mixed>  $secrets
     * @return non-empty-list<string>
     *
     * @throws AlgorithmNotAllowedException for Ed25519 / ECDSA
     * @throws InvalidKeyMaterialException for no secrets, more than {@see MacsAccessor::MAX_SECRETS}, or an empty one
     * @throws InvalidArgumentException for a non-list or a non-string secret
     */
    public static function secrets(Algorithm $algorithm, #[SensitiveParameter] array $secrets): array
    {
        self::algorithm($algorithm);

        if (! array_is_list($secrets)) {
            throw new InvalidArgumentException('The MAC secrets must be a list of strings.');
        }

        if ($secrets === []) {
            throw InvalidKeyMaterialException::noSecrets();
        }

        if (count($secrets) > MacsAccessor::MAX_SECRETS) {
            throw InvalidKeyMaterialException::tooManySecrets(MacsAccessor::MAX_SECRETS);
        }

        $checked = [];

        foreach ($secrets as $secret) {
            if (! is_string($secret)) {
                throw new InvalidArgumentException('The MAC secrets must be a list of strings.');
            }

            self::secret($secret);
            $checked[] = $secret;
        }

        return $checked;
    }
}
