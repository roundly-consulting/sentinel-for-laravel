<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Keys;

use RoundlyConsulting\Sentinel\DataTransferObjects\IssuedMac;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\MacRules;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\Signers;

/**
 * MAC arbitrary bytes with a ring's current signing key — the counterpart of
 * {@see VerifyMacAction}: `HMAC(raw secret, message)` as unpadded base64url, plus the kid the
 * receiver verifies it with.
 */
final readonly class ComputeMacAction
{
    public function __construct(
        private KeyStoreManager $keys,
        private Signers $signers,
    ) {}

    /**
     * @throws NoSigningKeyException when the ring has no active key holding its secret
     * @throws AlgorithmNotAllowedException when that key is no `hmac-*` key the ring allows
     * @throws SealingMisconfiguredException for a ring that is not configured or holds no MAC keys
     */
    public function execute(string $ring, string $message): IssuedMac
    {
        $config = MacRules::ring($ring);
        $key = $this->keys->signingKey($ring);
        $algorithm = $key->algorithm();

        if (! $algorithm->isHmac()) {
            throw AlgorithmNotAllowedException::notHmac($ring, $key->keyId, $algorithm);
        }

        if (! $config->allows($algorithm)) {
            throw AlgorithmNotAllowedException::forRing($ring, $algorithm);
        }

        return new IssuedMac($ring, $key->keyId, $algorithm, MacRules::encode($this->signers->sign($key, Purpose::Mac, $message)));
    }
}
