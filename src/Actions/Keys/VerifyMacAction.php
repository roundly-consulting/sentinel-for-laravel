<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Keys;

use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Enums\MacRejection;
use RoundlyConsulting\Sentinel\Exceptions\MacVerificationException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\MacRules;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use SensitiveParameter;

/**
 * Verify a MAC over arbitrary bytes with the key a kid names in one ring: the raw shared secret
 * (no HKDF), so any peer holding it — PHP or not — produces the MAC with a plain
 * `HMAC(secret, message)`, sent as unpadded base64url. The algorithm comes from the key.
 *
 * Order: the ring → the kid (inside this ring only) → the key's status and algorithm → the
 * full HMAC and its constant-time compare, whatever the MAC's shape → the MAC's encoding and
 * length → the match. A malformed or wrong-length MAC therefore costs what a wrong one does.
 */
final readonly class VerifyMacAction
{
    public function __construct(
        private KeyStoreManager $keys,
        private Signers $signers,
    ) {}

    /**
     * The key that vouches for the message — material-free: bind its owner or label to the
     * sender's identity.
     *
     * @throws MacVerificationException
     * @throws SealingMisconfiguredException for a ring that is not configured or holds no MAC keys
     */
    public function execute(string $ring, string $keyId, string $message, #[SensitiveParameter] string $mac): KeyInfo
    {
        $config = MacRules::ring($ring);
        $key = Identifiers::isKeyId($keyId) ? $this->keys->find($ring, $keyId) : null;

        if ($key === null) {
            throw MacVerificationException::rejected(MacRejection::UnknownKey, $ring, $keyId);
        }

        $refusal = MacRules::refusal($config, $key->status, $key->algorithm());

        if ($refusal !== null) {
            throw MacVerificationException::rejected($refusal, $ring, $keyId);
        }

        $provided = MacRules::decode($mac);
        $matches = $this->signers->verify($key, Purpose::Mac, $message, $provided ?? '');

        if ($provided === null || strlen($provided) !== $key->algorithm()->hashLength()) {
            throw MacVerificationException::rejected(MacRejection::Malformed, $ring, $keyId);
        }

        if (! $matches) {
            throw MacVerificationException::rejected(MacRejection::Mismatch, $ring, $keyId);
        }

        return KeyInfo::fromKey($key);
    }
}
