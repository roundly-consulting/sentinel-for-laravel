<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Enums\Algorithm;

/**
 * A MAC `mac()` computed with a ring's current signing key: send `keyId` and `mac` along with
 * the message, and the receiver verifies with `verifyMac($keyId, $message, $mac)`.
 */
final readonly class IssuedMac
{
    /**
     * @param  string  $mac  the HMAC as unpadded base64url (RFC 4648 §5)
     */
    public function __construct(
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public string $mac,
    ) {}
}
