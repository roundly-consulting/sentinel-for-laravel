<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\Enums\MacRejection;

/**
 * `verifyMac()` refused a MAC; {@see reason()} says why. The message names the ring and the
 * kid (sanitised) — never the MAC, the message or any key material.
 */
final class MacVerificationException extends SentinelException
{
    private function __construct(
        string $message,
        private readonly MacRejection $reason,
        private readonly string $ring,
        private readonly string $keyId,
    ) {
        parent::__construct($message);
    }

    public static function rejected(MacRejection $reason, string $ring, string $keyId): self
    {
        $kid = preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $keyId) === 1 ? $keyId : '(invalid)';

        $message = match ($reason) {
            MacRejection::UnknownKey => "Key ring [{$ring}] has no key [{$kid}] to verify a MAC with.",
            MacRejection::PendingKey => "Key [{$kid}] of ring [{$ring}] is pending and verifies no MAC.",
            MacRejection::RetiredKey => "Key [{$kid}] of ring [{$ring}] is retired and verifies no MAC.",
            MacRejection::RevokedKey => "Key [{$kid}] of ring [{$ring}] is revoked and verifies no MAC.",
            MacRejection::UnsupportedAlgorithm => "Key [{$kid}] of ring [{$ring}] is not an HMAC key; a MAC needs an hmac-* key.",
            MacRejection::AlgorithmNotAllowed => "The algorithm of key [{$kid}] is not allowed in key ring [{$ring}].",
            MacRejection::Malformed => "The MAC for key [{$kid}] of ring [{$ring}] is malformed: send the HMAC as unpadded base64url (RFC 4648 §5) of the full hash length.",
            MacRejection::Mismatch => "The MAC does not match the message for key [{$kid}] of ring [{$ring}].",
        };

        return new self($message, $reason, $ring, $keyId);
    }

    public function reason(): MacRejection
    {
        return $this->reason;
    }

    public function ring(): string
    {
        return $this->ring;
    }

    /**
     * The kid as the caller passed it (unsanitised — escape it before rendering).
     */
    public function keyId(): string
    {
        return $this->keyId;
    }
}
