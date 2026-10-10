<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Why `verifyMac()` refused a MAC (`MacVerificationException::reason()`).
 * Checked in this order: the key (unknown → its status → its algorithm), then — after the full
 * HMAC and its constant-time compare — the MAC's encoding and length, then the match.
 */
enum MacRejection: string
{
    use Helpers;

    /** No key with that kid in that ring — a kid of another ring included, by design. */
    case UnknownKey = 'unknown_key';

    /** The key does not verify yet (`activates_at` is in the future). */
    case PendingKey = 'pending_key';

    /** The key has retired: it verifies nothing any more. */
    case RetiredKey = 'retired_key';

    /** The key is revoked — in its store or through `SENTINEL_REVOKED_KEYS`. */
    case RevokedKey = 'revoked_key';

    /** The key is a signing key (Ed25519, ECDSA), not an `hmac-*` key. */
    case UnsupportedAlgorithm = 'unsupported_algorithm';

    /** The key's HMAC algorithm is not in the ring's `algorithms` (any more). */
    case AlgorithmNotAllowed = 'algorithm_not_allowed';

    /** The MAC is not unpadded base64url, or not the key's full hash length. */
    case Malformed = 'malformed_mac';

    /** A well-formed MAC that does not match the message under the key. */
    case Mismatch = 'mismatch';
}
