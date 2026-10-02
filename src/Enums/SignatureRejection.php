<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Why an RFC 9421 HTTP message signature was rejected. Clients see only
 * `signature_rejected` unless `app.debug` is on (no verification oracle).
 */
enum SignatureRejection: string
{
    use Helpers;

    case Missing = 'missing_signature';
    case Malformed = 'malformed';
    case Ambiguous = 'ambiguous_signature';
    case MissingParameter = 'missing_parameter';
    case MissingComponent = 'missing_component';
    case UnsupportedComponent = 'unsupported_component';
    case UnsupportedAlgorithm = 'unsupported_algorithm';
    case UnknownKey = 'unknown_key';
    case RevokedKey = 'revoked_key';
    case AlgorithmMismatch = 'algorithm_mismatch';
    case AlgorithmNotAllowed = 'algorithm_not_allowed';
    case TagMismatch = 'tag_mismatch';
    case NotYetValid = 'not_yet_valid';
    case TooOld = 'too_old';
    case Expired = 'expired';
    case DigestMismatch = 'digest_mismatch';
    case UnsupportedDigest = 'unsupported_digest';
    case InvalidSignature = 'invalid_signature';
    case Replayed = 'replayed';
}
