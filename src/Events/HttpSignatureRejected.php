<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use RoundlyConsulting\Sentinel\Enums\SignatureRejection;

/**
 * An HTTP message signature was rejected (synchronously) — with the precise reason, which the
 * client does not see.
 */
final readonly class HttpSignatureRejected
{
    public function __construct(
        public SignatureRejection $reason,
        public ?string $keyId,
        public string $method,
        public string $path,
    ) {}
}
