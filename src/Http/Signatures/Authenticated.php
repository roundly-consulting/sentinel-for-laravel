<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Signatures;

use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;

/**
 * A signature the verifier accepted, with the scope its nonce is recorded under (the key's, as
 * the store resolved it) and the instant it may be forgotten (Unix seconds).
 *
 * @internal
 */
final readonly class Authenticated
{
    public function __construct(
        public VerifiedSignature $signature,
        public string $nonceScope,
        public int $nonceUntil,
    ) {}
}
