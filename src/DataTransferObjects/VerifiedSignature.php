<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Enums\Algorithm;

/**
 * A verified RFC 9421 signature — on a request, available as the `sentinel.signature`
 * request attribute: who signed (ring, key id, the key's owner for database keys), when,
 * and what was covered.
 */
final readonly class VerifiedSignature
{
    /**
     * @param  list<string>  $components
     */
    public function __construct(
        public string $label,
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public int $created,
        public ?int $expires,
        public ?string $nonce,
        public ?string $tag,
        public array $components,
        public ?string $ownerType = null,
        public int|string|null $ownerId = null,
    ) {}
}
