<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Enums\DigestAlgorithm;

/**
 * How an outgoing request is signed (RFC 9421). Every null falls back to
 * `sentinel.signatures.outbound.*`; `nonce` adds a fresh random nonce (the default).
 */
final readonly class SigningOptions
{
    /**
     * @param  list<string>|null  $components
     */
    public function __construct(
        public ?array $components = null,
        public ?string $label = null,
        public ?int $expiresIn = null,
        public ?string $tag = null,
        public ?bool $includeAlg = null,
        public ?DigestAlgorithm $digest = null,
        public ?string $ring = null,
        public bool $nonce = true,
    ) {}
}
