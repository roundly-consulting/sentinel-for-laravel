<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Signatures;

use RoundlyConsulting\Sentinel\Enums\Algorithm;

/**
 * One validated `sentinel.signatures.profiles.<name>` section: what an inbound signature must
 * look like.
 *
 * @internal
 */
final readonly class SignatureProfile
{
    /**
     * @param  list<string>  $components
     * @param  list<Algorithm>  $algorithms
     */
    public function __construct(
        public string $name,
        public string $ring,
        public ?string $label,
        public ?string $tag,
        public array $components,
        public bool $requireQuery,
        public bool $requireContentDigest,
        public bool $requireNonce,
        public int $maxAge,
        public int $clockSkew,
        public array $algorithms,
    ) {}

    public function allows(Algorithm $algorithm): bool
    {
        return in_array($algorithm, $this->algorithms, true);
    }
}
