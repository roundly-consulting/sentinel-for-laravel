<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Nonces;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\Nonces\NonceDigest;
use RoundlyConsulting\Sentinel\Support\Clock;
use SensitiveParameter;

/**
 * Remember a nonce a client sent (an HTTP signature's `nonce`) until `until`: true the first
 * time, false for a replay inside the window.
 *
 * @internal
 */
final readonly class RememberNonceAction
{
    public function __construct(private NonceStore $store) {}

    public function execute(string $purpose, #[SensitiveParameter] string $nonce, CarbonImmutable $until): bool
    {
        return $this->store->remember($purpose, NonceDigest::of($nonce), $until, Clock::now());
    }
}
