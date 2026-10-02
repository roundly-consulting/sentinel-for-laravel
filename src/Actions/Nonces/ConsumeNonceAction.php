<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Nonces;

use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\ConsumeNonceRequest;
use RoundlyConsulting\Sentinel\Exceptions\InvalidPurposeException;
use RoundlyConsulting\Sentinel\Nonces\NonceDigest;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Identifiers;

/**
 * Use a nonce once. True exactly once for an unexpired, unused nonce of this purpose and
 * subject; every other case is the same `false` (one atomic statement, no oracle).
 */
final readonly class ConsumeNonceAction
{
    public function __construct(private NonceStore $store) {}

    public function execute(ConsumeNonceRequest $request): bool
    {
        if (! Identifiers::isPurpose($request->purpose)) {
            throw InvalidPurposeException::forPurpose($request->purpose);
        }

        if ($request->value === '' || strlen($request->value) > 512) {
            return false;
        }

        return $this->store->consume($request->purpose, NonceDigest::of($request->value), Clock::now(), $request->subject);
    }
}
