<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Nonces;

use RoundlyConsulting\Crypto\Random\Csprng;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssuedNonce;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssueNonceRequest;
use RoundlyConsulting\Sentinel\Exceptions\InvalidPurposeException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Nonces\NonceDigest;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Issue a single-use nonce: a CSPRNG token (43 base64url characters ≈ 256 bits by default)
 * bound to a purpose and optionally a subject. Only its SHA-256 is stored; the value is
 * returned once.
 */
final readonly class IssueNonceAction
{
    public function __construct(
        private NonceStore $store,
        private Csprng $random = new Csprng,
    ) {}

    public function execute(IssueNonceRequest $request): IssuedNonce
    {
        if (! Identifiers::isPurpose($request->purpose)) {
            throw InvalidPurposeException::forPurpose($request->purpose);
        }

        $ttl = $request->ttl ?? Settings::nonceTtl();

        if ($ttl < 1 || $ttl > 2592000) {
            throw InvalidSentinelConfigurationException::invalidOption('ttl', 'must be between 1 and 2592000 seconds');
        }

        $value = $this->random->token(Settings::nonceLength());
        $expiresAt = Clock::now()->addSeconds($ttl);

        $this->store->issue($request->purpose, NonceDigest::of($value), $expiresAt, $request->subject);

        return new IssuedNonce($value, $request->purpose, $expiresAt);
    }
}
