<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * A request signature verified with its nonce NOT yet recorded — what
 * `Sentinel::signatures()->verifyDeferred()` returns. Everything was checked, including that
 * the nonce is unused; hand it to `Sentinel::signatures()->commitNonce()` once the request is
 * accepted, before acting on it. Until then an identical copy verifies too.
 *
 * `nonceScope` is the signing key's nonce scope, exactly as on the eager path; `nonceUntil` is
 * when its record would expire (`created + max_age + clock_skew + 1`, Unix seconds) — a commit
 * from that instant on is refused as `too_old`.
 */
final readonly class DeferredSignature
{
    /**
     * @internal built by the verifier; a hand-built one commits under whatever it claims
     */
    public function __construct(
        public VerifiedSignature $signature,
        public string $nonceScope,
        public int $nonceUntil,
        public string $method,
        public string $path,
    ) {}

    /**
     * The signature carries a nonce, so `commitNonce()` has one to record.
     */
    public function hasNonce(): bool
    {
        return $this->signature->nonce !== null;
    }
}
