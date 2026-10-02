<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Accessors;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\ConsumeNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssuedNonce;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssueNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\SignedRouteRequest;
use RoundlyConsulting\Sentinel\Exceptions\NonceRejectedException;
use RoundlyConsulting\Sentinel\SentinelManager;
use SensitiveParameter;

/**
 * `Sentinel::nonces()` — single-use, purpose-bound nonces and single-use signed URLs. Every
 * call goes through the manager, so `Sentinel::fake()` sees it.
 */
final readonly class NoncesAccessor
{
    public function __construct(private SentinelManager $manager) {}

    public function issue(string $purpose, ?int $ttl = null, ?Model $subject = null): IssuedNonce
    {
        return $this->manager->issueNonce(new IssueNonceRequest($purpose, $ttl, $subject));
    }

    /**
     * True exactly once for a valid nonce of this purpose (and subject).
     */
    public function consume(string $purpose, #[SensitiveParameter] string $nonce, ?Model $subject = null): bool
    {
        return $this->manager->consumeNonce(new ConsumeNonceRequest($purpose, $nonce, $subject));
    }

    /**
     * @throws NonceRejectedException (403) unless the nonce is valid
     */
    public function consumeOrFail(string $purpose, #[SensitiveParameter] string $nonce, ?Model $subject = null): void
    {
        if (! $this->consume($purpose, $nonce, $subject)) {
            throw NonceRejectedException::rejected();
        }
    }

    /**
     * A signed URL for a named route that works once (pair it with `sentinel.single-use`).
     *
     * @param  array<string, mixed>  $parameters
     */
    public function signedRoute(string $name, array $parameters = [], ?int $ttl = null): string
    {
        return $this->manager->signedRoute(new SignedRouteRequest($name, $parameters, $ttl));
    }
}
