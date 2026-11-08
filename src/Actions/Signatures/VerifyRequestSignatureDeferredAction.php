<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Signatures;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use RoundlyConsulting\Sentinel\Contracts\InspectsNonces;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\DeferredSignature;
use RoundlyConsulting\Sentinel\Events\HttpSignatureRejected;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Http\Messages\SymfonyRequestView;
use RoundlyConsulting\Sentinel\Http\Signatures\ProfileResolver;
use RoundlyConsulting\Sentinel\Http\Signatures\SignatureVerifier;
use RoundlyConsulting\Sentinel\Nonces\NonceDigest;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Verify an incoming request's RFC 9421 signature exactly as {@see VerifyRequestSignatureAction}
 * does — a nonce already recorded is `replayed` — but leave the nonce unrecorded: the caller
 * commits it with {@see CommitSignatureNonceAction} once it accepts the request. A request it
 * refuses (a 400, a 500) keeps the nonce free for the sender's retry.
 */
final readonly class VerifyRequestSignatureDeferredAction
{
    public function __construct(
        private SignatureVerifier $verifier,
        private NonceStore $store,
        private Dispatcher $events,
    ) {}

    /**
     * @throws HttpSignatureException with the reason (401); fires `HttpSignatureRejected`
     * @throws InvalidSentinelConfigurationException for an unknown profile, or a bound nonce
     *                                               store that cannot look a nonce up
     */
    public function execute(Request $request, ?string $profile = null): DeferredSignature
    {
        $store = $this->store;

        if (! $store instanceof InspectsNonces) {
            throw InvalidSentinelConfigurationException::nonceStoreCannotInspect($store::class);
        }

        $resolved = ProfileResolver::resolve($profile);
        $path = '/'.ltrim($request->path(), '/');

        try {
            $authenticated = $this->verifier->authenticate(
                new SymfonyRequestView($request),
                $resolved,
                static fn (string $purpose, string $nonce): bool => ! $store->seen($purpose, NonceDigest::of($nonce), Clock::now()),
            );
        } catch (HttpSignatureException $exception) {
            $this->events->dispatch(new HttpSignatureRejected($exception->reason(), $exception->keyId(), $request->getMethod(), $path));

            throw $exception;
        }

        return new DeferredSignature($authenticated->signature, $authenticated->nonceScope, $authenticated->nonceUntil, $request->getMethod(), $path);
    }
}
