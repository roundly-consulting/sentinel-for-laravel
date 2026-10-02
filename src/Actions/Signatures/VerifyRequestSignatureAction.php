<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Signatures;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Events\HttpSignatureRejected;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Http\Messages\SymfonyRequestView;
use RoundlyConsulting\Sentinel\Http\Signatures\SignatureProfile;
use RoundlyConsulting\Sentinel\Http\Signatures\SignatureVerifier;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * Verify an incoming request's RFC 9421 signature against a profile. A rejection fires
 * `HttpSignatureRejected` (with the precise reason) and throws `HttpSignatureException`
 * (401); a nonce is remembered only after the signature verified.
 */
final readonly class VerifyRequestSignatureAction
{
    public function __construct(
        private SignatureVerifier $verifier,
        private SentinelManager $manager,
        private Dispatcher $events,
    ) {}

    public function execute(Request $request, SignatureProfile $profile): VerifiedSignature
    {
        try {
            return $this->verifier->verify(
                new SymfonyRequestView($request),
                $profile,
                fn (string $purpose, string $nonce, int $until): bool => $this->manager->rememberNonce($purpose, $nonce, CarbonImmutable::createFromTimestampUTC($until)),
            );
        } catch (HttpSignatureException $exception) {
            $this->events->dispatch(new HttpSignatureRejected($exception->reason(), $exception->keyId(), $request->getMethod(), '/'.ltrim($request->path(), '/')));

            throw $exception;
        }
    }
}
