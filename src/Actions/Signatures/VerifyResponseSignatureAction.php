<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Signatures;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Client\Response as ClientResponse;
use Psr\Http\Message\ResponseInterface;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Events\HttpSignatureRejected;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Http\Messages\PsrResponseView;
use RoundlyConsulting\Sentinel\Http\Signatures\ProfileResolver;
use RoundlyConsulting\Sentinel\Http\Signatures\SignatureVerifier;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * Verify a received response's RFC 9421 signature against a profile (by name, null = the
 * default): the same rules, with `@status` required
 * and no query or nonce requirement (a nonce that is present is still de-duplicated).
 */
final readonly class VerifyResponseSignatureAction
{
    public function __construct(
        private SignatureVerifier $verifier,
        private SentinelManager $manager,
        private Dispatcher $events,
    ) {}

    public function execute(ResponseInterface|ClientResponse $response, ?string $profile = null): VerifiedSignature
    {
        $psr = $response instanceof ClientResponse ? $response->toPsrResponse() : $response;

        try {
            return $this->verifier->verify(
                new PsrResponseView($psr),
                ProfileResolver::resolve($profile),
                fn (string $purpose, string $nonce, int $until): bool => $this->manager->rememberNonce($purpose, $nonce, CarbonImmutable::createFromTimestampUTC($until)),
            );
        } catch (HttpSignatureException $exception) {
            $this->events->dispatch(new HttpSignatureRejected($exception->reason(), $exception->keyId(), 'RESPONSE', (string) $psr->getStatusCode()));

            throw $exception;
        }
    }
}
