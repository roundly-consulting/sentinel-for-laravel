<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Signatures;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Sentinel\DataTransferObjects\DeferredSignature;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Events\HttpSignatureRejected;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Record the nonce of a {@see DeferredSignature} — once. The record is the eager path's: the
 * same atomic `remember()` on the configured nonce store, under the signing key's scope, until
 * `nonceUntil`. Of any number of concurrent commits of one nonce exactly one succeeds; the
 * others are `replayed`. A commit from `nonceUntil` on is `too_old`: the window has closed, and
 * a record that would already be expired could not keep a second late commit out. A signature
 * without a nonce has nothing to record and passes.
 */
final readonly class CommitSignatureNonceAction
{
    public function __construct(
        private SentinelManager $manager,
        private Dispatcher $events,
    ) {}

    /**
     * @throws HttpSignatureException `replayed` or `too_old` (401); fires `HttpSignatureRejected`
     */
    public function execute(DeferredSignature $deferred): VerifiedSignature
    {
        $signature = $deferred->signature;

        if ($signature->nonce === null) {
            return $signature;
        }

        $rejection = match (true) {
            Clock::now()->getTimestamp() >= $deferred->nonceUntil => SignatureRejection::TooOld,
            ! $this->manager->rememberNonce(
                $deferred->nonceScope,
                $signature->nonce,
                CarbonImmutable::createFromTimestampUTC($deferred->nonceUntil),
            ) => SignatureRejection::Replayed,
            default => null,
        };

        if ($rejection !== null) {
            $this->events->dispatch(new HttpSignatureRejected($rejection, $signature->keyId, $deferred->method, $deferred->path));

            throw HttpSignatureException::rejected($rejection, $signature->keyId);
        }

        return $signature;
    }
}
