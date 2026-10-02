<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Signatures;

use Psr\Http\Message\RequestInterface;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\Http\Signatures\MessageSigner;

/**
 * Sign an outgoing PSR-7 request with an RFC 9421 HTTP message signature (and an RFC 9530
 * `Content-Digest` when the body is covered). The key must be active in the outbound ring.
 */
final readonly class SignRequestAction
{
    public function __construct(private MessageSigner $signer) {}

    public function execute(RequestInterface $request, string $keyId, SigningOptions $options): RequestInterface
    {
        return $this->signer->sign($request, $keyId, $options);
    }
}
