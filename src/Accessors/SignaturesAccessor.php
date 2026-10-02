<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Accessors;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Client\Response as ClientResponse;
use Illuminate\Http\Request;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Enums\DigestAlgorithm;
use RoundlyConsulting\Sentinel\Http\Signatures\ContentDigest;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * `Sentinel::signatures()` — RFC 9421 HTTP message signatures. Signing and verification go
 * through the manager, so `Sentinel::fake()` sees them.
 */
final readonly class SignaturesAccessor
{
    public function __construct(private SentinelManager $manager) {}

    public function sign(RequestInterface $request, string $keyId, ?SigningOptions $options = null): RequestInterface
    {
        return $this->manager->signRequest($request, $keyId, $options);
    }

    /**
     * Verify an incoming request against a profile (null = the default profile).
     */
    public function verify(Request $request, ?string $profile = null): VerifiedSignature
    {
        return $this->manager->verifyRequestSignature($request, $profile);
    }

    public function verifyResponse(ResponseInterface|ClientResponse $response, ?string $profile = null): VerifiedSignature
    {
        return $this->manager->verifyResponseSignature($response, $profile);
    }

    /**
     * The signature `sentinel.signed` verified on this request, or null.
     */
    public function current(Request $request): ?VerifiedSignature
    {
        return $this->manager->verifiedSignature($request);
    }

    /**
     * The model owning the signing key (e.g. the partner), or null.
     */
    public function owner(Request|VerifiedSignature $from): ?Model
    {
        return $this->manager->signatureOwner($from);
    }

    /**
     * An RFC 9530 `Content-Digest` value for a body: `sha-256=:…:`.
     */
    public function contentDigest(string $body, DigestAlgorithm $algorithm = DigestAlgorithm::Sha256): string
    {
        return ContentDigest::header($body, $algorithm);
    }
}
