<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\PackageToolkit\Support\Config;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Http\Problem;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * An HTTP message signature was rejected (401). The response is RFC 9457 problem details
 * whose `code` is the precise reason only under `app.debug` — `signature_rejected` otherwise —
 * plus an `Accept-Signature` advertisement of what this endpoint expects, when enabled.
 */
final class HttpSignatureException extends HttpException implements Responsable
{
    private ?string $acceptSignature = null;

    private ?string $keyId = null;

    private function __construct(private readonly SignatureRejection $reason)
    {
        parent::__construct(401, "The HTTP message signature was rejected ({$reason->value}).");
    }

    public static function rejected(SignatureRejection $reason, ?string $keyId = null): self
    {
        $exception = new self($reason);
        $exception->keyId = $keyId;

        return $exception;
    }

    public function reason(): SignatureRejection
    {
        return $this->reason;
    }

    public function keyId(): ?string
    {
        return $this->keyId;
    }

    public function advertising(?string $acceptSignature): self
    {
        $this->acceptSignature = $acceptSignature;

        return $this;
    }

    /**
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return $this->acceptSignature === null ? [] : ['Accept-Signature' => $this->acceptSignature];
    }

    /**
     * @param  Request  $request
     */
    public function toResponse($request): JsonResponse
    {
        $code = Config::boolean('app.debug') ? $this->reason->value : 'signature_rejected';

        return Problem::response(401, $code, $this->getHeaders(), 'signature_rejected');
    }
}
