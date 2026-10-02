<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\PackageToolkit\Concerns\ProvidesRetryAfter;
use RoundlyConsulting\PackageToolkit\Contracts\HasRetryAfter;
use RoundlyConsulting\Sentinel\Enums\IdempotencyRejection;
use RoundlyConsulting\Sentinel\Http\Problem;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * An idempotent request was refused (draft-ietf-httpapi-idempotency-key-header-07). Renders
 * itself as RFC 9457 problem details with the rejection's status (400/422/409) and a
 * `Retry-After` when the key is still in flight. The same classes are thrown by
 * `Sentinel::idempotency()->run()`, where the status codes are irrelevant.
 */
abstract class IdempotencyException extends HttpException implements HasRetryAfter, Responsable
{
    use ProvidesRetryAfter;

    final protected function __construct(private readonly IdempotencyRejection $rejection)
    {
        $message = trans("sentinel::messages.problems.{$rejection->value}.detail");

        parent::__construct($rejection->status(), is_string($message) ? $message : $rejection->value);
    }

    public function rejection(): IdempotencyRejection
    {
        return $this->rejection;
    }

    /**
     * @param  Request  $request
     */
    public function toResponse($request): JsonResponse
    {
        return Problem::response(
            $this->rejection->status(),
            $this->rejection->value,
            $this->retryAfterSeconds() > 0 ? ['Retry-After' => (string) $this->retryAfterSeconds()] : [],
        );
    }

    /**
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return $this->retryAfterSeconds() > 0 ? ['Retry-After' => (string) $this->retryAfterSeconds()] : [];
    }
}
