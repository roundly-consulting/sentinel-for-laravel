<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\Sentinel\Http\Problem;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * A nonce or single-use URL was not accepted (403). Unknown, expired, used, foreign-purpose
 * and foreign-subject nonces are deliberately indistinguishable.
 */
final class NonceRejectedException extends HttpException implements Responsable
{
    public static function rejected(): self
    {
        $message = trans('sentinel::messages.problems.nonce_rejected.detail');

        return new self(403, is_string($message) ? $message : 'nonce_rejected');
    }

    /**
     * @param  Request  $request
     */
    public function toResponse($request): JsonResponse
    {
        return Problem::response(403, 'nonce_rejected');
    }
}
