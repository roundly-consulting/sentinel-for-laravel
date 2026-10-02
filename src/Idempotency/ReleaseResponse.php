<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rolls a transactional idempotent request back while still answering with a response.
 *
 * @internal
 */
final class ReleaseResponse extends RuntimeException
{
    public function __construct(
        public readonly Response $response,
        public readonly bool $release = true,
    ) {
        parent::__construct('The idempotent request was rolled back.');
    }
}
