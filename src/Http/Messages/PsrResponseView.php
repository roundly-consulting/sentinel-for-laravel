<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Messages;

use Psr\Http\Message\ResponseInterface;

/**
 * A received PSR-7 response (`@status` and its fields; no request-derived components).
 *
 * The body is read once and kept: a streamed (non-seekable) body cannot be read twice, and
 * verification needs it for the coverage check and the digest.
 *
 * @internal
 */
final class PsrResponseView implements MessageView
{
    private ?string $body = null;

    public function __construct(private readonly ResponseInterface $response) {}

    public function isRequest(): bool
    {
        return false;
    }

    public function method(): ?string
    {
        return null;
    }

    public function methodOverridden(): bool
    {
        return false;
    }

    public function scheme(): ?string
    {
        return null;
    }

    public function authority(): ?string
    {
        return null;
    }

    public function path(): ?string
    {
        return null;
    }

    public function query(): ?string
    {
        return null;
    }

    public function status(): int
    {
        return $this->response->getStatusCode();
    }

    public function header(string $name): ?array
    {
        $lines = $this->response->getHeader($name);

        return $lines === [] ? null : array_values($lines);
    }

    public function body(): string
    {
        if ($this->body !== null) {
            return $this->body;
        }

        $body = $this->response->getBody();
        $this->body = (string) $body;

        if ($body->isSeekable()) {
            $body->rewind();
        }

        return $this->body;
    }

    public function bodyUnavailable(): bool
    {
        return false;
    }
}
