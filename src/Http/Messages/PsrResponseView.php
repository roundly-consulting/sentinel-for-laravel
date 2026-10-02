<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Messages;

use Psr\Http\Message\ResponseInterface;

/**
 * A received PSR-7 response (`@status` and its fields; no request-derived components).
 *
 * @internal
 */
final readonly class PsrResponseView implements MessageView
{
    public function __construct(private ResponseInterface $response) {}

    public function isRequest(): bool
    {
        return false;
    }

    public function method(): ?string
    {
        return null;
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
        $body = $this->response->getBody();
        $content = (string) $body;

        if ($body->isSeekable()) {
            $body->rewind();
        }

        return $content;
    }
}
