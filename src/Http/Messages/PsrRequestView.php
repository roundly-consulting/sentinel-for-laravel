<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Messages;

use Psr\Http\Message\RequestInterface;

/**
 * An outgoing PSR-7 request (the Laravel HTTP client's), exactly as it will be sent.
 *
 * @internal
 */
final readonly class PsrRequestView implements MessageView
{
    private const array DEFAULT_PORTS = ['http' => 80, 'https' => 443];

    public function __construct(private RequestInterface $request) {}

    public function isRequest(): bool
    {
        return true;
    }

    public function method(): string
    {
        return $this->request->getMethod();
    }

    public function methodOverridden(): bool
    {
        return false;
    }

    public function scheme(): string
    {
        return strtolower($this->request->getUri()->getScheme());
    }

    public function authority(): string
    {
        $uri = $this->request->getUri();
        $port = $uri->getPort();
        $host = strtolower($uri->getHost());

        return $port === null || $port === (self::DEFAULT_PORTS[$this->scheme()] ?? null) ? $host : $host.':'.$port;
    }

    public function path(): string
    {
        $path = $this->request->getUri()->getPath();

        return $path === '' ? '/' : $path;
    }

    public function query(): string
    {
        return $this->request->getUri()->getQuery();
    }

    public function status(): ?int
    {
        return null;
    }

    public function header(string $name): ?array
    {
        $lines = $this->request->getHeader($name);

        return $lines === [] ? null : array_values($lines);
    }

    public function body(): string
    {
        $body = $this->request->getBody();
        $content = (string) $body;

        if ($body->isSeekable()) {
            $body->rewind();
        }

        return $content;
    }
}
