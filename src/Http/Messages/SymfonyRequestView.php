<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Messages;

use Symfony\Component\HttpFoundation\Request;

/**
 * An incoming request. `@path` and `@query` come from the raw request target and
 * `QUERY_STRING` — never Symfony's decoded or re-sorted forms. Scheme, host and port follow
 * the TrustProxies configuration.
 *
 * @internal
 */
final readonly class SymfonyRequestView implements MessageView
{
    public function __construct(private Request $request) {}

    public function isRequest(): bool
    {
        return true;
    }

    public function method(): string
    {
        $method = $this->request->server->get('REQUEST_METHOD');

        return is_string($method) && $method !== '' ? $method : $this->request->getMethod();
    }

    /**
     * Symfony routes on getMethod(), which honours `X-HTTP-Method-Override` on every POST (and
     * `_method` when the parameter override is enabled, as Laravel does): `@method` covers the
     * wire method, so any difference means the signature does not cover what runs.
     */
    public function methodOverridden(): bool
    {
        $wire = $this->request->server->get('REQUEST_METHOD');

        return is_string($wire) && $wire !== '' && strtoupper($wire) !== $this->request->getMethod();
    }

    public function scheme(): string
    {
        return strtolower($this->request->getScheme());
    }

    public function authority(): string
    {
        return strtolower($this->request->getHttpHost());
    }

    public function path(): string
    {
        $target = $this->request->getRequestUri();
        $path = explode('?', $target, 2)[0];

        return $path === '' ? '/' : $path;
    }

    public function query(): string
    {
        $query = $this->request->server->get('QUERY_STRING');

        return is_string($query) ? $query : '';
    }

    public function status(): ?int
    {
        return null;
    }

    public function header(string $name): ?array
    {
        $lines = array_values(array_filter($this->request->headers->all(strtolower($name)), is_string(...)));

        return $lines === [] ? null : $lines;
    }

    public function body(): string
    {
        return $this->request->getContent();
    }
}
