<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Messages;

/**
 * An HTTP message as RFC 9421 sees it: the derived components and the raw field lines.
 * Request-only parts are null on a response, the status null on a request.
 *
 * @internal
 */
interface MessageView
{
    public function isRequest(): bool;

    /** The method as received. */
    public function method(): ?string;

    /**
     * Whether the application executes another method than the one received (Symfony's
     * `X-HTTP-Method-Override` / `_method` override) — never for an outgoing message.
     */
    public function methodOverridden(): bool;

    /** Lowercase scheme. */
    public function scheme(): ?string;

    /** Lowercase host, plus `:port` unless it is the scheme's default. */
    public function authority(): ?string;

    /** The raw (undecoded) path of the request target; `/` when empty. */
    public function path(): ?string;

    /** The raw query string without `?`; `''` when there is none. */
    public function query(): ?string;

    public function status(): ?int;

    /**
     * Every field line of a header (null when absent).
     *
     * @return list<string>|null
     */
    public function header(string $name): ?array;

    public function body(): string;

    /**
     * Whether the message has a body that {@see body()} cannot give: PHP parses a
     * `multipart/form-data` request into `$_POST` / `$_FILES` and leaves no raw bytes (while
     * `enable_post_data_reading` is on).
     */
    public function bodyUnavailable(): bool;
}
