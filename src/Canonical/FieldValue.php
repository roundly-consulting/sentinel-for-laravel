<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Canonical;

/**
 * One canonical field tuple of a seal document: `[name, tag, value]`, where `name` is
 * `a:<column>` or `c:<computed>`, `tag` the runtime tag and `value` the canonical string or
 * null.
 *
 * @internal
 */
final readonly class FieldValue
{
    public function __construct(
        public string $name,
        public string $tag,
        public ?string $value,
    ) {}

    /**
     * @return list<string|null>
     */
    public function tuple(): array
    {
        return [$this->name, $this->tag, $this->value];
    }
}
