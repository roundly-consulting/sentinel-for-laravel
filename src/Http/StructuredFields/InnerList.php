<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\StructuredFields;

/**
 * An RFC 9651 Inner List: `(item item …)` with parameters — e.g. a covered-components list.
 *
 * @internal
 */
final readonly class InnerList
{
    /**
     * @param  list<Item>  $items
     */
    public function __construct(
        public array $items,
        public Parameters $parameters = new Parameters,
    ) {}
}
