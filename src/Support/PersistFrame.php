<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Database\Eloquent\Model;

/**
 * One sealed persist in flight ({@see SealingScope::persisting()}): the row it writes, and
 * whether a nested write of that same row joined it.
 *
 * @internal
 */
final class PersistFrame
{
    public bool $nested = false;

    public function __construct(public readonly Model $model) {}

    /**
     * The same row: same connection, table and key (the instance may differ — a listener can
     * load it afresh).
     */
    public function matches(Model $model): bool
    {
        return $this->model->exists
            && $this->model->getKey() !== null
            && (string) $this->model->getKey() === (string) $model->getKey()
            && $this->model->getTable() === $model->getTable()
            && $this->model->getConnection()->getName() === $model->getConnection()->getName();
    }
}
