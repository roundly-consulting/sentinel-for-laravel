<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Closure;
use Illuminate\Database\Eloquent\Model;
use WeakMap;

/**
 * Suspension flags (`withoutSealing`, `withoutVerification`) and the models currently written
 * through the sealed write path. Bound **scoped**: Laravel drops it between Octane requests
 * and queued jobs, so a suspension can never leak into the next unit of work. Nesting-safe
 * counters, restored even when the callback throws.
 *
 * @internal
 */
final class SealingScope
{
    private int $sealingSuspended = 0;

    private int $verificationSuspended = 0;

    /** @var WeakMap<Model, int> */
    private WeakMap $writing;

    /** @var list<PersistFrame> */
    private array $persisting = [];

    public function __construct()
    {
        $this->writing = new WeakMap;
    }

    /**
     * Run a write of the model through the sealed path (`HasSeals::persistSealed()`); the
     * trait's `saving` / `deleting` guard refuses any write of a sealable model outside it.
     *
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function writing(Model $model, Closure $callback): mixed
    {
        $this->writing[$model] = ($this->writing[$model] ?? 0) + 1;

        try {
            return $callback();
        } finally {
            $depth = ($this->writing[$model] ?? 1) - 1;

            if ($depth > 0) {
                $this->writing[$model] = $depth;
            } else {
                unset($this->writing[$model]);
            }
        }
    }

    public function isWriting(Model $model): bool
    {
        return isset($this->writing[$model]);
    }

    /**
     * Run a sealed persist of the model, so a write of the same row from inside it (a model
     * listener saving it again) can join it instead of sealing on its own. The callback gets
     * whether such a write happened, by reference — read it after the host's write.
     *
     * @template T
     *
     * @param  Closure(bool): T  $callback
     * @return T
     */
    public function persisting(Model $model, Closure $callback): mixed
    {
        $frame = new PersistFrame($model);
        $this->persisting[] = $frame;

        try {
            return $callback($frame->nested);
        } finally {
            array_pop($this->persisting);
        }
    }

    /**
     * Whether a persist of the same row is in flight; if so, it is told it must re-seal. Only
     * rows that exist on both sides match — two new models of one class are not the same row.
     */
    public function joinPersist(Model $model): bool
    {
        if (! $model->exists || $model->getKey() === null) {
            return false;
        }

        foreach ($this->persisting as $frame) {
            if ($frame->matches($model)) {
                $frame->nested = true;

                return true;
            }
        }

        return false;
    }

    /**
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function withoutSealing(Closure $callback): mixed
    {
        $this->sealingSuspended++;

        try {
            return $callback();
        } finally {
            $this->sealingSuspended--;
        }
    }

    /**
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function withoutVerification(Closure $callback): mixed
    {
        $this->verificationSuspended++;

        try {
            return $callback();
        } finally {
            $this->verificationSuspended--;
        }
    }

    public function sealingSuspended(): bool
    {
        return $this->sealingSuspended > 0;
    }

    public function verificationSuspended(): bool
    {
        return $this->verificationSuspended > 0;
    }
}
