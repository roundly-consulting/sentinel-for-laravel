<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Identifiers;

/**
 * The input names a model (its key, or the value of `column`) that must exist and be intact
 * — one seal, or every seal when none is named.
 *
 *     'invoice_id' => ['required', new IntactSeal(Invoice::class, seal: 'financial')],
 *
 * A missing model fails like `exists`; a model that is not intact fails with
 * `sentinel::validation.intact_seal` (no status or reason is revealed).
 */
final readonly class IntactSeal implements ValidationRule
{
    /**
     * @param  class-string<Model>  $model
     */
    public function __construct(
        private string $model,
        private ?string $seal = null,
        private ?string $column = null,
    ) {
        if ($column !== null && ! Identifiers::isColumn($column)) {
            throw SealingMisconfiguredException::invalidColumn($column);
        }
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $manager = app(SentinelManager::class);

        $model = is_int($value) || is_string($value)
            ? $manager->withoutVerification(fn (): ?Model => $this->column === null
                ? $this->model::query()->whereKey($value)->first()
                : $this->model::query()->where($this->column, $value)->first())
            : null;

        if (! $model instanceof Model) {
            $fail('validation.exists')->translate();

            return;
        }

        $results = $this->seal === null
            ? $manager->verifyManyIn(VerificationContext::Rule, [$model])->results
            : [$manager->verifyIn(VerificationContext::Rule, $model, $this->seal)];

        foreach ($results as $result) {
            if ($result->failed()) {
                $fail('sentinel::validation.intact_seal')->translate();

                return;
            }
        }
    }
}
