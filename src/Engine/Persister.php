<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Engine;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\CompiledSeals;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Enums\PersistOperation;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;

/**
 * An Eloquent write and its sealing as one transaction (plan §9.4): the host's write and
 * every seal it implies commit together, and any sealing failure rolls the write back. Inside
 * an outer transaction this is a savepoint; the host's write is never retried.
 *
 * Before an update the row is locked and verified first (anti-laundering, D19): a row changed
 * outside the application is refused by default, so a later save can never silently re-seal
 * an unauthorised change. Benign drift is re-sealed (and audited): a changed definition
 * (`outdated`) and computed fields whose source rows changed (`c:*` only).
 *
 * @internal
 */
final readonly class Persister
{
    public function __construct(
        private DefinitionRegistry $registry,
        private Sealer $sealer,
        private Verifier $verifier,
        private ReadBack $readBack,
        private SealingScope $scope,
    ) {}

    public function persist(Model $model, Closure $write, PersistOperation $operation): mixed
    {
        $seals = $this->registry->for($model);
        $delete = $operation === PersistOperation::Delete;

        // A delete covers every seal — manual() ones too, which have rows and histories to
        // close; an unsaved model deletes nothing (Eloquent returns null), so it seals nothing.
        if (! Settings::autoSeal() || ($delete ? ! $model->exists : $seals->auto() === []) || $this->scope->sealingSuspended()) {
            return $write();
        }

        $existing = $model->exists;

        return $model->getConnection()->transaction(function () use ($model, $write, $operation, $seals, $existing): mixed {
            $previous = [];
            $skip = [];

            if ($existing) {
                // Lock order: the model row first, then its seal rows (in the verifier).
                $this->readBack->row($model, [], lock: true);

                foreach ($operation === PersistOperation::Delete ? $seals->all() : $seals->auto() as $seal) {
                    $this->precheck($model, $seal, $operation, $previous, $skip);
                }
            }

            $result = $write();

            if ($result === false) {
                return false;
            }

            match (true) {
                $operation === PersistOperation::Delete => $this->afterDelete($model, $seals, $previous, $skip),
                ! $existing => $this->afterCreate($model, $seals),
                default => $this->afterUpdate($model, $seals, $previous, $skip),
            };

            return $result;
        });
    }

    /**
     * Whether a pre-write verdict may be re-sealed without an acknowledgement.
     */
    public static function benign(VerificationResult $result): bool
    {
        return $result->isIntact() || $result->status === VerificationStatus::Outdated || $result->onlyComputedChanged();
    }

    /**
     * @param  array<string, VerificationStatus|true>  $previous
     * @param  array<string, true>  $skip
     */
    private function precheck(Model $model, CompiledSeal $seal, PersistOperation $operation, array &$previous, array &$skip): void
    {
        $verdict = $this->verifier->verify($model, $seal, VerificationContext::Write, Settings::checkLedger(), lock: true);

        if ($operation === PersistOperation::Delete) {
            // Deletes are never refused; the tombstone records what was deleted. A soft delete
            // only re-seals what was benign (it writes no tombstone that could keep evidence).
            $previous[$seal->name] = $verdict->status;

            if (! self::benign($verdict)) {
                $skip[$seal->name] = true;
            }

            return;
        }

        if (self::benign($verdict)) {
            // Re-seal drift even when no sealed column changes, and audit it.
            if (! $verdict->isIntact() || $verdict->status === VerificationStatus::Outdated) {
                $previous[$seal->name] = $verdict->isIntact() ? true : $verdict->status;
            }

            return;
        }

        match ($seal->policy()) {
            TamperedWritePolicy::Refuse => throw TamperedModelException::forResult($verdict),
            TamperedWritePolicy::Skip => $skip[$seal->name] = true,
            TamperedWritePolicy::Reseal => $previous[$seal->name] = $verdict->status,
        };
    }

    /**
     * @param  array<string, VerificationStatus|true>  $previous
     * @param  array<string, true>  $skip
     */
    private function afterUpdate(Model $model, CompiledSeals $seals, array $previous, array $skip): void
    {
        foreach ($seals->auto() as $seal) {
            if (isset($skip[$seal->name])) {
                continue;
            }

            if ($seal->hasComputed() || isset($previous[$seal->name]) || $model->wasChanged($seal->columns())) {
                $status = $previous[$seal->name] ?? null;

                $this->sealer->seal($model, $seal, SealEvent::Resealed, previousStatus: $status instanceof VerificationStatus ? $status : null);
            }
        }
    }

    private function afterCreate(Model $model, CompiledSeals $seals): void
    {
        foreach ($seals->auto() as $seal) {
            $head = $this->sealer->head($model, $seal->name);
            $recreated = Tables::seals($model, $seal->name)->exists()
                || ($head !== null && ! $this->sealer->endsHistory($model, $seal, $head));

            if (! $recreated) {
                $this->sealer->seal($model, $seal, SealEvent::Sealed);

                continue;
            }

            // The id was used before and its history never ended (an out-of-band delete).
            $verdict = new VerificationResult(
                VerificationStatus::Stale, 'entity_recreated', $model->getMorphClass(), $model->getKey(), $seal->name,
                context: VerificationContext::Write, outdatedIsIntact: Settings::outdatedIsIntact(),
            );
            $this->verifier->report($verdict);

            match ($seal->policy()) {
                TamperedWritePolicy::Refuse => throw TamperedModelException::forResult($verdict),
                TamperedWritePolicy::Skip => null,
                TamperedWritePolicy::Reseal => $this->sealer->seal($model, $seal, SealEvent::Sealed, previousStatus: VerificationStatus::Stale),
            };
        }
    }

    /**
     * @param  array<string, VerificationStatus|true>  $previous
     * @param  array<string, true>  $skip
     */
    private function afterDelete(Model $model, CompiledSeals $seals, array $previous, array $skip): void
    {
        $softDeleted = in_array(SoftDeletes::class, class_uses_recursive($model), true)
            && ! (method_exists($model, 'isForceDeleting') && $model->isForceDeleting());

        if (! $softDeleted) {
            foreach ($seals->all() as $seal) {
                $status = $previous[$seal->name] ?? null;
                $this->sealer->tombstone($model, $seal, SealEvent::Deleted, $status instanceof VerificationStatus ? $status : null);
            }

            return;
        }

        // A soft delete writes deleted_at (and updated_at) itself: re-seal what covers them.
        $touched = array_filter([
            method_exists($model, 'getDeletedAtColumn') ? $model->getDeletedAtColumn() : null,
            $model->usesTimestamps() ? $model->getUpdatedAtColumn() : null,
        ]);

        foreach ($seals->auto() as $seal) {
            if (! isset($skip[$seal->name]) && (array_intersect($touched, $seal->columns()) !== [] || $seal->hasComputed())) {
                $status = $previous[$seal->name] ?? null;
                $this->sealer->seal($model, $seal, SealEvent::Resealed, previousStatus: $status instanceof VerificationStatus && $status !== VerificationStatus::Intact ? $status : null);
            }
        }
    }
}
