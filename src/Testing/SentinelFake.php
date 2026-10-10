<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Testing;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Client\Response as ClientResponse;
use Illuminate\Http\Request;
use PHPUnit\Framework\Assert as PHPUnit;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RoundlyConsulting\Sentinel\Actions\Idempotency\CompleteIdempotentRequestAction;
use RoundlyConsulting\Sentinel\Actions\Idempotency\ForgetIdempotencyKeyAction;
use RoundlyConsulting\Sentinel\Actions\Idempotency\RunIdempotentAction;
use RoundlyConsulting\Sentinel\Actions\Nonces\ConsumeNonceAction;
use RoundlyConsulting\Sentinel\Actions\Nonces\IssueNonceAction;
use RoundlyConsulting\Sentinel\Actions\Nonces\IssueSingleUseUrlAction;
use RoundlyConsulting\Sentinel\Actions\Nonces\RememberNonceAction;
use RoundlyConsulting\Sentinel\Actions\PruneAction;
use RoundlyConsulting\Sentinel\Contracts\AcknowledgementPolicy;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgementResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\BaselineOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\ConsumeNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\GeneratedKey;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotencyDecision;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\ImportKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssuedNonce;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssueNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealWhereRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotationResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\SignedRouteRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\StatusCount;
use RoundlyConsulting\Sentinel\DataTransferObjects\UpdateAndResealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\CompiledSeals;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Persister;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\PersistOperation;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Exceptions\SealingSuspensionNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Exceptions\UnknownKeyException;
use RoundlyConsulting\Sentinel\Http\Signatures\ProfileResolver;
use RoundlyConsulting\Sentinel\Keys\EnvSnippet;
use RoundlyConsulting\Sentinel\Keys\ImportedMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyIds;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\RingConfig;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\BulkQuery;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use RoundlyConsulting\Sentinel\Support\Reasons;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;
use SensitiveParameter;
use Symfony\Component\HttpFoundation\Response;

/**
 * The test double installed by `Sentinel::fake()`. It extends the manager, so injected
 * managers keep type-checking, and records every call — including those made through the
 * `HasSeals` trait and the sub-accessors — instead of touching keys, seals or the ledger.
 *
 * Same semantics where it matters (fleet theme 7): definitions are compiled by the real
 * registry, the configured tampered-write policy applies to faked statuses (so `refuse`
 * throws as in production), reasons/actors/the acknowledgement policy and the suspension
 * switch are enforced, and unknown rings or seals throw what production throws. Verification
 * defaults to `intact`; script it with `fakeStatus()` / `fakeStatusOnce()`. Fires no events.
 */
final class SentinelFake extends SentinelManager
{
    /** The bulk re-seal verbs. */
    private const array BULK = ['reseal', 'resealWhere', 'updateAndReseal', 'sealMissing'];

    /** @var list<RecordedCall> */
    private array $calls = [];

    /** @var array<string, FakedStatus> */
    private array $sticky = [];

    /** @var array<string, list<FakedStatus>> */
    private array $once = [];

    private readonly InMemoryIdempotencyStore $idempotencyStore;

    private readonly InMemoryNonceStore $nonceStore;

    private ?VerifiedSignature $signature = null;

    private ?SignatureRejection $rejection = null;

    /** @var array<string, KeyInfo> keys the fake generated or imported, by "ring\0kid" */
    private array $keys = [];

    /** @var list<LedgerFinding> */
    private array $ledgerFindings = [];

    public function __construct(Container $container)
    {
        parent::__construct($container);

        $this->idempotencyStore = new InMemoryIdempotencyStore;
        $this->nonceStore = new InMemoryNonceStore;
    }

    // ── controls ──────────────────────────────────────────────────────────────

    /**
     * Every verification of the model (one seal, or all when null) returns this status until
     * changed — or until the fake re-seals or acknowledges that seal, which leaves it intact,
     * as in production.
     *
     * The reason defaults to what production reports most often: `seal_deleted` for `missing`
     * (which `seal()` refuses — script `never_sealed` for a row that was never sealed),
     * `computed` for `tampered` with only `c:*` changes and `mac` for any other `tampered`.
     *
     * @param  list<string>|null  $changed
     */
    public function fakeStatus(Model $model, VerificationStatus $status, ?string $seal = null, ?array $changed = null, ?string $reason = null): static
    {
        if ($seal === null) {
            // A status for every seal replaces what was scripted or settled per seal.
            $prefix = $this->identity($model, '');

            foreach (array_keys($this->sticky) as $identity) {
                if (str_starts_with($identity, $prefix)) {
                    unset($this->sticky[$identity]);
                }
            }
        }

        $this->sticky[$this->identity($model, $seal)] = new FakedStatus($status, $changed, $reason);

        return $this;
    }

    /**
     * The next verification of the model (one seal, or any when null) returns this status
     * (reasons default as for {@see fakeStatus()}).
     *
     * @param  list<string>|null  $changed
     */
    public function fakeStatusOnce(Model $model, VerificationStatus $status, ?string $seal = null, ?array $changed = null, ?string $reason = null): static
    {
        $this->once[$this->identity($model, $seal)][] = new FakedStatus($status, $changed, $reason);

        return $this;
    }

    /**
     * Every signature verification returns this signature (null = a synthetic one, key `fake`).
     */
    public function fakeVerifiedSignature(?VerifiedSignature $signature = null): static
    {
        $this->signature = $signature;
        $this->rejection = null;

        return $this;
    }

    /**
     * Every signature verification is rejected for this reason (401, as in production).
     */
    public function rejectSignatures(SignatureRejection $reason): static
    {
        $this->rejection = $reason;

        return $this;
    }

    /**
     * Every ledger verification reports these findings (with the real `clean()`,
     * `violations()` and `throwIfViolated()` semantics) until called again — with none to
     * go back to a clean ledger.
     */
    public function fakeLedgerFindings(LedgerFinding ...$findings): static
    {
        $this->ledgerFindings = array_values($findings);

        return $this;
    }

    // ── seals ─────────────────────────────────────────────────────────────────

    public function seal(Model $model, ?string $seal = null, ?string $reason = null, ?Model $actor = null): SealResult
    {
        $compiled = $this->compiled($model, $seal);

        if (! $model->exists) {
            throw SealingFailedException::notPersisted($model->getMorphClass());
        }

        $verdict = $this->faked($model, $compiled, VerificationContext::Api);
        $absent = $verdict->status === VerificationStatus::Unsealed
            || ($verdict->status === VerificationStatus::Missing && $verdict->reason === 'never_sealed');

        if (! $absent && ! Persister::benign($verdict)) {
            throw TamperedModelException::forResult($verdict);
        }

        return $this->recordSeal($model, $compiled, $absent ? SealEvent::Sealed : SealEvent::Resealed, $reason, $actor);
    }

    public function verify(Model $model, ?string $seal = null): VerificationResult
    {
        $compiled = $this->compiled($model, $seal);

        return $this->record('verify', [$model, $compiled->name], $this->faked($model, $compiled, VerificationContext::Api));
    }

    public function verifyIn(VerificationContext $context, Model $model, ?string $seal = null): VerificationResult
    {
        $compiled = $this->compiled($model, $seal);

        return $this->record('verify', [$model, $compiled->name], $this->faked($model, $compiled, $context));
    }

    /**
     * @param  iterable<Model>  $models
     */
    public function verifyManyIn(VerificationContext $context, iterable $models, ?string $seal = null): VerificationReport
    {
        $results = [];

        foreach ($models as $model) {
            $names = $seal === null ? $this->container->make(DefinitionRegistry::class)->for($model)->names() : [$seal];

            foreach ($names as $name) {
                $results[] = $this->verifyIn($context, $model, $name);
            }
        }

        return new VerificationReport($results);
    }

    public function verifyAll(Model $model): VerificationReport
    {
        return new VerificationReport(array_map(
            fn (string $seal): VerificationResult => $this->verify($model, $seal),
            $this->container->make(DefinitionRegistry::class)->for($model)->names(),
        ));
    }

    public function acknowledge(Model $model, string $reason, ?Model $actor = null, ?string $seal = null): AcknowledgementResult
    {
        $compiled = $this->compiled($model, $seal);
        $reason = Reasons::normalize($reason);
        $request = new AcknowledgeRequest($model, $compiled->name, $reason, $this->container->make(Runtime::class)->actor($actor));
        $denial = $this->container->make(AcknowledgementPolicy::class)->authorize($request);

        if ($denial !== null) {
            throw AcknowledgementDeniedException::unauthorized($denial);
        }

        $before = $this->faked($model, $compiled, VerificationContext::Api);

        if ($before->isIntact()) {
            return $this->record('acknowledge', [$model, $compiled->name, $reason, $request->actor], new AcknowledgementResult(false, $before));
        }

        $this->settle($model, $compiled->name);

        return $this->record('acknowledge', [$model, $compiled->name, $reason, $request->actor], new AcknowledgementResult(
            true, $before, $this->synthetic($model, $compiled, SealEvent::Acknowledged),
        ));
    }

    public function unseal(Model $model, string $reason, ?Model $actor = null, ?string $seal = null): bool
    {
        $compiled = $this->compiled($model, $seal);
        $reason = Reasons::normalize($reason);
        $request = new AcknowledgeRequest($model, $compiled->name, $reason, $this->container->make(Runtime::class)->actor($actor));
        $denial = $this->container->make(AcknowledgementPolicy::class)->authorize($request);

        if ($denial !== null) {
            throw AcknowledgementDeniedException::unauthorized($denial);
        }

        // As in production: a strict seal is then missing (and comes back through
        // acknowledge()), a lenient one unsealed.
        $this->sticky[$this->identity($model, $compiled->name)] = $compiled->strict
            ? new FakedStatus(VerificationStatus::Missing, null, 'unsealed')
            : new FakedStatus(VerificationStatus::Unsealed, null);

        return $this->record('unseal', [$model, $compiled->name, $reason, $request->actor], true);
    }

    /**
     * @return list<LedgerRecord>
     */
    public function ledgerHistory(Model $model, ?string $seal = null, int $limit = 50): array
    {
        $this->compiled($model, $seal);

        return [];
    }

    public function currentSeal(Model $model, ?string $seal = null): ?SealRecord
    {
        $this->compiled($model, $seal);

        return null;
    }

    public function withoutSealing(Closure $callback, string $reason): mixed
    {
        if (! Settings::allowSuspension()) {
            throw SealingSuspensionNotAllowedException::disabled();
        }

        $this->record('withoutSealing', [Reasons::normalize($reason)], null);

        return $this->container->make(SealingScope::class)->withoutSealing($callback);
    }

    /**
     * @internal the HasSeals write path: runs the host write, records the seals it implies and
     * applies the tampered-write policy to faked statuses.
     */
    public function persist(Model $model, Closure $write, PersistOperation $operation): mixed
    {
        $seals = $this->container->make(DefinitionRegistry::class)->for($model);
        $scope = $this->container->make(SealingScope::class);

        if (! Settings::autoSeal() || $seals->auto() === [] || $scope->sealingSuspended()) {
            return $write();
        }

        // As in production: a write of the same row from inside this one joins it.
        if ($operation !== PersistOperation::Delete && $scope->joinPersist($model)) {
            return $write();
        }

        return $scope->persisting($model, fn (bool &$nested): mixed => $this->persistFaked($model, $write, $operation, $seals, $nested));
    }

    private function persistFaked(Model $model, Closure $write, PersistOperation $operation, CompiledSeals $seals, bool &$nested): mixed
    {
        $existing = $model->exists;
        $skip = [];
        $previous = [];

        if ($existing && $operation !== PersistOperation::Delete) {
            foreach ($seals->auto() as $seal) {
                $verdict = $this->faked($model, $seal, VerificationContext::Write);

                if (Persister::benign($verdict)) {
                    continue;
                }

                match ($seal->policy()) {
                    TamperedWritePolicy::Refuse => throw TamperedModelException::forResult($verdict),
                    TamperedWritePolicy::Skip => $skip[$seal->name] = true,
                    TamperedWritePolicy::Reseal => $previous[$seal->name] = true,
                };
            }
        }

        $result = $write();

        if ($result === false || $operation === PersistOperation::Delete) {
            return $result;
        }

        // As in production: increment() writes updated_at in the SQL only.
        $touched = $operation === PersistOperation::Increment && $model->usesTimestamps() ? array_filter([$model->getUpdatedAtColumn()]) : [];

        foreach ($seals->auto() as $seal) {
            if (! $existing) {
                $this->recordSeal($model, $seal, SealEvent::Sealed);
            } elseif (! isset($skip[$seal->name]) && ($nested || $seal->hasComputed() || isset($previous[$seal->name]) || $model->wasChanged($seal->columns())
                || array_intersect($touched, $seal->columns()) !== [])) {
                $this->recordSeal($model, $seal, SealEvent::Resealed);
            }
        }

        return $result;
    }

    /**
     * @internal the verify-on-retrieve hook: faked statuses, the real reactions (`throw`
     * throws), suspension honoured.
     */
    public function retrieved(Model $model): void
    {
        $scope = $this->container->make(SealingScope::class);

        if ($scope->verificationSuspended()) {
            return;
        }

        foreach ($this->container->make(DefinitionRegistry::class)->for($model)->all() as $seal) {
            if (! $seal->verifiesOnRetrieve) {
                continue;
            }

            $result = $this->record('verify', [$model, $seal->name], $this->faked($model, $seal, VerificationContext::Retrieve));

            if ($result->failed() && ($seal->retrieveReaction ?? Settings::retrieveReaction()) === Reaction::Throw) {
                throw TamperedModelException::forResult($result);
            }
        }
    }

    // ── bulk ──────────────────────────────────────────────────────────────────

    /**
     * Faked statuses over every row of the models — or the rows a `where` selects (the rows are
     * read; nothing is written). Progress is reported per chunk, as in production.
     */
    public function scan(ScanOptions $options): ScanReport
    {
        if ($options->where !== null && count($options->models) !== 1) {
            throw SealingMisconfiguredException::whereNeedsOneModel();
        }

        $counts = [];
        $findings = [];
        $scanned = 0;
        $processed = 0;

        foreach ($options->models as $class) {
            $compiled = $this->container->make(DefinitionRegistry::class)->for($class);
            $seals = $options->seal === null ? $compiled->all() : [$compiled->get($options->seal)];
            $base = $class::query()->withoutGlobalScopes();
            $query = $options->where === null ? $base : BulkQuery::resolve($class, $options->where, $base);
            $rows = $this->rows($query->reorder(), $options->limit === null ? null : max(0, $options->limit - $processed));

            foreach ($rows as $index => $model) {
                $processed++;

                foreach ($seals as $seal) {
                    $result = $this->faked($model, $seal, VerificationContext::Command);
                    $scanned++;
                    $counts[$result->status->value] = ($counts[$result->status->value] ?? 0) + 1;

                    if ($result->failed() && count($findings) < $options->maxFindings) {
                        $findings[] = $result;
                    }
                }

                if ($options->progress !== null && (($index + 1) % max(1, $options->chunk) === 0 || $index === count($rows) - 1)) {
                    ($options->progress)($processed);
                }
            }
        }

        $list = [];

        foreach (VerificationStatus::cases() as $status) {
            if (isset($counts[$status->value])) {
                $list[] = new StatusCount($status, $counts[$status->value]);
            }
        }

        return $this->record('scan', $options, new ScanReport($scanned, $list, $findings, false, Settings::outdatedIsIntact()));
    }

    /**
     * Intact and outdated rows count as re-sealed (the fake holds no keys, so it cannot tell a
     * row already on the current key); the others are skipped — or acknowledged.
     */
    public function reseal(ResealOptions $options): ResealReport
    {
        $compiled = $this->container->make(DefinitionRegistry::class)->for($options->model);
        $seals = $options->seal === null ? $compiled->all() : [$compiled->get($options->seal)];
        $reason = $options->acknowledgeReason === null ? null : Reasons::normalize($options->acknowledgeReason);
        $resealed = $acknowledged = 0;
        $skipped = [];
        $rows = $this->rows($options->model::query()->withoutGlobalScopes());

        foreach ($rows as $index => $model) {
            foreach ($seals as $seal) {
                $verdict = $this->faked($model, $seal, VerificationContext::Command);

                match (true) {
                    $verdict->status === VerificationStatus::Unsealed => null,
                    $verdict->status === VerificationStatus::Intact, $verdict->status === VerificationStatus::Outdated => $resealed++,
                    $reason !== null => $acknowledged += $options->dryRun ? 1 : (int) $this->acknowledge($model, $reason, $options->actor, $seal->name)->acknowledged,
                    default => $skipped[] = $verdict,
                };
            }

            $this->progress($options->progress, $index, count($rows), $options->chunk);
        }

        return $this->record('reseal', $options, new ResealReport($resealed, $acknowledged, count($skipped), 0, $skipped, $options->dryRun));
    }

    public function resealWhere(ResealWhereRequest $request): ResealReport
    {
        $compiled = $this->container->make(DefinitionRegistry::class)->for($request->model);
        $seals = $request->seal === null ? $compiled->all() : [$compiled->get($request->seal)];
        $reason = Reasons::normalize($request->reason);
        $actor = $this->container->make(Runtime::class)->actor($request->actor);
        $acknowledged = $skipped = 0;

        foreach ($this->rows(BulkQuery::resolve($request->model, $request->query)) as $model) {
            foreach ($seals as $seal) {
                $this->acknowledge($model, $reason, $actor, $seal->name)->acknowledged ? $acknowledged++ : $skipped++;
            }
        }

        return $this->record('resealWhere', $request, new ResealReport(acknowledged: $acknowledged, skipped: $skipped));
    }

    /**
     * The real refusal (any faked non-intact row → nothing written), then the host's update.
     */
    public function updateAndReseal(UpdateAndResealRequest $request): ResealReport
    {
        foreach (array_keys($request->values) as $column) {
            if (! Identifiers::isColumn($column)) {
                throw SealingMisconfiguredException::invalidColumn($column);
            }
        }

        $seals = $this->container->make(DefinitionRegistry::class)->for($request->model)->all();
        Reasons::normalize($request->reason);
        $this->container->make(Runtime::class)->actor($request->actor);
        $models = $this->rows(BulkQuery::resolve($request->model, $request->query));
        $failures = [];

        foreach ($models as $model) {
            foreach ($seals as $seal) {
                $verdict = $this->faked($model, $seal, VerificationContext::Api);

                if ($verdict->failed()) {
                    $failures[] = $verdict;
                }
            }
        }

        if ($failures !== []) {
            throw TamperedModelException::many($failures);
        }

        $keys = array_map(static fn (Model $model): mixed => $model->getKey(), $models);

        if ($keys !== []) {
            $request->model::query()->withoutGlobalScopes()->whereKey($keys)->update($request->values);
        }

        return $this->record('updateAndReseal', $request, new ResealReport(resealed: count($models)));
    }

    /**
     * Nothing is sealed under the fake, so every row is adopted — except rows faked as
     * `missing`, which (as in production, where their history shows a seal) are reported.
     */
    public function sealMissing(BaselineOptions $options): ResealReport
    {
        $compiled = $this->container->make(DefinitionRegistry::class)->for($options->model);
        $seals = $options->seal === null ? $compiled->all() : [$compiled->get($options->seal)];
        Reasons::normalize($options->reason);
        $this->container->make(Runtime::class)->actor($options->actor);
        $resealed = 0;
        $skipped = [];
        $rows = $this->rows($options->model::query()->withoutGlobalScopes());

        foreach ($rows as $index => $model) {
            foreach ($seals as $seal) {
                $verdict = $this->faked($model, $seal, VerificationContext::Command);
                // A row with history (anything but never sealed) is reported, never baselined.
                $verdict->status === VerificationStatus::Missing && $verdict->reason !== 'never_sealed' ? $skipped[] = $verdict : $resealed++;
            }

            $this->progress($options->progress, $index, count($rows), $options->chunk);
        }

        return $this->record('sealMissing', $options, new ResealReport(resealed: $resealed, skipped: count($skipped), skippedResults: $skipped));
    }

    // ── ledger ────────────────────────────────────────────────────────────────

    /**
     * Records the run; the fake keeps no ledger, so there is never anything to fold.
     */
    public function checkpoint(?CheckpointOptions $options = null): ?CheckpointResult
    {
        $options ??= new CheckpointOptions;

        if ($options->batchSize !== null && ($options->batchSize < 1 || $options->batchSize > 100000)) {
            throw InvalidSentinelConfigurationException::invalidValue('ledger.batch_size', 'must be between 1 and 100000');
        }

        return $this->record('checkpoint', $options, null);
    }

    public function verifyLedger(?LedgerVerifyOptions $options = null): LedgerReport
    {
        $options ??= new LedgerVerifyOptions;

        return $this->record('verifyLedger', $options, new LedgerReport(0, 0, 0, $this->ledgerFindings));
    }

    public function ledgerHead(?string $connection = null): ?CheckpointRecord
    {
        return null;
    }

    // ── idempotency / nonces ──────────────────────────────────────────────────

    /**
     * The real action over the in-memory store: replay, 409 and 422 behave as in production.
     */
    public function runIdempotent(IdempotentCall $call): IdempotentResult
    {
        $result = null;

        try {
            return $result = $this->container->make(RunIdempotentAction::class, ['store' => $this->idempotencyStore])->execute($call);
        } finally {
            $this->record('runIdempotent', $call, $result);
        }
    }

    public function forgetIdempotencyKey(string $key, string $scope): bool
    {
        return $this->record('forgetIdempotencyKey', [$key, $scope], $this->container->make(ForgetIdempotencyKeyAction::class, ['store' => $this->idempotencyStore])->execute($key, $scope));
    }

    public function issueNonce(IssueNonceRequest $request): IssuedNonce
    {
        return $this->record('issueNonce', $request, $this->container->make(IssueNonceAction::class, ['store' => $this->nonceStore])->execute($request));
    }

    public function consumeNonce(ConsumeNonceRequest $request): bool
    {
        return $this->record('consumeNonce', $request, $this->container->make(ConsumeNonceAction::class, ['store' => $this->nonceStore])->execute($request));
    }

    public function signedRoute(SignedRouteRequest $request): string
    {
        return $this->record('signedRoute', $request, $this->container->make(IssueSingleUseUrlAction::class, ['manager' => $this])->execute($request));
    }

    public function prune(?PruneOptions $options = null): PruneResult
    {
        $options ??= new PruneOptions;

        return $this->record('prune', $options, $this->container->make(PruneAction::class, ['idempotency' => $this->idempotencyStore, 'nonces' => $this->nonceStore])->execute($options));
    }

    /**
     * @internal the `sentinel.idempotent` middleware, over the in-memory store
     */
    public function beginIdempotentRequest(IdempotentRequest $request): IdempotencyDecision
    {
        return $this->record('beginIdempotentRequest', $request, $this->idempotencyStore->begin($request));
    }

    /**
     * @internal
     */
    public function completeIdempotentRequest(IdempotentRequest $request, Response $response): bool
    {
        return $this->container->make(CompleteIdempotentRequestAction::class, ['store' => $this->idempotencyStore])->execute($request, $response);
    }

    /**
     * @internal
     */
    public function releaseIdempotentRequest(IdempotentRequest $request): void
    {
        $this->idempotencyStore->release($request);
    }

    /**
     * @internal
     */
    public function rememberNonce(string $purpose, #[SensitiveParameter] string $nonce, CarbonImmutable $until): bool
    {
        return $this->container->make(RememberNonceAction::class, ['store' => $this->nonceStore])->execute($purpose, $nonce, $until);
    }

    // ── HTTP message signatures ───────────────────────────────────────────────

    /**
     * Records the request and returns it unsigned (the fake holds no key material).
     */
    public function signRequest(RequestInterface $request, string $keyId, ?SigningOptions $options = null): RequestInterface
    {
        return $this->record('signRequest', [$request, $keyId, $options], $request);
    }

    public function verifyRequestSignature(Request $request, ?string $profile = null): VerifiedSignature
    {
        return $this->fakedSignature('verifyRequestSignature', $request, $profile);
    }

    public function verifyResponseSignature(ResponseInterface|ClientResponse $response, ?string $profile = null): VerifiedSignature
    {
        return $this->fakedSignature('verifyResponseSignature', $response, $profile);
    }

    // ── keys ──────────────────────────────────────────────────────────────────

    /**
     * Production's checks and material (nothing stored): an overlong label, a taken kid or a
     * database key in a config-only ring are refused as in production, and a config key comes
     * with its environment lines.
     */
    public function generateKey(GenerateKeyRequest $request): GeneratedKey
    {
        $config = Settings::ring($request->ring);

        if (! $config->allows($request->algorithm)) {
            throw AlgorithmNotAllowedException::forRing($request->ring, $request->algorithm);
        }

        $keyId = $request->keyId ?? KeyIds::generate($request->ring);

        if (! Identifiers::isKeyId($keyId)) {
            throw KeyDriverException::invalidKeyId($request->ring);
        }

        if ($request->label !== null && mb_strlen($request->label) > 191) {
            throw KeyDriverException::invalidLabel();
        }

        if ($this->fakedKey($request->ring, $keyId) !== null) {
            throw KeyDriverException::keyIdTaken($request->ring, $keyId);
        }

        if ($request->destination === KeyDestination::Database && ! self::writable($config)) {
            throw KeyDriverException::readOnly($request->ring);
        }

        $material = KeyMaterial::generate($request->algorithm);
        $config = $request->destination === KeyDestination::Config;
        $info = new KeyInfo(
            $request->ring, $keyId, $request->algorithm, KeyStatus::Active, $request->destination->value, true,
            $config ? null : ($request->activatesAt ?? Clock::now()), label: $config ? null : $request->label,
        );
        $this->keys["{$request->ring}\0{$keyId}"] = $info;

        return $this->record('generateKey', $request, new GeneratedKey(
            $info, $config ? EnvSnippet::forKey($request->ring, $keyId, $material) : null, $material->encodedPublic(),
        ));
    }

    /**
     * The production validation and parsing (pure — nothing stored): an import that would be
     * refused in production is refused here with the same exception.
     */
    public function importKey(ImportKeyRequest $request): KeyInfo
    {
        $config = Settings::ring($request->ring);

        if (! $config->allows($request->algorithm)) {
            throw AlgorithmNotAllowedException::forRing($request->ring, $request->algorithm);
        }

        if (! Identifiers::isKeyId($request->keyId)) {
            throw KeyDriverException::invalidKeyId($request->ring);
        }

        if ($request->label !== null && mb_strlen($request->label) > 191) {
            throw KeyDriverException::invalidLabel();
        }

        if (! self::writable($config)) {
            throw KeyDriverException::readOnly($request->ring);
        }

        $material = ImportedMaterial::parse($request->algorithm, $request->material, $request->signing);
        $signing = $request->signing && $material->canSign();
        $info = new KeyInfo(
            $request->ring, $request->keyId, $request->algorithm, $signing ? KeyStatus::Active : KeyStatus::VerifyOnly, 'database', $signing,
            $request->activatesAt ?? Clock::now(), label: $request->label, ownerType: $request->owner?->getMorphClass(), ownerId: $request->owner?->getKey(),
        );
        $this->keys["{$request->ring}\0{$request->keyId}"] = $info;

        return $this->record('importKey', $request, $info);
    }

    public function rotateKey(RotateKeyRequest $request): RotationResult
    {
        $config = Settings::ring($request->ring);
        $algorithm = $request->algorithm ?? $config->algorithm;

        if (! $config->allows($algorithm)) {
            throw AlgorithmNotAllowedException::forRing($request->ring, $algorithm);
        }

        $result = new RotationResult(new KeyInfo(
            $request->ring, KeyIds::generate($request->ring), $algorithm, KeyStatus::Active, $config->driver, true, $request->activatesAt,
        ));
        $this->keys["{$request->ring}\0{$result->current->keyId}"] = $result->current;

        return $this->record('rotateKey', $request, $result);
    }

    public function revokeKey(RevokeKeyRequest $request): KeyInfo
    {
        Settings::ring($request->ring);
        $reason = trim($request->reason);

        if ($reason === '' || mb_strlen($reason) > 1000) {
            throw KeyDriverException::reasonRequired();
        }

        $key = $this->storedKey($request->ring, $request->keyId);

        return $this->record('revokeKey', $request, $this->keys["{$request->ring}\0{$request->keyId}"] = new KeyInfo(
            $request->ring, $request->keyId, $key->algorithm, KeyStatus::Revoked, 'database', false,
            $key->activatesAt, label: $key->label, ownerType: $key->ownerType, ownerId: $key->ownerId,
        ));
    }

    public function retireKey(string $ring, string $keyId): KeyInfo
    {
        Settings::ring($ring);
        $key = $this->storedKey($ring, $keyId);

        // A revoked key stays revoked: revocation beats every other status, as in production.
        return $this->record('retireKey', [$ring, $keyId], $this->keys["{$ring}\0{$keyId}"] = new KeyInfo(
            $ring, $keyId, $key->algorithm, $key->status === KeyStatus::Revoked ? KeyStatus::Revoked : KeyStatus::Retired, 'database', false,
            $key->activatesAt, label: $key->label, ownerType: $key->ownerType, ownerId: $key->ownerId,
        ));
    }

    /**
     * A key the fake generated or imported, else one the application's real key store holds
     * (read only — the fake never writes it).
     */
    private function fakedKey(string $ring, string $keyId): ?KeyInfo
    {
        if (isset($this->keys["{$ring}\0{$keyId}"])) {
            return $this->keys["{$ring}\0{$keyId}"];
        }

        $key = $this->container->make(KeyStoreManager::class)->find($ring, $keyId);

        return $key === null ? null : KeyInfo::fromKey($key);
    }

    /**
     * As production: an unknown kid is unknown, a key outside the database is read only.
     */
    private function storedKey(string $ring, string $keyId): KeyInfo
    {
        $key = $this->fakedKey($ring, $keyId) ?? throw UnknownKeyException::inRing($ring, $keyId);

        return $key->driver === 'database' ? $key : throw KeyDriverException::notStoredInDatabase($ring, $keyId);
    }

    private static function writable(RingConfig $config): bool
    {
        return in_array('database', $config->driver === 'chain' ? $config->drivers : [$config->driver], true);
    }

    // ── assertions ────────────────────────────────────────────────────────────

    /**
     * @param  (Closure(SealResult): bool)|null  $callback
     */
    public function assertSealed(Model $model, ?string $seal = null, ?Closure $callback = null): void
    {
        $matching = array_filter(
            $this->callsFor('seal', $model, $seal),
            static fn (RecordedCall $call): bool => $callback === null || ($call->result instanceof SealResult && $callback($call->result)),
        );

        PHPUnit::assertNotEmpty($matching, $this->describe('to be sealed', $model, $seal).($callback === null ? '' : ' with a matching result'));
    }

    public function assertNotSealed(Model $model, ?string $seal = null): void
    {
        PHPUnit::assertEmpty($this->callsFor('seal', $model, $seal), $this->describe('not to be sealed', $model, $seal));
    }

    public function assertNothingSealed(): void
    {
        $count = count($this->recorded('seal'));

        PHPUnit::assertSame(0, $count, "Expected nothing to be sealed, but {$count} seal(s) were recorded.");
    }

    public function assertVerified(Model $model, ?string $seal = null): void
    {
        PHPUnit::assertNotEmpty($this->callsFor('verify', $model, $seal), $this->describe('to be verified', $model, $seal));
    }

    public function assertNothingVerified(): void
    {
        $count = count($this->recorded('verify'));

        PHPUnit::assertSame(0, $count, "Expected nothing to be verified, but {$count} verification(s) were recorded.");
    }

    public function assertNotVerified(Model $model, ?string $seal = null): void
    {
        PHPUnit::assertEmpty($this->callsFor('verify', $model, $seal), $this->describe('not to be verified', $model, $seal, 'it was'));
    }

    public function assertAcknowledged(Model $model, ?string $reason = null): void
    {
        $matching = array_filter(
            $this->callsFor('acknowledge', $model, null),
            static fn (RecordedCall $call): bool => $call->result instanceof AcknowledgementResult && $call->result->acknowledged
                && ($reason === null || (is_array($call->arguments) && ($call->arguments[2] ?? null) === $reason)),
        );

        PHPUnit::assertNotEmpty($matching, $this->describe('to be acknowledged', $model, null).($reason === null ? '' : " with reason [{$reason}]"));
    }

    public function assertNotAcknowledged(Model $model): void
    {
        $matching = array_filter($this->callsFor('acknowledge', $model, null), static fn (RecordedCall $call): bool => $call->result instanceof AcknowledgementResult && $call->result->acknowledged);

        PHPUnit::assertEmpty($matching, $this->describe('not to be acknowledged', $model, null, 'it was'));
    }

    public function assertNothingAcknowledged(): void
    {
        $count = count(array_filter($this->recorded('acknowledge'), static fn (RecordedCall $call): bool => $call->result instanceof AcknowledgementResult && $call->result->acknowledged));

        PHPUnit::assertSame(0, $count, "Expected nothing to be acknowledged, but {$count} acknowledgement(s) were recorded.");
    }

    public function assertUnsealed(Model $model, ?string $seal = null): void
    {
        PHPUnit::assertNotEmpty($this->callsFor('unseal', $model, $seal), $this->describe('to be unsealed', $model, $seal));
    }

    public function assertNothingUnsealed(): void
    {
        $count = count($this->recorded('unseal'));

        PHPUnit::assertSame(0, $count, "Expected nothing to be unsealed, but {$count} seal removal(s) were recorded.");
    }

    public function assertSealingSuspended(?string $reason = null): void
    {
        $matching = array_filter(
            $this->recorded('withoutSealing'),
            static fn (RecordedCall $call): bool => $reason === null || (is_array($call->arguments) && $call->arguments[0] === $reason),
        );

        PHPUnit::assertNotEmpty($matching, $reason === null ? 'Expected sealing to be suspended, but it was not.' : "Expected sealing to be suspended for [{$reason}], but it was not.");
    }

    public function assertSealingNotSuspended(): void
    {
        $count = count($this->recorded('withoutSealing'));

        PHPUnit::assertSame(0, $count, "Expected sealing not to be suspended, but it was suspended {$count} time(s).");
    }

    /**
     * A chunked scan ran (`Sentinel::scan()`, `Sentinel::model()->scan()`, `sentinel:verify`)
     * — over this model class, when given.
     *
     * @param  class-string<Model>|null  $model
     */
    public function assertScanned(?string $model = null): void
    {
        $matching = array_filter(
            $this->recorded('scan'),
            static fn (RecordedCall $call): bool => $model === null || ($call->arguments instanceof ScanOptions && in_array($model, $call->arguments->models, true)),
        );

        PHPUnit::assertNotEmpty($matching, $model === null ? 'Expected a seal scan, but none ran.' : "Expected [{$model}] to be scanned, but it was not.");
    }

    public function assertKeyGenerated(?string $ring = null): void
    {
        PHPUnit::assertNotEmpty(
            $this->keyCalls('generateKey', $ring),
            $ring === null ? 'Expected a key to be generated, but none was.' : "Expected a key to be generated in ring [{$ring}], but none was.",
        );
    }

    /**
     * A key was imported — into this ring, with this kid, when given.
     */
    public function assertKeyImported(?string $ring = null, ?string $keyId = null): void
    {
        $matching = array_filter(
            $this->recorded('importKey'),
            static fn (RecordedCall $call): bool => $call->arguments instanceof ImportKeyRequest
                && ($ring === null || $call->arguments->ring === $ring) && ($keyId === null || $call->arguments->keyId === $keyId),
        );

        PHPUnit::assertNotEmpty($matching, sprintf(
            'Expected a key to be imported%s%s, but none was.',
            $ring === null ? '' : " into ring [{$ring}]",
            $keyId === null ? '' : " as [{$keyId}]",
        ));
    }

    public function assertKeyRotated(?string $ring = null): void
    {
        PHPUnit::assertNotEmpty(
            $this->keyCalls('rotateKey', $ring),
            $ring === null ? 'Expected a key rotation, but none happened.' : "Expected ring [{$ring}] to be rotated, but it was not.",
        );
    }

    public function assertKeyRevoked(string $keyId): void
    {
        $matching = array_filter(
            $this->recorded('revokeKey'),
            static fn (RecordedCall $call): bool => $call->arguments instanceof RevokeKeyRequest && $call->arguments->keyId === $keyId,
        );

        PHPUnit::assertNotEmpty($matching, "Expected key [{$keyId}] to be revoked, but it was not.");
    }

    public function assertKeyRetired(string $keyId): void
    {
        $matching = array_filter(
            $this->recorded('retireKey'),
            static fn (RecordedCall $call): bool => is_array($call->arguments) && ($call->arguments[1] ?? null) === $keyId,
        );

        PHPUnit::assertNotEmpty($matching, "Expected key [{$keyId}] to be retired, but it was not.");
    }

    public function assertNoKeyChanges(): void
    {
        $changes = array_merge(...array_map($this->recorded(...), ['generateKey', 'importKey', 'rotateKey', 'revokeKey', 'retireKey']));

        PHPUnit::assertEmpty($changes, sprintf('Expected no key changes, but %d were recorded.', count($changes)));
    }

    public function assertCheckpointed(?int $times = null): void
    {
        $count = count($this->recorded('checkpoint'));

        $times === null
            ? PHPUnit::assertGreaterThan(0, $count, 'Expected a ledger checkpoint, but none was made.')
            : PHPUnit::assertSame($times, $count, "Expected {$times} ledger checkpoint(s), but {$count} were made.");
    }

    public function assertLedgerVerified(): void
    {
        PHPUnit::assertNotEmpty($this->recorded('verifyLedger'), 'Expected the ledger to be verified, but it was not.');
    }

    /**
     * A bulk re-seal of the model happened (`reseal`, `resealWhere`, `updateAndReseal` or
     * `sealMissing`) — with `count` rows re-sealed or acknowledged in total, when given.
     *
     * @param  class-string<Model>  $model
     */
    public function assertResealed(string $model, ?int $count = null): void
    {
        $calls = array_values(array_filter(
            array_merge(...array_map($this->recorded(...), self::BULK)),
            static fn (RecordedCall $call): bool => is_object($call->arguments) && property_exists($call->arguments, 'model') && $call->arguments->model === $model,
        ));

        PHPUnit::assertNotEmpty($calls, "Expected [{$model}] to be re-sealed, but it was not.");

        if ($count !== null) {
            $total = array_sum(array_map(static fn (RecordedCall $call): int => $call->result instanceof ResealReport ? $call->result->resealed + $call->result->acknowledged : 0, $calls));

            PHPUnit::assertSame($count, $total, "Expected {$count} [{$model}] row(s) to be re-sealed, but {$total} were.");
        }
    }

    /**
     * No bulk re-seal of any model (`reseal`, `resealWhere`, `updateAndReseal`, `sealMissing`).
     */
    public function assertNothingResealed(): void
    {
        $count = count(array_merge(...array_map($this->recorded(...), self::BULK)));

        PHPUnit::assertSame(0, $count, "Expected nothing to be re-sealed, but {$count} bulk re-seal(s) were recorded.");
    }

    /**
     * An idempotent run with this key happened — replayed or fresh, when given.
     */
    public function assertIdempotentRun(string $key, ?bool $replayed = null): void
    {
        $matching = array_filter(
            $this->recorded('runIdempotent'),
            static fn (RecordedCall $call): bool => $call->arguments instanceof IdempotentCall && $call->arguments->key === $key
                && ($replayed === null || ($call->result instanceof IdempotentResult && $call->result->replayed === $replayed)),
        );

        PHPUnit::assertNotEmpty($matching, "Expected an idempotent run with key [{$key}]".match ($replayed) {
            true => ' that replayed', false => ' that ran fresh', null => '',
        }.', but there was none.');
    }

    /**
     * No programmatic idempotent run (`Sentinel::idempotency()->run()`, the `Idempotent` job
     * middleware).
     */
    public function assertNoIdempotentRuns(): void
    {
        $count = count($this->recorded('runIdempotent'));

        PHPUnit::assertSame(0, $count, "Expected no idempotent runs, but {$count} were recorded.");
    }

    public function assertIdempotencyKeyForgotten(#[SensitiveParameter] string $key): void
    {
        $matching = array_filter(
            $this->recorded('forgetIdempotencyKey'),
            static fn (RecordedCall $call): bool => is_array($call->arguments) && ($call->arguments[0] ?? null) === $key,
        );

        PHPUnit::assertNotEmpty($matching, 'Expected the idempotency key to be forgotten, but it was not.');
    }

    public function assertNonceIssued(string $purpose): void
    {
        $matching = array_filter($this->recorded('issueNonce'), static fn (RecordedCall $call): bool => $call->arguments instanceof IssueNonceRequest && $call->arguments->purpose === $purpose);

        PHPUnit::assertNotEmpty($matching, "Expected a nonce to be issued for [{$purpose}], but none was.");
    }

    /**
     * A nonce of this purpose was consumed successfully.
     */
    public function assertNonceConsumed(string $purpose): void
    {
        $matching = array_filter($this->recorded('consumeNonce'), static fn (RecordedCall $call): bool => $call->arguments instanceof ConsumeNonceRequest && $call->arguments->purpose === $purpose && $call->result === true);

        PHPUnit::assertNotEmpty($matching, "Expected a nonce for [{$purpose}] to be consumed, but none was.");
    }

    /**
     * No nonce was issued (single-use URLs issue one too).
     */
    public function assertNoNoncesIssued(): void
    {
        $count = count($this->recorded('issueNonce'));

        PHPUnit::assertSame(0, $count, "Expected no nonces to be issued, but {$count} were.");
    }

    /**
     * No nonce of this purpose was consumed successfully.
     */
    public function assertNonceNotConsumed(string $purpose): void
    {
        $matching = array_filter($this->recorded('consumeNonce'), static fn (RecordedCall $call): bool => $call->arguments instanceof ConsumeNonceRequest && $call->arguments->purpose === $purpose && $call->result === true);

        PHPUnit::assertEmpty($matching, "Expected no nonce for [{$purpose}] to be consumed, but one was.");
    }

    /**
     * A single-use signed URL was issued — for this route name, when given.
     */
    public function assertSingleUseUrlIssued(?string $route = null): void
    {
        $matching = array_filter(
            $this->recorded('signedRoute'),
            static fn (RecordedCall $call): bool => $route === null || ($call->arguments instanceof SignedRouteRequest && $call->arguments->name === $route),
        );

        PHPUnit::assertNotEmpty($matching, $route === null ? 'Expected a single-use URL to be issued, but none was.' : "Expected a single-use URL for route [{$route}], but none was issued.");
    }

    public function assertPruned(): void
    {
        PHPUnit::assertNotEmpty($this->recorded('prune'), 'Expected expired idempotency keys and nonces to be pruned, but they were not.');
    }

    /**
     * An outgoing request was signed — with this key, when given.
     */
    public function assertRequestSigned(?string $keyId = null): void
    {
        $matching = array_filter(
            $this->recorded('signRequest'),
            static fn (RecordedCall $call): bool => $keyId === null || (is_array($call->arguments) && ($call->arguments[1] ?? null) === $keyId),
        );

        PHPUnit::assertNotEmpty($matching, $keyId === null ? 'Expected a request to be signed, but none was.' : "Expected a request to be signed with key [{$keyId}], but none was.");
    }

    public function assertNothingSigned(): void
    {
        $count = count($this->recorded('signRequest'));

        PHPUnit::assertSame(0, $count, "Expected nothing to be signed, but {$count} request(s) were.");
    }

    /**
     * An inbound request or a received response verified — against this profile, when given
     * (null verifies against the default profile). Scripted rejections do not count.
     */
    public function assertSignatureVerified(?string $profile = null): void
    {
        $matching = array_filter(
            [...$this->recorded('verifyRequestSignature'), ...$this->recorded('verifyResponseSignature')],
            static fn (RecordedCall $call): bool => $call->result instanceof VerifiedSignature
                && ($profile === null || (is_array($call->arguments) && ($call->arguments[1] ?? null) === $profile)),
        );

        PHPUnit::assertNotEmpty($matching, $profile === null ? 'Expected a signature to be verified, but none was.' : "Expected a signature to be verified against profile [{$profile}], but none was.");
    }

    /**
     * The recorded calls, optionally of one manager method.
     *
     * @return list<RecordedCall>
     */
    public function recorded(?string $method = null): array
    {
        return array_values(array_filter(
            $this->calls,
            static fn (RecordedCall $call): bool => $method === null || $call->method === $method,
        ));
    }

    // ── internals ─────────────────────────────────────────────────────────────

    /**
     * The profile is validated as in production; the outcome is scripted.
     */
    private function fakedSignature(string $method, object $message, ?string $profile): VerifiedSignature
    {
        $resolved = ProfileResolver::resolve($profile);

        if ($this->rejection !== null) {
            $this->record($method, [$message, $resolved->name], $this->rejection);

            throw HttpSignatureException::rejected($this->rejection, 'fake');
        }

        return $this->record($method, [$message, $resolved->name], $this->signature ?? new VerifiedSignature(
            'sig1', $resolved->ring, 'fake', Algorithm::HmacSha256, Clock::now()->getTimestamp(), null, null, $resolved->tag, $resolved->components,
        ));
    }

    /**
     * @param  Builder<Model>  $query
     * @return list<Model>
     */
    private function rows(Builder $query, ?int $limit = null): array
    {
        $models = $this->container->make(SealingScope::class)->withoutVerification(
            static fn (): EloquentCollection => ($limit === null ? $query : $query->limit($limit))->get(),
        );

        return array_values($models->all());
    }

    /**
     * Report progress after each full chunk and after the last row, as the chunked
     * production runs do.
     *
     * @param  (Closure(int): void)|null  $progress
     */
    private function progress(?Closure $progress, int $index, int $total, int $chunk): void
    {
        if ($progress !== null && (($index + 1) % max(1, $chunk) === 0 || $index === $total - 1)) {
            $progress($index + 1);
        }
    }

    private function compiled(Model $model, ?string $seal): CompiledSeal
    {
        return $this->container->make(DefinitionRegistry::class)->seal($model, $seal);
    }

    private function faked(Model $model, CompiledSeal $seal, VerificationContext $context): VerificationResult
    {
        $faked = null;

        foreach ([$this->identity($model, $seal->name), $this->identity($model, null)] as $identity) {
            if (($this->once[$identity] ?? []) !== []) {
                $faked = array_shift($this->once[$identity]);

                break;
            }
        }

        $faked ??= $this->sticky[$this->identity($model, $seal->name)] ?? $this->sticky[$this->identity($model, null)] ?? new FakedStatus(VerificationStatus::Intact, null);

        $reason = $faked->reason ?? match ($faked->status) {
            VerificationStatus::Tampered => self::tamperedReason($faked->changed),
            VerificationStatus::Missing => 'seal_deleted',
            default => null,
        };

        return new VerificationResult(
            $faked->status, $reason, $model->getMorphClass(), $model->getKey(),
            $seal->name, changedAttributes: $faked->changed, context: $context, outdatedIsIntact: Settings::outdatedIsIntact(),
        );
    }

    /**
     * A scripted change list of computed fields only is computed drift (`Tampered(computed)`,
     * which writes and seal() re-seal); anything else is a failed MAC.
     *
     * @param  list<string>|null  $changed
     */
    private static function tamperedReason(?array $changed): string
    {
        if ($changed === null || $changed === []) {
            return 'mac';
        }

        foreach ($changed as $name) {
            if (! str_starts_with($name, 'c:')) {
                return 'mac';
            }
        }

        return 'computed';
    }

    private function recordSeal(Model $model, CompiledSeal $seal, SealEvent $event, ?string $reason = null, ?Model $actor = null): SealResult
    {
        $result = $this->record('seal', [$model, $seal->name, $reason, $actor], $this->synthetic($model, $seal, $event));
        $this->settle($model, $seal->name);

        return $result;
    }

    /**
     * A seal the fake recorded covers the model as it is now, so — as in production — that
     * seal verifies intact afterwards. Statuses scripted for the model's other seals stay.
     */
    private function settle(Model $model, string $seal): void
    {
        if (isset($this->sticky[$this->identity($model, $seal)]) || isset($this->sticky[$this->identity($model, null)])) {
            $this->sticky[$this->identity($model, $seal)] = new FakedStatus(VerificationStatus::Intact, null);
        }
    }

    private function synthetic(Model $model, CompiledSeal $seal, SealEvent $event): SealResult
    {
        return new SealResult(
            $model->getMorphClass(), $model->getKey(), $seal->name, count($this->callsFor('seal', $model, $seal->name)) + 1,
            $seal->ring, 'fake', $seal->algorithms[0], Clock::now(), $event, null,
        );
    }

    /**
     * @return list<RecordedCall>
     */
    private function callsFor(string $method, Model $model, ?string $seal): array
    {
        return array_values(array_filter(
            $this->recorded($method),
            static fn (RecordedCall $call): bool => is_array($call->arguments)
                && ($call->arguments[0] ?? null) instanceof Model && $call->arguments[0]->is($model)
                && ($seal === null || ($call->arguments[1] ?? null) === $seal),
        ));
    }

    /**
     * @return list<RecordedCall>
     */
    private function keyCalls(string $method, ?string $ring): array
    {
        return array_values(array_filter(
            $this->recorded($method),
            static fn (RecordedCall $call): bool => $ring === null
                || (($call->arguments instanceof GenerateKeyRequest || $call->arguments instanceof RotateKeyRequest) && $call->arguments->ring === $ring),
        ));
    }

    private function identity(Model $model, ?string $seal): string
    {
        return $model->getMorphClass().':'.$model->getKey().':'.($seal ?? '*');
    }

    private function describe(string $expectation, Model $model, ?string $seal, string $but = 'it was not'): string
    {
        return "Expected [{$model->getMorphClass()}:{$model->getKey()}]".($seal === null ? '' : " seal [{$seal}]")." {$expectation}, but {$but}.";
    }

    /**
     * @template TResult
     *
     * @param  object|list<mixed>  $arguments
     * @param  TResult  $result
     * @return TResult
     */
    private function record(string $method, object|array $arguments, mixed $result): mixed
    {
        $this->calls[] = new RecordedCall($method, $arguments, $result);

        return $result;
    }
}
