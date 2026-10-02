<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Testing;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Assert as PHPUnit;
use RoundlyConsulting\Sentinel\Contracts\AcknowledgementPolicy;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgementResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\GeneratedKey;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotationResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Persister;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\PersistOperation;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Exceptions\SealingSuspensionNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Keys\KeyIds;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use RoundlyConsulting\Sentinel\Support\Reasons;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;

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
    /** @var list<RecordedCall> */
    private array $calls = [];

    /** @var array<string, FakedStatus> */
    private array $sticky = [];

    /** @var array<string, list<FakedStatus>> */
    private array $once = [];

    public function __construct(Container $container)
    {
        parent::__construct($container);
    }

    // ── controls ──────────────────────────────────────────────────────────────

    /**
     * Every verification of the model (one seal, or all when null) returns this status until
     * changed. An acknowledgement clears it.
     *
     * @param  list<string>|null  $changed
     */
    public function fakeStatus(Model $model, VerificationStatus $status, ?string $seal = null, ?array $changed = null): static
    {
        $this->sticky[$this->identity($model, $seal)] = new FakedStatus($status, $changed);

        return $this;
    }

    /**
     * The next verification of the model (one seal, or any when null) returns this status.
     *
     * @param  list<string>|null  $changed
     */
    public function fakeStatusOnce(Model $model, VerificationStatus $status, ?string $seal = null, ?array $changed = null): static
    {
        $this->once[$this->identity($model, $seal)][] = new FakedStatus($status, $changed);

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
        $absent = $verdict->status === VerificationStatus::Unsealed || $verdict->status === VerificationStatus::Missing;

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

    public function verifyAll(Model $model): VerificationReport
    {
        return new VerificationReport(array_map(
            fn (string $seal): VerificationResult => $this->verify($model, $seal),
            $this->container->make(DefinitionRegistry::class)->for($model)->names(),
        ));
    }

    /**
     * @param  iterable<Model>  $models
     */
    public function verifyMany(iterable $models, ?string $seal = null): VerificationReport
    {
        $results = [];

        foreach ($models as $model) {
            if ($seal !== null) {
                $results[] = $this->verify($model, $seal);

                continue;
            }

            array_push($results, ...$this->verifyAll($model)->results);
        }

        return new VerificationReport($results);
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

        unset($this->sticky[$this->identity($model, $compiled->name)], $this->sticky[$this->identity($model, null)]);

        return $this->record('acknowledge', [$model, $compiled->name, $reason, $request->actor], new AcknowledgementResult(
            true, $before, $this->synthetic($model, $compiled, SealEvent::Acknowledged),
        ));
    }

    public function unseal(Model $model, string $reason, ?Model $actor = null, ?string $seal = null): bool
    {
        $compiled = $this->compiled($model, $seal);

        return $this->record('unseal', [$model, $compiled->name, Reasons::normalize($reason), $actor], true);
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

        if (! Settings::autoSeal() || $seals->auto() === [] || $this->container->make(SealingScope::class)->sealingSuspended()) {
            return $write();
        }

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

        foreach ($seals->auto() as $seal) {
            if (! $existing) {
                $this->recordSeal($model, $seal, SealEvent::Sealed);
            } elseif (! isset($skip[$seal->name]) && ($seal->hasComputed() || isset($previous[$seal->name]) || $model->wasChanged($seal->columns()))) {
                $this->recordSeal($model, $seal, SealEvent::Resealed);
            }
        }

        return $result;
    }

    // ── keys ──────────────────────────────────────────────────────────────────

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

        $result = new GeneratedKey(new KeyInfo(
            $request->ring, $keyId, $request->algorithm, KeyStatus::Active, $request->destination->value, true,
            $request->activatesAt, label: $request->label,
        ));

        return $this->record('generateKey', $request, $result);
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

        return $this->record('rotateKey', $request, $result);
    }

    public function revokeKey(RevokeKeyRequest $request): KeyInfo
    {
        $config = Settings::ring($request->ring);
        $reason = trim($request->reason);

        if ($reason === '' || mb_strlen($reason) > 1000) {
            throw KeyDriverException::reasonRequired();
        }

        return $this->record('revokeKey', $request, new KeyInfo(
            $request->ring, $request->keyId, $config->algorithm, KeyStatus::Revoked, $config->driver, false,
        ));
    }

    public function retireKey(string $ring, string $keyId): KeyInfo
    {
        $config = Settings::ring($ring);

        return $this->record('retireKey', [$ring, $keyId], new KeyInfo(
            $ring, $keyId, $config->algorithm, KeyStatus::Retired, $config->driver, false,
        ));
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

    public function assertAcknowledged(Model $model, ?string $reason = null): void
    {
        $matching = array_filter(
            $this->callsFor('acknowledge', $model, null),
            static fn (RecordedCall $call): bool => $call->result instanceof AcknowledgementResult && $call->result->acknowledged
                && ($reason === null || (is_array($call->arguments) && ($call->arguments[2] ?? null) === $reason)),
        );

        PHPUnit::assertNotEmpty($matching, $this->describe('to be acknowledged', $model, null).($reason === null ? '' : " with reason [{$reason}]"));
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

    public function assertSealingSuspended(?string $reason = null): void
    {
        $matching = array_filter(
            $this->recorded('withoutSealing'),
            static fn (RecordedCall $call): bool => $reason === null || (is_array($call->arguments) && $call->arguments[0] === $reason),
        );

        PHPUnit::assertNotEmpty($matching, $reason === null ? 'Expected sealing to be suspended, but it was not.' : "Expected sealing to be suspended for [{$reason}], but it was not.");
    }

    public function assertKeyGenerated(?string $ring = null): void
    {
        PHPUnit::assertNotEmpty(
            $this->keyCalls('generateKey', $ring),
            $ring === null ? 'Expected a key to be generated, but none was.' : "Expected a key to be generated in ring [{$ring}], but none was.",
        );
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

    public function assertNoKeyChanges(): void
    {
        $changes = array_merge(...array_map($this->recorded(...), ['generateKey', 'rotateKey', 'revokeKey', 'retireKey']));

        PHPUnit::assertEmpty($changes, sprintf('Expected no key changes, but %d were recorded.', count($changes)));
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

        return new VerificationResult(
            $faked->status, $faked->status === VerificationStatus::Tampered ? 'mac' : null, $model->getMorphClass(), $model->getKey(),
            $seal->name, changedAttributes: $faked->changed, context: $context, outdatedIsIntact: Settings::outdatedIsIntact(),
        );
    }

    private function recordSeal(Model $model, CompiledSeal $seal, SealEvent $event, ?string $reason = null, ?Model $actor = null): SealResult
    {
        return $this->record('seal', [$model, $seal->name, $reason, $actor], $this->synthetic($model, $seal, $event));
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

    private function describe(string $expectation, Model $model, ?string $seal): string
    {
        return "Expected [{$model->getMorphClass()}:{$model->getKey()}]".($seal === null ? '' : " seal [{$seal}]")." {$expectation}, but it was not.";
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
