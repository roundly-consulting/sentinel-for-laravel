<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Client\Response as ClientResponse;
use Illuminate\Http\Request;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RoundlyConsulting\Sentinel\Accessors\IdempotencyAccessor;
use RoundlyConsulting\Sentinel\Accessors\KeysAccessor;
use RoundlyConsulting\Sentinel\Accessors\LedgerAccessor;
use RoundlyConsulting\Sentinel\Accessors\NoncesAccessor;
use RoundlyConsulting\Sentinel\Accessors\SignaturesAccessor;
use RoundlyConsulting\Sentinel\Actions\CheckInstallationAction;
use RoundlyConsulting\Sentinel\Actions\Idempotency\BeginIdempotentRequestAction;
use RoundlyConsulting\Sentinel\Actions\Idempotency\CompleteIdempotentRequestAction;
use RoundlyConsulting\Sentinel\Actions\Idempotency\ForgetIdempotencyKeyAction;
use RoundlyConsulting\Sentinel\Actions\Idempotency\ReleaseIdempotentRequestAction;
use RoundlyConsulting\Sentinel\Actions\Idempotency\RunIdempotentAction;
use RoundlyConsulting\Sentinel\Actions\Keys\GenerateKeyAction;
use RoundlyConsulting\Sentinel\Actions\Keys\ImportKeyAction;
use RoundlyConsulting\Sentinel\Actions\Keys\RetireKeyAction;
use RoundlyConsulting\Sentinel\Actions\Keys\RevokeKeyAction;
use RoundlyConsulting\Sentinel\Actions\Keys\RotateKeyAction;
use RoundlyConsulting\Sentinel\Actions\Ledger\CreateCheckpointAction;
use RoundlyConsulting\Sentinel\Actions\Ledger\VerifyLedgerAction;
use RoundlyConsulting\Sentinel\Actions\Nonces\ConsumeNonceAction;
use RoundlyConsulting\Sentinel\Actions\Nonces\IssueNonceAction;
use RoundlyConsulting\Sentinel\Actions\Nonces\IssueSingleUseUrlAction;
use RoundlyConsulting\Sentinel\Actions\Nonces\RememberNonceAction;
use RoundlyConsulting\Sentinel\Actions\PruneAction;
use RoundlyConsulting\Sentinel\Actions\Seals\AcknowledgeTamperingAction;
use RoundlyConsulting\Sentinel\Actions\Seals\PersistSealedModelAction;
use RoundlyConsulting\Sentinel\Actions\Seals\ReadLedgerHistoryAction;
use RoundlyConsulting\Sentinel\Actions\Seals\ResealModelsAction;
use RoundlyConsulting\Sentinel\Actions\Seals\ResealWhereAction;
use RoundlyConsulting\Sentinel\Actions\Seals\ScanSealsAction;
use RoundlyConsulting\Sentinel\Actions\Seals\SealMissingAction;
use RoundlyConsulting\Sentinel\Actions\Seals\SealModelAction;
use RoundlyConsulting\Sentinel\Actions\Seals\UnsealModelAction;
use RoundlyConsulting\Sentinel\Actions\Seals\UpdateAndResealAction;
use RoundlyConsulting\Sentinel\Actions\Seals\VerifyModelAction;
use RoundlyConsulting\Sentinel\Actions\Seals\VerifyModelsAction;
use RoundlyConsulting\Sentinel\Actions\Seals\VerifyRetrievedModelAction;
use RoundlyConsulting\Sentinel\Actions\Signatures\SignRequestAction;
use RoundlyConsulting\Sentinel\Actions\Signatures\VerifyRequestSignatureAction;
use RoundlyConsulting\Sentinel\Actions\Signatures\VerifyResponseSignatureAction;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgementResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\BaselineOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\ConsumeNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\GeneratedKey;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\HealthReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotencyDecision;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\ImportKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssuedNonce;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssueNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
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
use RoundlyConsulting\Sentinel\DataTransferObjects\SealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\SignedRouteRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\UnsealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\UpdateAndResealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifyManyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifyRequest;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Enums\PersistOperation;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Events\SealingSuspended;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SealingSuspensionNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifyHttpSignature;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Ledger\AnchorManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\ModelDiscovery;
use RoundlyConsulting\Sentinel\Support\MorphedModel;
use RoundlyConsulting\Sentinel\Support\Reasons;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;
use SensitiveParameter;
use Symfony\Component\HttpFoundation\Response;

/**
 * The public API behind the `Sentinel` facade, injectable by its own class-string. Every
 * method is thin: it resolves an action through the container and calls `execute()`, so host
 * overrides and `Sentinel::fake()` both apply. Sub-accessors and model traits call back into
 * this manager, never into an action.
 *
 * Not Laravel\Sentinel\SentinelManager (laravel/sentinel, pulled in by Horizon/Pulse/Telescope)
 * — import RoundlyConsulting\Sentinel\SentinelManager.
 *
 * Not final on purpose: SentinelFake extends it, so an injected manager still type-checks
 * under `Sentinel::fake()`.
 */
class SentinelManager
{
    public function __construct(
        protected readonly Container $container,
    ) {}

    // ── model seals ───────────────────────────────────────────────────────────

    /**
     * A handle on one seal of a model (null = its default seal).
     */
    public function for(Model $model, ?string $seal = null): SealHandle
    {
        return new SealHandle($this, $model, $this->container->make(DefinitionRegistry::class)->seal($model, $seal));
    }

    /**
     * Class-level operations of a sealable model.
     *
     * @param  class-string<Model>  $class
     */
    public function model(string $class): ModelSeals
    {
        return new ModelSeals($this, $class, $this->container->make(DefinitionRegistry::class)->for($class));
    }

    /**
     * The installation health check: signing keys, APP_KEY, tables, models, anchors,
     * checkpoint backlog, scheduling, seals on retired keys and stores (`sentinel:check`).
     */
    public function check(): HealthReport
    {
        return $this->container->make(CheckInstallationAction::class)->execute();
    }

    /**
     * Every sealable model class: `sentinel.models` first, then each class that has seal rows
     * or ledger entries (discovered, alphabetically). `sentinel:verify` scans these when it
     * is given no model.
     *
     * @return list<class-string<Model>>
     */
    public function sealables(): array
    {
        return ModelDiscovery::run()->models;
    }

    /**
     * Seal (or re-seal) a model explicitly. Refuses a model changed outside the application
     * — acknowledge it instead.
     */
    public function seal(Model $model, ?string $seal = null, ?string $reason = null, ?Model $actor = null): SealResult
    {
        return $this->container->make(SealModelAction::class)->execute(new SealRequest($model, $this->sealName($model, $seal), $reason, $actor));
    }

    public function verify(Model $model, ?string $seal = null): VerificationResult
    {
        return $this->container->make(VerifyModelAction::class)->execute(new VerifyRequest($model, $this->sealName($model, $seal)));
    }

    /**
     * @throws TamperedModelException when the seal is not intact
     */
    public function verifyOrFail(Model $model, ?string $seal = null): VerificationResult
    {
        $result = $this->verify($model, $seal);

        return $result->isIntact() ? $result : throw TamperedModelException::forResult($result);
    }

    /**
     * Every seal of the model.
     */
    public function verifyAll(Model $model): VerificationReport
    {
        return $this->container->make(VerifyModelsAction::class)->execute(new VerifyManyRequest([$model]));
    }

    /**
     * @param  iterable<Model>  $models
     */
    public function verifyMany(iterable $models, ?string $seal = null): VerificationReport
    {
        return $this->verifyManyIn(VerificationContext::Api, $models, $seal);
    }

    /**
     * `verify()` from another entry point (middleware, rule, collection macro), recorded with
     * that context.
     *
     * @internal
     */
    public function verifyIn(VerificationContext $context, Model $model, ?string $seal = null): VerificationResult
    {
        return $this->container->make(VerifyModelAction::class)->execute(new VerifyRequest($model, $this->sealName($model, $seal), true, $context));
    }

    /**
     * `verifyMany()` from another entry point.
     *
     * @internal
     *
     * @param  iterable<Model>  $models
     */
    public function verifyManyIn(VerificationContext $context, iterable $models, ?string $seal = null): VerificationReport
    {
        return $this->container->make(VerifyModelsAction::class)->execute(new VerifyManyRequest($models, $seal, $context));
    }

    /**
     * Every seal of the model is intact.
     */
    public function isIntact(Model $model): bool
    {
        return $this->verifyAll($model)->allIntact();
    }

    /**
     * Accept an out-of-band change: reason required, actor recorded, policy checked.
     */
    public function acknowledge(Model $model, string $reason, ?Model $actor = null, ?string $seal = null): AcknowledgementResult
    {
        return $this->container->make(AcknowledgeTamperingAction::class)->execute(new AcknowledgeRequest($model, $this->sealName($model, $seal), $reason, $actor));
    }

    /**
     * Remove a seal deliberately (an `unsealed` tombstone records why).
     */
    public function unseal(Model $model, string $reason, ?Model $actor = null, ?string $seal = null): bool
    {
        return $this->container->make(UnsealModelAction::class)->execute(new UnsealRequest($model, $this->sealName($model, $seal), $reason, $actor));
    }

    /**
     * Verify every row of the given models in chunks (`sentinel:verify`).
     */
    public function scan(ScanOptions $options): ScanReport
    {
        return $this->container->make(ScanSealsAction::class)->execute($options);
    }

    /**
     * Re-seal intact/outdated rows with the current key; never launders.
     */
    public function reseal(ResealOptions $options): ResealReport
    {
        return $this->container->make(ResealModelsAction::class)->execute($options);
    }

    /**
     * Acknowledge every row a query selects.
     */
    public function resealWhere(ResealWhereRequest $request): ResealReport
    {
        return $this->container->make(ResealWhereAction::class)->execute($request);
    }

    /**
     * A deliberate mass update: verify all, update, re-seal with the reason.
     */
    public function updateAndReseal(UpdateAndResealRequest $request): ResealReport
    {
        return $this->container->make(UpdateAndResealAction::class)->execute($request);
    }

    /**
     * Seal rows that were never sealed (adoption).
     */
    public function sealMissing(BaselineOptions $options): ResealReport
    {
        return $this->container->make(SealMissingAction::class)->execute($options);
    }

    /**
     * @return list<LedgerRecord>
     */
    public function ledgerHistory(Model $model, ?string $seal = null, int $limit = 50): array
    {
        return $this->container->make(ReadLedgerHistoryAction::class)->execute($model, $this->sealName($model, $seal), $limit);
    }

    /**
     * The stored seal row (unverified), or null.
     */
    public function currentSeal(Model $model, ?string $seal = null): ?SealRecord
    {
        $row = Tables::seals($model, $this->sealName($model, $seal))->first();

        if ($row === null) {
            return null;
        }

        $manifest = $row->manifest;
        $sealedById = $row->getRawOriginal('sealed_by_id');

        // Unverified, as stored: a corrupt timestamp is shown as unknown, never an abort (it is
        // what `sentinel:inspect` exists to show; verification reports it as malformed).
        try {
            $sealedAt = (new UtcDateTime)->get($row, 'sealed_at', $row->getRawOriginal('sealed_at'), []);
        } catch (CorruptRecordException) {
            $sealedAt = null;
        }

        return new SealRecord(
            $row->sealable_type, $row->sealable_id, $row->seal, $row->version, $row->ring, $row->key_id, $row->algorithm,
            $manifest ?? [], $sealedAt, SealEvent::tryFrom((string) $row->getRawOriginal('event')),
            $row->reason, $row->sealed_by_type, is_int($sealedById) || is_string($sealedById) ? $sealedById : null,
        );
    }

    /**
     * Run the callback with automatic sealing off (seeders, imports). Writes inside are
     * unsealed or stale until re-sealed; strict seals report them. Audited by
     * `SealingSuspended`; refused unless `sentinel.sealing.allow_suspension` is on (it ships
     * off, and a key that is not set keeps it off).
     *
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function withoutSealing(Closure $callback, string $reason): mixed
    {
        if (! Settings::allowSuspension()) {
            throw SealingSuspensionNotAllowedException::disabled();
        }

        $reason = Reasons::normalize($reason);
        $actor = $this->container->make(Runtime::class)->user();
        $this->container->make(Dispatcher::class)->dispatch(new SealingSuspended($reason, $actor?->getMorphClass(), $actor?->getKey()));

        return $this->container->make(SealingScope::class)->withoutSealing($callback);
    }

    /**
     * Run the callback with verify-on-retrieve off (so an acknowledgement can load a tampered
     * model).
     *
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    public function withoutVerification(Closure $callback): mixed
    {
        return $this->container->make(SealingScope::class)->withoutVerification($callback);
    }

    /**
     * The Eloquent write path of `HasSeals`.
     *
     * @internal
     */
    public function persist(Model $model, Closure $write, PersistOperation $operation): mixed
    {
        return $this->container->make(PersistSealedModelAction::class)->execute($model, $write, $operation);
    }

    /**
     * Whether the class declares a verify-on-retrieve seal (`HasSeals` registers its
     * `retrieved` hook only then). Compiles the definition.
     *
     * @internal
     *
     * @param  class-string<Model>  $class
     */
    public function verifiesOnRetrieve(string $class): bool
    {
        return $this->container->make(DefinitionRegistry::class)->for($class)->verifiesOnRetrieve();
    }

    /**
     * The `retrieved` hook of `HasSeals` (verify-on-retrieve).
     *
     * @internal
     */
    public function retrieved(Model $model): void
    {
        $this->container->make(VerifyRetrievedModelAction::class)->execute($model);
    }

    // ── ledger ────────────────────────────────────────────────────────────────

    public function ledger(): LedgerAccessor
    {
        return new LedgerAccessor($this);
    }

    /**
     * Fold the next batch of pending ledger entries into a checkpoint and anchor it.
     */
    public function checkpoint(?CheckpointOptions $options = null): ?CheckpointResult
    {
        $options ??= new CheckpointOptions;

        return $this->container->make(CreateCheckpointAction::class)->execute($options);
    }

    /**
     * Verify the ledger: checkpoints, anchors, pending entries, entity heads.
     */
    public function verifyLedger(?LedgerVerifyOptions $options = null): LedgerReport
    {
        $options ??= new LedgerVerifyOptions;

        return $this->container->make(VerifyLedgerAction::class)->execute($options);
    }

    /**
     * The newest checkpoint of a connection (unverified), or null.
     */
    public function ledgerHead(?string $connection = null): ?CheckpointRecord
    {
        $head = Tables::checkpoints($connection)->orderByDesc('seq')->first();

        if ($head === null) {
            return null;
        }

        try {
            $createdAt = (new UtcDateTime)->get($head, 'created_at', $head->getRawOriginal('created_at'), []);
        } catch (CorruptRecordException) {
            $createdAt = null;
        }

        return new CheckpointRecord((int) $head->getRawOriginal('seq'), (string) $head->getRawOriginal('root'), $createdAt ?? Clock::now()->setTimestamp(0), (string) $head->getRawOriginal('key_id'), (int) $head->getRawOriginal('entries'));
    }

    /**
     * The configured anchor driver names.
     *
     * @return list<string>
     */
    public function anchors(): array
    {
        return $this->container->make(AnchorManager::class)->names();
    }

    /**
     * Register a custom anchor driver: `fn (Container $app, array $config): Anchor`.
     */
    public function extendAnchor(string $driver, Closure $factory): static
    {
        $this->container->make(AnchorManager::class)->extend($driver, $factory);

        return $this;
    }

    // ── idempotency / nonces ──────────────────────────────────────────────────

    public function idempotency(): IdempotencyAccessor
    {
        return new IdempotencyAccessor($this);
    }

    /**
     * Run a callback at most once per (key, scope). The key and the scope are 1–255 bytes, a
     * TTL 60–2 592 000 seconds — as for the `Idempotent` job middleware.
     *
     * @throws InvalidIdempotencyKeyException
     */
    public function runIdempotent(IdempotentCall $call): IdempotentResult
    {
        return $this->container->make(RunIdempotentAction::class)->execute($call);
    }

    /**
     * Forget a programmatic idempotency key.
     *
     * @throws InvalidIdempotencyKeyException
     */
    public function forgetIdempotencyKey(string $key, string $scope): bool
    {
        return $this->container->make(ForgetIdempotencyKeyAction::class)->execute($key, $scope);
    }

    public function nonces(): NoncesAccessor
    {
        return new NoncesAccessor($this);
    }

    public function issueNonce(IssueNonceRequest $request): IssuedNonce
    {
        return $this->container->make(IssueNonceAction::class)->execute($request);
    }

    public function consumeNonce(ConsumeNonceRequest $request): bool
    {
        return $this->container->make(ConsumeNonceAction::class)->execute($request);
    }

    /**
     * A signed URL for a named route that works once.
     */
    public function signedRoute(SignedRouteRequest $request): string
    {
        return $this->container->make(IssueSingleUseUrlAction::class)->execute($request);
    }

    /**
     * Delete expired idempotency keys and nonces.
     */
    public function prune(?PruneOptions $options = null): PruneResult
    {
        return $this->container->make(PruneAction::class)->execute($options ?? new PruneOptions);
    }

    // ── HTTP message signatures ───────────────────────────────────────────────

    public function signatures(): SignaturesAccessor
    {
        return new SignaturesAccessor($this);
    }

    /**
     * Sign an outgoing PSR-7 request (RFC 9421).
     */
    public function signRequest(RequestInterface $request, string $keyId, ?SigningOptions $options = null): RequestInterface
    {
        return $this->container->make(SignRequestAction::class)->execute($request, $keyId, $options ?? new SigningOptions);
    }

    /**
     * Verify an incoming request's signature against a profile (null = the default).
     */
    public function verifyRequestSignature(Request $request, ?string $profile = null): VerifiedSignature
    {
        return $this->container->make(VerifyRequestSignatureAction::class)->execute($request, $profile);
    }

    /**
     * The signature `sentinel.signed` verified on this request, or null.
     */
    public function verifiedSignature(Request $request): ?VerifiedSignature
    {
        $signature = $request->attributes->get(VerifyHttpSignature::ATTRIBUTE);

        return $signature instanceof VerifiedSignature ? $signature : null;
    }

    /**
     * The model that owns the key a request was signed with (e.g. the partner) — database
     * keys imported or generated with an owner; null for config keys, unsigned requests and
     * owners that no longer exist.
     */
    public function signatureOwner(Request|VerifiedSignature $from): ?Model
    {
        $signature = $from instanceof Request ? $this->verifiedSignature($from) : $from;

        return $signature === null ? null : MorphedModel::find($signature->ownerType, $signature->ownerId);
    }

    /**
     * Verify a received response's signature against a profile (null = the default).
     */
    public function verifyResponseSignature(ResponseInterface|ClientResponse $response, ?string $profile = null): VerifiedSignature
    {
        return $this->container->make(VerifyResponseSignatureAction::class)->execute($response, $profile);
    }

    /**
     * The `sentinel.idempotent` middleware: own the key, or learn why not.
     *
     * @internal
     */
    public function beginIdempotentRequest(IdempotentRequest $request): IdempotencyDecision
    {
        return $this->container->make(BeginIdempotentRequestAction::class)->execute($request);
    }

    /**
     * @internal
     */
    public function completeIdempotentRequest(IdempotentRequest $request, Response $response): bool
    {
        return $this->container->make(CompleteIdempotentRequestAction::class)->execute($request, $response);
    }

    /**
     * @internal
     */
    public function releaseIdempotentRequest(IdempotentRequest $request): void
    {
        $this->container->make(ReleaseIdempotentRequestAction::class)->execute($request);
    }

    /**
     * Remember a client's nonce (HTTP signatures); false for a replay.
     *
     * @internal
     */
    public function rememberNonce(string $purpose, #[SensitiveParameter] string $nonce, CarbonImmutable $until): bool
    {
        return $this->container->make(RememberNonceAction::class)->execute($purpose, $nonce, $until);
    }

    // ── keys ──────────────────────────────────────────────────────────────────

    public function keys(): KeysAccessor
    {
        return new KeysAccessor($this);
    }

    public function generateKey(GenerateKeyRequest $request): GeneratedKey
    {
        return $this->container->make(GenerateKeyAction::class)->execute($request);
    }

    /**
     * Import existing key material (a partner's public key or shared secret, or your own key
     * pair) into a ring's database store; verify-only unless imported with `signing: true`.
     */
    public function importKey(ImportKeyRequest $request): KeyInfo
    {
        return $this->container->make(ImportKeyAction::class)->execute($request);
    }

    public function rotateKey(RotateKeyRequest $request): RotationResult
    {
        return $this->container->make(RotateKeyAction::class)->execute($request);
    }

    public function revokeKey(RevokeKeyRequest $request): KeyInfo
    {
        return $this->container->make(RevokeKeyAction::class)->execute($request);
    }

    public function retireKey(string $ring, string $keyId): KeyInfo
    {
        return $this->container->make(RetireKeyAction::class)->execute($ring, $keyId);
    }

    /**
     * @return list<KeyInfo>
     */
    public function listKeys(?string $ring = null): array
    {
        if ($ring !== null) {
            Settings::ring($ring);
        }

        return $this->container->make(KeyStoreManager::class)->all($ring);
    }

    public function findKey(string $ring, string $keyId): ?KeyInfo
    {
        $key = $this->container->make(KeyStoreManager::class)->find($ring, $keyId);

        return $key === null ? null : KeyInfo::fromKey($key);
    }

    /**
     * The current signing key of a ring (null = the default ring).
     */
    public function currentKey(?string $ring = null): KeyInfo
    {
        return KeyInfo::fromKey($this->container->make(KeyStoreManager::class)->signingKey($ring ?? Settings::defaultRing()));
    }

    /**
     * Register a custom key-store driver: `fn (Container $app, string $ring, array $config): KeyStore`.
     */
    public function extend(string $driver, Closure $factory): static
    {
        $this->container->make(KeyStoreManager::class)->extend($driver, $factory);

        return $this;
    }

    /**
     * The seal's name, validated against the model's definition (null = its default).
     */
    protected function sealName(Model $model, ?string $seal): string
    {
        return $this->container->make(DefinitionRegistry::class)->seal($model, $seal)->name;
    }
}
