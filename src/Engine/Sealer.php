<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Engine;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Sentinel\Canonical\FieldTagger;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealResult;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\ModelSealed;
use RoundlyConsulting\Sentinel\Events\SealRemoved;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\ConcurrentSealException;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;

/**
 * Writes seals and tombstones (plan §9.3). Always called inside the caller's transaction,
 * taking locks in the one global order — model row → seal row → ledger insert — so sealing
 * never deadlocks against itself. The version is max(seal row, ledger head) + 1 and the seal
 * row is written by compare-and-swap on that version.
 *
 * @internal
 */
final readonly class Sealer
{
    public function __construct(
        private KeyStoreManager $keys,
        private Signers $signers,
        private FieldTagger $tagger,
        private LedgerWriter $ledger,
        private ReadBack $readBack,
        private DocumentBuilder $documents,
        private Container $container,
    ) {}

    /**
     * @param  list<string>|null  $changed
     */
    public function seal(
        Model $model,
        CompiledSeal $seal,
        SealEvent $event,
        ?string $reason = null,
        ?Model $actor = null,
        ?VerificationStatus $previousStatus = null,
        ?array $changed = null,
    ): SealResult {
        if (! $model->exists) {
            throw SealingFailedException::notPersisted($model->getMorphClass());
        }

        $key = $this->keys->signingKey($seal->ring);

        if (! $seal->allows($key->algorithm())) {
            throw AlgorithmNotAllowedException::forSeal($seal->model, $seal->name, $key->algorithm());
        }

        $row = $this->readBack->row($model, $seal->readColumns(), lock: true)
            ?? throw SealingFailedException::rowVanished($model->getMorphClass(), $model->getKey());
        $sealRow = Tables::seals($model, $seal->name)->lockForUpdate()->first();
        $head = $this->head($model, $seal->name);
        $rowVersion = $sealRow === null ? 0 : (int) $sealRow->getRawOriginal('version');
        $version = max($rowVersion, $head === null ? 0 : (int) $head->getRawOriginal('version')) + 1;
        $previous = $this->previousDigest($sealRow, $head);
        $at = Clock::now();

        $message = $this->documents->build($model, $seal, $seal->fields, $row, $key->ring, $key->keyId, $key->algorithm(), $version, $previous, $at);
        $mac = Base64Url::encode($this->signers->sign($key, Purpose::Seal, $message->bytes()));
        $tags = $seal->usesFieldTags() ? $this->tagger->tags($key, $message) : null;

        $entry = Settings::ledgerEnabled()
            ? $this->ledger->append($model, $seal->name, $key, $event, $version, $mac, $previous, $changed, $previousStatus, $actor, $reason, $at)
            : null;

        $attributes = [
            'format' => 1,
            'ring' => $key->ring,
            'key_id' => $key->keyId,
            'algorithm' => $key->algorithm()->value,
            'version' => $version,
            'previous_digest' => $previous,
            'mac' => $mac,
            'manifest' => json_encode($seal->manifest(), JSON_THROW_ON_ERROR),
            'field_tags' => $tags === null ? null : json_encode($tags, JSON_THROW_ON_ERROR),
            'event' => $event->value,
            'sealed_by_type' => $actor?->getMorphClass(),
            'sealed_by_id' => $actor?->getKey(),
            'reason' => $reason,
            'sealed_at' => Clock::database($at),
            'ledger_entry_id' => $entry?->getKey(),
        ];

        $this->write($model, $seal, $sealRow, $rowVersion, $attributes);
        // An eager-loaded copy of the seal rows is stale now.
        $model->unsetRelation('sentinelSeals');

        $this->container->make(Dispatcher::class)->dispatch(new ModelSealed(
            $model->getMorphClass(), $model->getKey(), $seal->name, $version, $key->keyId, $event, $actor?->getMorphClass(), $actor?->getKey(),
        ));

        return new SealResult(
            $model->getMorphClass(), $model->getKey(), $seal->name, $version, $key->ring, $key->keyId, $key->algorithm(), $at, $event,
            $entry === null ? null : (int) $entry->getKey(),
        );
    }

    /**
     * Remove a seal row and record why: `deleted` (hard delete) or `unsealed` (deliberate).
     * Returns whether there was a seal row. Nothing is written for a model that never had a
     * seal or any history.
     */
    public function tombstone(
        Model $model,
        CompiledSeal $seal,
        SealEvent $event,
        ?VerificationStatus $previousStatus = null,
        ?string $reason = null,
        ?Model $actor = null,
    ): bool {
        $sealRow = Tables::seals($model, $seal->name)->lockForUpdate()->first();
        $head = $this->head($model, $seal->name);
        $ended = $head === null || SealEvent::tryFrom((string) $head->getRawOriginal('event'))?->isTombstone() === true;

        // Nothing to remove and no open history to close.
        if ($sealRow === null && $ended) {
            return false;
        }

        if (Settings::ledgerEnabled()) {
            $key = $this->keys->signingKey($seal->ring);
            $version = max($sealRow === null ? 0 : (int) $sealRow->getRawOriginal('version'), $head === null ? 0 : (int) $head->getRawOriginal('version')) + 1;

            $this->ledger->append(
                $model, $seal->name, $key, $event, $version, null, $this->previousDigest($sealRow, $head), null, $previousStatus, $actor, $reason, Clock::now(),
            );
        }

        if ($sealRow !== null) {
            Tables::seals($model, $seal->name)->whereKey($sealRow->getKey())->delete();
            $model->unsetRelation('sentinelSeals');
        }

        $this->container->make(Dispatcher::class)->dispatch(new SealRemoved($model->getMorphClass(), $model->getKey(), $seal->name, $event, $previousStatus));

        return $sealRow !== null;
    }

    public function head(Model $model, string $seal): ?LedgerEntry
    {
        return Settings::ledgerEnabled()
            ? Tables::entries($model, $seal)->orderByDesc('version')->first()
            : null;
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private function write(Model $model, CompiledSeal $seal, ?Seal $sealRow, int $rowVersion, array $attributes): void
    {
        if ($sealRow !== null) {
            $affected = Tables::seals($model, $seal->name)->whereKey($sealRow->getKey())->where('version', $rowVersion)->update($attributes);

            if ($affected !== 1) {
                throw ConcurrentSealException::versionConflict($model->getMorphClass(), $model->getKey(), $seal->name);
            }

            return;
        }

        $new = Tables::seal($model)->forceFill([
            'sealable_type' => $model->getMorphClass(),
            'sealable_id' => $model->getKey(),
            'seal' => $seal->name,
        ]);

        // Raw values (the JSON is already encoded): no casts between the engine and the row.
        $new->setRawAttributes([...$new->getAttributes(), ...$attributes]);

        try {
            $new->save();
        } catch (UniqueConstraintViolationException) {
            throw ConcurrentSealException::versionConflict($model->getMorphClass(), $model->getKey(), $seal->name);
        }
    }

    /**
     * The chain link: base64url SHA-256 of the previous seal's MAC bytes (the seal row's, or
     * the last ledger entry's when the row is gone).
     */
    private function previousDigest(?Seal $sealRow, ?LedgerEntry $head): ?string
    {
        $mac = $sealRow?->getRawOriginal('mac') ?? $head?->getRawOriginal('seal_mac');

        if ($mac === null) {
            return null;
        }

        try {
            $bytes = Base64Url::decode((string) $mac);
        } catch (InvalidEncodingException) {
            $bytes = (string) $mac;
        }

        return Base64Url::encode((new Digest)->raw($bytes));
    }
}
