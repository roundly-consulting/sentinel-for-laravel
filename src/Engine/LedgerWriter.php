<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Engine;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use JsonException;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Sentinel\Canonical\LedgerMessage;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\ConcurrentSealException;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;
use SensitiveParameter;

/**
 * Appends MAC'd ledger entries (plan §4.7.1) in the same transaction as the seal event they
 * record, and re-checks an entry's MAC from its stored columns. The unique
 * (sealable, seal, version) index turns a lost race into a rolled-back transaction.
 *
 * @internal
 */
final readonly class LedgerWriter
{
    public function __construct(
        private Signers $signers,
        private KeyStoreManager $keys,
    ) {}

    /**
     * @param  list<string>|null  $changed
     */
    public function append(
        Model $model,
        string $seal,
        #[SensitiveParameter] SealingKey $key,
        SealEvent $event,
        int $version,
        ?string $sealMac,
        ?string $previous,
        ?array $changed,
        ?VerificationStatus $previousStatus,
        ?Model $actor,
        ?string $reason,
        CarbonImmutable $at,
    ): LedgerEntry {
        if ($changed !== null) {
            sort($changed, SORT_STRING);
        }

        $message = new LedgerMessage(
            Settings::context(), $model->getMorphClass(), (string) $model->getKey(), $seal, $version, $event, $key->ring, $key->keyId,
            $key->algorithm(), $sealMac, $previous, $changed, $previousStatus,
            $actor === null ? null : $actor->getMorphClass().':'.$actor->getKey(), $reason, $at,
        );

        $entry = Tables::ledger($model)->forceFill([
            'sealable_type' => $model->getMorphClass(),
            'sealable_id' => $model->getKey(),
            'seal' => $seal,
            'event' => $event,
            'version' => $version,
            'ring' => $key->ring,
            'key_id' => $key->keyId,
            'algorithm' => $key->algorithm()->value,
            'seal_mac' => $sealMac,
            'previous_digest' => $previous,
            'changed' => $changed,
            'previous_status' => $previousStatus?->value,
            'actor_type' => $actor?->getMorphClass(),
            'actor_id' => $actor?->getKey(),
            'reason' => $reason,
            'entry_mac' => Base64Url::encode($this->signers->sign($key, Purpose::Ledger, $message->bytes())),
            'occurred_at' => $at,
        ]);

        try {
            $entry->save();
        } catch (UniqueConstraintViolationException) {
            throw ConcurrentSealException::versionConflict($model->getMorphClass(), $model->getKey(), $seal);
        }

        return $entry;
    }

    /**
     * Whether a stored entry still carries a valid MAC over its audit fields. Any unreadable
     * column, unknown key or unusable key status fails closed.
     */
    public function verify(LedgerEntry $entry, Model $model): bool
    {
        $key = $this->keys->find((string) $entry->getRawOriginal('ring'), (string) $entry->getRawOriginal('key_id'));
        $message = $key === null || ! $key->canVerify() ? null : $this->message($entry, $model, $key->algorithm());

        if ($key === null || $message === null) {
            return false;
        }

        try {
            $mac = Base64Url::decode((string) $entry->getRawOriginal('entry_mac'));
        } catch (InvalidEncodingException) {
            return false;
        }

        return $this->signers->verify($key, Purpose::Ledger, $message->bytes(), $mac);
    }

    /**
     * The entry's document rebuilt from its raw columns, with the algorithm pinned to the key
     * (null when a column is unreadable).
     */
    private function message(LedgerEntry $entry, Model $model, Algorithm $algorithm): ?LedgerMessage
    {
        $event = SealEvent::tryFrom((string) $entry->getRawOriginal('event'));
        $status = $entry->getRawOriginal('previous_status');
        $previousStatus = $status === null ? null : VerificationStatus::tryFrom((string) $status);
        $changed = $this->changed($entry->getRawOriginal('changed'));
        $actorType = $entry->getRawOriginal('actor_type');
        $sealMac = $entry->getRawOriginal('seal_mac');
        $previous = $entry->getRawOriginal('previous_digest');
        $reason = $entry->getRawOriginal('reason');

        try {
            $at = (new UtcDateTime)->get($entry, 'occurred_at', $entry->getRawOriginal('occurred_at'), []);
        } catch (CorruptRecordException) {
            $at = null;
        }

        if ($event === null || ($status !== null && $previousStatus === null) || $changed === false || $at === null) {
            return null;
        }

        return new LedgerMessage(
            Settings::context(), $model->getMorphClass(), (string) $model->getKey(), (string) $entry->getRawOriginal('seal'),
            (int) $entry->getRawOriginal('version'), $event, (string) $entry->getRawOriginal('ring'), (string) $entry->getRawOriginal('key_id'),
            $algorithm, $sealMac === null ? null : (string) $sealMac, $previous === null ? null : (string) $previous, $changed,
            $previousStatus, $actorType === null ? null : $actorType.':'.$entry->getRawOriginal('actor_id'),
            $reason === null ? null : (string) $reason, $at,
        );
    }

    /**
     * @return list<string>|false|null false when the stored JSON is not a list of names
     */
    private function changed(mixed $raw): array|false|null
    {
        if ($raw === null) {
            return null;
        }

        try {
            $decoded = json_decode((string) $raw, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }

        if (! is_array($decoded) || ! array_is_list($decoded)) {
            return false;
        }

        $names = [];

        foreach ($decoded as $name) {
            if (! is_string($name)) {
                return false;
            }

            $names[] = $name;
        }

        return $names;
    }
}
