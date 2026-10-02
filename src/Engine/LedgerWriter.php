<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Engine;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Sentinel\Canonical\LedgerMessage;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Exceptions\ConcurrentSealException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Ledger\StoredEntry;
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
     * Whether a stored entry still carries a valid MAC over its audit fields. The key must
     * come from one of the accepted rings (a partner's HTTP key can never vouch for the
     * ledger); the identity is the given sealable's (re-pointing an entry breaks its MAC),
     * else the stored one. `historic` also accepts a retired key: the ledger is permanent
     * evidence and outlives the keys' verification periods — revoked keys never verify.
     * Any unreadable column, unknown key or unusable key status fails closed.
     *
     * @param  list<string>  $acceptedRings
     */
    public function verify(LedgerEntry $entry, ?Model $model, array $acceptedRings, bool $historic = false): bool
    {
        $ring = (string) $entry->getRawOriginal('ring');

        if (! in_array($ring, $acceptedRings, true)) {
            return false;
        }

        try {
            $key = $this->keys->find($ring, (string) $entry->getRawOriginal('key_id'));
        } catch (SealingMisconfiguredException) {
            return false;
        }

        $usable = $key !== null && ($key->canVerify() || ($historic && $key->status === KeyStatus::Retired));

        // The algorithm comes from the key; a stored one that disagrees was edited.
        if (! $usable || (string) $entry->getRawOriginal('algorithm') !== $key->algorithm()->value) {
            return false;
        }

        try {
            $message = StoredEntry::message($entry, $key->algorithm(), $model?->getMorphClass(), $model === null ? null : (string) $model->getKey());
            $bytes = $message?->bytes();
            $mac = Base64Url::decode((string) $entry->getRawOriginal('entry_mac'));
        } catch (InvalidEncodingException|CanonicalizationException) {
            return false;
        }

        return $bytes !== null && $this->signers->verify($key, Purpose::Ledger, $bytes, $mac);
    }
}
