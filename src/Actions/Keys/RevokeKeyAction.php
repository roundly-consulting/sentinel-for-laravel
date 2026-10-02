<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Keys;

use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Events\KeyRevoked;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\UnknownKeyException;
use RoundlyConsulting\Sentinel\Keys\EnvelopeData;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Revoke a database key (it will neither sign nor verify again). A kid of another ring is
 * unknown here. Config keys are revoked by listing `ring:kid` in `SENTINEL_REVOKED_KEYS`,
 * which also beats any database state.
 */
final readonly class RevokeKeyAction
{
    public function __construct(
        private KeyStoreManager $keys,
        private Dispatcher $events,
    ) {}

    public function execute(RevokeKeyRequest $request): KeyInfo
    {
        Settings::ring($request->ring);

        $reason = trim($request->reason);

        if ($reason === '' || mb_strlen($reason) > 1000) {
            throw KeyDriverException::reasonRequired();
        }

        $key = $this->keys->find($request->ring, $request->keyId)
            ?? throw UnknownKeyException::inRing($request->ring, $request->keyId);

        if ($key->driver !== 'database') {
            throw KeyDriverException::notStoredInDatabase($request->ring, $request->keyId);
        }

        $now = Clock::now();
        $revoked = $this->keys->writableStore($request->ring)->update(
            $request->keyId,
            static fn (EnvelopeData $data): EnvelopeData => $data->with(status: KeyStatus::Revoked->value, revokedAt: $data->revokedAt ?? $now),
            $reason,
        );

        $this->events->dispatch(new KeyRevoked(
            $request->ring, $request->keyId, $revoked->algorithm(), $reason,
            $request->actor?->getMorphClass(), $request->actor?->getKey(),
        ));

        return KeyInfo::fromKey($revoked);
    }
}
