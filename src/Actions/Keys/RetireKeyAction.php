<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Keys;

use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Events\KeyRetired;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\UnknownKeyException;
use RoundlyConsulting\Sentinel\Keys\EnvelopeData;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Retire a database key: its verification period ends now (NIST SP 800-57), so seals still
 * using it report `retired_key` — re-seal them first (`sentinel:reseal --from-key`).
 */
final readonly class RetireKeyAction
{
    public function __construct(
        private KeyStoreManager $keys,
        private Dispatcher $events,
    ) {}

    public function execute(string $ring, string $keyId): KeyInfo
    {
        Settings::ring($ring);

        $key = $this->keys->find($ring, $keyId) ?? throw UnknownKeyException::inRing($ring, $keyId);

        if ($key->driver !== 'database') {
            throw KeyDriverException::notStoredInDatabase($ring, $keyId);
        }

        $now = Clock::now();
        $retired = $this->keys->writableStore($ring)->update(
            $keyId,
            static fn (EnvelopeData $data): EnvelopeData => $data->with(
                status: KeyStatus::Retired->value,
                verifiesUntil: $data->verifiesUntil !== null && $data->verifiesUntil->lessThan($now) ? $data->verifiesUntil : $now,
            ),
        );

        $this->events->dispatch(new KeyRetired($ring, $keyId, $retired->algorithm()));

        return KeyInfo::fromKey($retired);
    }
}
