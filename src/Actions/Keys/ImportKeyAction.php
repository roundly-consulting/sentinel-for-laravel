<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Keys;

use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Sentinel\DataTransferObjects\ImportKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Events\KeyImported;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Keys\ImportedMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Import existing key material into a ring's database store — onboard a partner at runtime
 * (their public key or an agreed HMAC secret, bound to the owner model) or move your own key
 * pair from the environment into the database. An imported key is verify-only unless it was
 * imported with `signing: true` and holds private/secret material; its status is bound into
 * the encrypted envelope, so it cannot be flipped in SQL. The kid must be free in the whole
 * ring (configuration side of a chain ring included); the database's unique index settles a
 * race between two imports.
 */
final readonly class ImportKeyAction
{
    public function __construct(
        private KeyStoreManager $keys,
        private Dispatcher $events,
        private Runtime $runtime,
    ) {}

    public function execute(ImportKeyRequest $request): KeyInfo
    {
        $config = Settings::ring($request->ring);

        if (! $config->allows($request->algorithm)) {
            throw AlgorithmNotAllowedException::forRing($request->ring, $request->algorithm);
        }

        if (! Identifiers::isKeyId($request->keyId)) {
            throw KeyDriverException::invalidKeyId($request->ring);
        }

        if ($request->label !== null && (! mb_check_encoding($request->label, 'UTF-8') || mb_strlen($request->label) > 191)) {
            throw KeyDriverException::invalidLabel();
        }

        $store = $this->keys->writableStore($request->ring);
        $material = ImportedMaterial::parse($request->algorithm, $request->material, $request->signing);

        if ($this->keys->find($request->ring, $request->keyId) !== null) {
            throw KeyDriverException::keyIdTaken($request->ring, $request->keyId);
        }

        $signing = $request->signing && $material->canSign();
        $key = $store->insert(
            $request->keyId, $material, $request->activatesAt ?? Clock::now(), $request->owner, $request->label,
            $signing ? KeyStatus::Active : KeyStatus::VerifyOnly,
        );

        $actor = $this->runtime->user();
        $this->events->dispatch(new KeyImported(
            $request->ring, $request->keyId, $request->algorithm, $signing, $actor?->getMorphClass(), $actor?->getKey(),
        ));

        return KeyInfo::fromKey($key);
    }
}
