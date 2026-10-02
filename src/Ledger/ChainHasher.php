<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Ledger;

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Sentinel\Canonical\BinarySafe;
use RoundlyConsulting\Sentinel\Canonical\Jcs;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;

/**
 * The hash chain a checkpoint commits to (plan §4.7.2):
 *
 *     h0 = previous root bytes (32 × 0x00 for the first checkpoint)
 *     hi = SHA-256("sentinel.chain/1" ‖ 0x00 ‖ hi-1 ‖ SHA-256(LedgerMessage(ei) ‖ 0x00 ‖ entry_mac(ei)))
 *     root = base64url(hn)
 *
 * The leaf is built from the stored columns only (with the stored algorithm), so the chain
 * commits to exactly what the database holds and can be recomputed even when a key is gone;
 * a row too damaged to read as a document is committed to through its raw columns, so a
 * corrupt entry can still be checkpointed (and is reported by its own MAC check).
 *
 * @internal
 */
final readonly class ChainHasher
{
    public const string DOMAIN = 'sentinel.chain/1';

    public function __construct(private Digest $digest = new Digest) {}

    /**
     * The chain state a checkpoint starts from: the previous root's bytes (zeros for none).
     */
    public function start(?string $previousRoot): string
    {
        if ($previousRoot === null) {
            return str_repeat("\0", 32);
        }

        try {
            $bytes = Base64Url::decode($previousRoot);
        } catch (InvalidEncodingException) {
            $bytes = '';
        }

        // A damaged stored root still yields a deterministic (and mismatching) chain.
        return strlen($bytes) === 32 ? $bytes : $this->digest->raw($previousRoot);
    }

    public function next(string $state, LedgerEntry $entry): string
    {
        return $this->digest->raw(self::DOMAIN."\0".$state.$this->leaf($entry));
    }

    public function root(string $state): string
    {
        return Base64Url::encode($state);
    }

    public function leaf(LedgerEntry $entry): string
    {
        try {
            $document = StoredEntry::message($entry)?->bytes();
        } catch (CanonicalizationException) {
            $document = null;
        }

        $document ??= Jcs::encode(['sentinel.ledger-raw/1', ...array_map(BinarySafe::value(...), StoredEntry::rawColumns($entry))]);

        $mac = (string) $entry->getRawOriginal('entry_mac');

        try {
            $macBytes = Base64Url::decode($mac);
        } catch (InvalidEncodingException) {
            $macBytes = $mac;
        }

        return $this->digest->raw($document."\0".$macBytes);
    }
}
