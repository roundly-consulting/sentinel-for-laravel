<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Engine;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Log\LogManager;
use JsonException;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Sentinel\Canonical\FieldTagger;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;
use RoundlyConsulting\Sentinel\Definition\ManifestField;
use RoundlyConsulting\Sentinel\Definition\SealType;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;

/**
 * The one verifier behind every verification path (plan §4.6 / §9.5): the API, the pre-write
 * check, and — later — middleware, rules, macros, retrieve hooks and scans all run this, so a
 * status can never differ by entry point.
 *
 * Key, ring and algorithm checks run before any MAC is computed; the algorithm always comes
 * from the key. Fails closed: anything unreadable is a finding, never "intact". Read-only,
 * except that the pre-write check locks the seal row.
 *
 * @internal
 */
final readonly class Verifier
{
    public function __construct(
        private KeyStoreManager $keys,
        private Signers $signers,
        private FieldTagger $tagger,
        private ReadBack $readBack,
        private DocumentBuilder $documents,
        private LedgerWriter $ledger,
        private Sealer $sealer,
        private Dispatcher $events,
        private LogManager $log,
    ) {}

    /**
     * Contexts whose models were just loaded from the database: their raw original attributes
     * (and eager-loaded seal rows) are exactly what the database held, so a second read is
     * not needed.
     */
    private const array FRESH_CONTEXTS = [
        VerificationContext::Retrieve,
        VerificationContext::Middleware,
        VerificationContext::Command,
        VerificationContext::Rule,
        VerificationContext::Collection,
    ];

    /**
     * @param  bool  $report  announce a failure (`TamperDetected` + a warning log); the
     *                        retrieve hook reports per its configured reaction instead
     */
    public function verify(Model $model, CompiledSeal $seal, VerificationContext $context, bool $checkLedger, bool $lock = false, bool $report = true): VerificationResult
    {
        $result = $this->evaluate($model, $seal, $context, $checkLedger && Settings::ledgerEnabled(), $lock);

        if ($report && $result->failed()) {
            $this->report($result);
        }

        return $result;
    }

    public function dispatchTamperDetected(VerificationResult $result): void
    {
        $this->events->dispatch(new TamperDetected(
            $result->sealableType, $result->sealableId, $result->seal, $result->status, $result->reason,
            $result->changedAttributes, $result->context, $result->keyId,
        ));
    }

    public function logFinding(VerificationResult $result): void
    {
        $this->log->channel(Settings::logChannel())->warning('Sentinel: a sealed model is not intact.', [
            'sealable_type' => $result->sealableType,
            'sealable_id' => $result->sealableId,
            'seal' => $result->seal,
            'status' => $result->status->value,
            'reason' => $result->reason,
            'changed_attributes' => $result->changedAttributes,
            'context' => $result->context->value,
        ]);
    }

    /**
     * Announce a finding: `TamperDetected` (synchronously) and a warning log line — names and
     * statuses only, never values.
     */
    public function report(VerificationResult $result): void
    {
        $this->dispatchTamperDetected($result);
        $this->logFinding($result);
    }

    private function evaluate(Model $model, CompiledSeal $seal, VerificationContext $context, bool $checkLedger, bool $lock): VerificationResult
    {
        $row = $this->sealRow($model, $seal, $context, $lock);
        $outcome = new Outcome($model, $seal->name, $context, Settings::outdatedIsIntact());

        if ($row === null) {
            return $this->unsealed($model, $seal, $outcome);
        }

        $outcome = $outcome->withRow(
            (int) $row->getRawOriginal('version'), (string) $row->getRawOriginal('ring'), (string) $row->getRawOriginal('key_id'),
        );

        $manifest = $this->manifest($row->getRawOriginal('manifest'));
        $sealedAt = $this->sealedAt($row);
        $mac = $this->mac($row);

        $malformed = match (true) {
            (int) $row->getRawOriginal('format') !== 1 => 'format',
            $manifest === null => 'manifest',
            $mac === null => 'mac',
            (int) $row->getRawOriginal('version') < 1 => 'version',
            $sealedAt === null => 'sealed_at',
            default => null,
        };

        if ($malformed !== null) {
            return $outcome->result(VerificationStatus::Malformed, $malformed);
        }

        $key = $this->key($seal, $outcome);

        if (! $key instanceof SealingKey) {
            return $key;
        }

        $outcome = $outcome->withAlgorithm($key->algorithm(), $sealedAt);

        if ((string) $row->getRawOriginal('algorithm') !== $key->algorithm()->value) {
            return $outcome->result(VerificationStatus::AlgorithmMismatch);
        }

        $fields = $this->fields($seal, $manifest);

        if ($fields === null) {
            return $outcome->result(VerificationStatus::Unverifiable, 'missing_computed');
        }

        $columns = array_values(array_filter(array_map(static fn (ManifestField $field): ?string => $field->column, $fields)));
        $values = $this->values($model, $seal, $columns, $context, $lock);

        foreach ($columns as $column) {
            if ($values === null || ! array_key_exists($column, $values)) {
                return $outcome->result(VerificationStatus::Unverifiable, 'missing_attribute');
            }
        }

        try {
            $message = $this->documents->build(
                $model, $seal, $fields, (array) $values, (string) $outcome->ring, (string) $outcome->keyId, $key->algorithm(),
                (int) $outcome->version, $this->nullableString($row->getRawOriginal('previous_digest')), $sealedAt,
            );
        } catch (CanonicalizationException) {
            return $outcome->result(VerificationStatus::Tampered, 'canonicalization');
        }

        if (! $this->signers->verify($key, Purpose::Seal, $message->bytes(), $mac)) {
            $stored = $this->tags($row->getRawOriginal('field_tags'));
            $current = $stored === null ? null : $this->tagger->tags($key, $message);

            return $outcome->result(VerificationStatus::Tampered, 'mac', $stored === null || $current === null ? null : $this->tagger->changed($stored, $current));
        }

        if ($checkLedger) {
            $stale = $this->ledgerFinding($model, $seal, $row, $outcome);

            if ($stale !== null) {
                return $stale;
            }
        }

        if ($manifest !== $seal->manifest()) {
            return $outcome->result(VerificationStatus::Outdated);
        }

        return $outcome->result(VerificationStatus::Intact);
    }

    /**
     * The stored seal row — reused from an eager-loaded `sentinelSeals` relation of a model
     * that was just loaded (never under the pre-write lock). A row absent from the loaded
     * relation is looked up anyway: the eager load may have been constrained.
     */
    private function sealRow(Model $model, CompiledSeal $seal, VerificationContext $context, bool $lock): ?Seal
    {
        if (! $lock && self::fresh($model, $context) && $model->relationLoaded('sentinelSeals')) {
            $loaded = $model->getRelation('sentinelSeals');

            foreach ($loaded instanceof Collection ? $loaded : [] as $candidate) {
                if ($candidate instanceof Seal && (string) $candidate->getRawOriginal('seal') === $seal->name) {
                    return $candidate;
                }
            }
        }

        $query = Tables::seals($model, $seal->name);

        return ($lock ? $query->lockForUpdate() : $query)->first();
    }

    /**
     * The raw values to verify (plan §9.5): a just-loaded model's raw original attributes when
     * they hold every manifest column, else a fresh read. Verify-on-retrieve never reads
     * again: a partial `select()` is unverifiable, not a finding. Seals with a scope or
     * computed fields always read the whole row (their closures need the stored model).
     *
     * @param  list<string>  $columns
     * @return array<string, mixed>|null
     */
    private function values(Model $model, CompiledSeal $seal, array $columns, VerificationContext $context, bool $lock): ?array
    {
        if (! $lock && ! $seal->needsSubject() && self::fresh($model, $context)) {
            $original = $model->getRawOriginal();

            if (array_diff($columns, array_keys($original)) === []) {
                return $original;
            }

            if ($context === VerificationContext::Retrieve) {
                return null;
            }
        }

        // Under the pre-write lock the read must be a locking one too: on MySQL REPEATABLE
        // READ a plain read can return the transaction's older snapshot, and verifying that
        // instead of the row as it is would let a concurrent out-of-band change be re-sealed.
        return $this->readBack->row($model, $seal->needsSubject() ? ['*'] : $columns, $lock);
    }

    /**
     * A model whose original attributes still mirror the database (just loaded, not saved
     * since — a save syncs the original from in-memory values, not from the row).
     */
    private static function fresh(Model $model, VerificationContext $context): bool
    {
        return in_array($context, self::FRESH_CONTEXTS, true) && $model->exists && ! $model->wasRecentlyCreated && $model->getChanges() === [];
    }

    /**
     * Rows 2–4: no seal row.
     */
    private function unsealed(Model $model, CompiledSeal $seal, Outcome $outcome): VerificationResult
    {
        $head = $this->sealer->head($model, $seal->name);
        $event = $head === null ? null : SealEvent::tryFrom((string) $head->getRawOriginal('event'));
        $headVersion = $head === null ? null : (int) $head->getRawOriginal('version');

        if ($head !== null && ($event === null || ! $event->isTombstone())) {
            return $outcome->result(VerificationStatus::Missing, 'seal_deleted', ledgerVersion: $headVersion);
        }

        if ($seal->strict) {
            return $outcome->result(VerificationStatus::Missing, $event === SealEvent::Unsealed ? 'unsealed' : 'never_sealed', ledgerVersion: $headVersion);
        }

        return $outcome->result(VerificationStatus::Unsealed, ledgerVersion: $headVersion);
    }

    /**
     * Rows 6–10: ring, key, key status and algorithm allow-lists — before any MAC.
     */
    private function key(CompiledSeal $seal, Outcome $outcome): SealingKey|VerificationResult
    {
        $ring = (string) $outcome->ring;

        if (! $seal->acceptsRing($ring)) {
            return $outcome->result(VerificationStatus::UnknownKey, 'ring_not_accepted');
        }

        $lookup = $this->keys->lookup($ring, (string) $outcome->keyId);
        $key = $lookup->key;

        return match (true) {
            $key === null => $outcome->result(VerificationStatus::UnknownKey, $lookup->failure),
            $key->status === KeyStatus::Pending => $outcome->result(VerificationStatus::UnknownKey, 'pending'),
            $key->status === KeyStatus::Revoked => $outcome->result(VerificationStatus::RevokedKey),
            $key->status === KeyStatus::Retired => $outcome->result(VerificationStatus::RetiredKey),
            ! $seal->allows($key->algorithm()) || ! Settings::ring($ring)->allows($key->algorithm()) => $outcome->withAlgorithm($key->algorithm())->result(VerificationStatus::AlgorithmNotAllowed),
            default => $key,
        };
    }

    /**
     * Rows 15–18, one indexed query: the ledger must hold this exact seal as its latest entry,
     * with an intact entry MAC.
     */
    private function ledgerFinding(Model $model, CompiledSeal $seal, Seal $row, Outcome $outcome): ?VerificationResult
    {
        $version = (int) $outcome->version;
        $entries = Tables::entries($model, $seal->name)->where('version', '>=', $version)->orderByDesc('version')->limit(2)->get();
        $top = $entries->first();

        if ($top !== null && (int) $top->getRawOriginal('version') > $version) {
            return $outcome->result(VerificationStatus::Stale, 'newer_version', ledgerVersion: (int) $top->getRawOriginal('version'));
        }

        if ($top === null) {
            return $outcome->result(VerificationStatus::Stale, 'not_in_ledger');
        }

        if (! ConstantTime::equals((string) $row->getRawOriginal('mac'), (string) $top->getRawOriginal('seal_mac'))) {
            return $outcome->result(VerificationStatus::Stale, 'ledger_mismatch', ledgerVersion: $version);
        }

        // The entry must be vouched for by a key of a ring this seal accepts.
        if (! $this->ledger->verify($top, $model, [$seal->ring, ...$seal->acceptRings])) {
            return $outcome->result(VerificationStatus::Tampered, 'ledger_entry', ledgerVersion: $version);
        }

        return null;
    }

    /**
     * The stored manifest rebuilt as fields: attributes by column, computed fields by the
     * current resolver (null when one is no longer declared).
     *
     * @param  list<list<string>>  $manifest
     * @return list<ManifestField>|null
     */
    private function fields(CompiledSeal $seal, array $manifest): ?array
    {
        $fields = [];

        foreach ($manifest as [$name, $tag]) {
            $type = SealType::tryFromTag($tag) ?? SealType::auto();

            if (str_starts_with($name, 'a:')) {
                $fields[] = ManifestField::attribute(substr($name, 2), $type);

                continue;
            }

            $current = $seal->field($name);

            if ($current?->resolver === null) {
                return null;
            }

            $fields[] = ManifestField::computed(substr($name, 2), $type, $current->resolver);
        }

        return $fields;
    }

    /**
     * @return list<list<string>>|null null unless a list of `[a:column|c:name, tag]` pairs with valid tags
     */
    private function manifest(mixed $raw): ?array
    {
        try {
            $decoded = json_decode((string) $raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (! is_array($decoded) || $decoded === [] || ! array_is_list($decoded)) {
            return null;
        }

        $manifest = [];

        foreach ($decoded as $pair) {
            if (! is_array($pair) || count($pair) !== 2 || ! array_is_list($pair) || ! is_string($pair[0]) || ! is_string($pair[1])
                || preg_match('/^(a:[A-Za-z_][A-Za-z0-9_]{0,63}|c:[a-z][a-z0-9_]{0,63})$/D', $pair[0]) !== 1
                || SealType::tryFromTag($pair[1]) === null) {
                return null;
            }

            $manifest[] = [$pair[0], $pair[1]];
        }

        return $manifest;
    }

    /**
     * @return array<array-key, mixed>|null
     */
    private function tags(mixed $raw): ?array
    {
        if ($raw === null) {
            return null;
        }

        try {
            $decoded = json_decode((string) $raw, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        return is_array($decoded) ? $decoded : null;
    }

    private function mac(Seal $row): ?string
    {
        try {
            return Base64Url::decode((string) $row->getRawOriginal('mac'));
        } catch (InvalidEncodingException) {
            return null;
        }
    }

    private function sealedAt(Seal $row): ?CarbonImmutable
    {
        try {
            return (new UtcDateTime)->get($row, 'sealed_at', $row->getRawOriginal('sealed_at'), []);
        } catch (CorruptRecordException) {
            return null;
        }
    }

    private function nullableString(mixed $value): ?string
    {
        return $value === null ? null : (string) $value;
    }
}
