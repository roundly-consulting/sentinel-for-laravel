<?php

declare(strict_types=1);

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Sentinel\Actions\Signatures\VerifyRequestSignatureAction;
use RoundlyConsulting\Sentinel\Contracts\Anchor;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneOptions;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Messages\SymfonyRequestView;
use RoundlyConsulting\Sentinel\Http\Signatures\ComponentResolver;
use RoundlyConsulting\Sentinel\Http\Signatures\ProfileResolver;
use RoundlyConsulting\Sentinel\Http\Signatures\SignatureProfile;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Ledger\LedgerVerifier;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * Damaged rows, stale configuration and hand-built inputs end in a finding or a precise
 * exception — never a crash and never a pass (ASVS 11.2.5, fail secure).
 */
it('re-seals a seal row whose MAC was overwritten with garbage, chaining from the garbage bytes', function (): void {
    $invoice = invoice();
    Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->toBase()->update(['mac' => '!!not-base64url!!']);

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Malformed);

    $result = Sentinel::acknowledge($invoice, 'INC-7: seal row overwritten');
    $row = Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->firstOrFail();

    expect($result->acknowledged)->toBeTrue()
        ->and($result->before->status)->toBe(VerificationStatus::Malformed)
        ->and($row->getRawOriginal('previous_digest'))->toBe(Base64Url::encode(hash('sha256', '!!not-base64url!!', true)))
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);
});

it('still reports tampering when the stored field tags are unreadable — only the diagnostics are lost', function (): void {
    $invoice = invoice();

    if (! corrupt(static fn () => DB::table('sentinel_seals')->where('sealable_id', $invoice->id)->where('seal', 'financial')->update(['field_tags' => '{not json']))) {
        return;
    }

    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);
    $result = Sentinel::verify($invoice);

    expect($result->status)->toBe(VerificationStatus::Tampered)
        ->and($result->reason)->toBe('mac')
        ->and($result->changedAttributes)->toBeNull();
});

it('lists ledger history with damaged timestamps and change lists instead of failing', function (): void {
    $invoice = invoice();
    $entry = LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->value('id');

    $time = corrupt(static fn () => DB::table('sentinel_ledger')->where('id', $entry)->update(['occurred_at' => 'not a time']));
    corrupt(static fn () => DB::table('sentinel_ledger')->where('id', $entry)->update(['changed' => '{oops']));
    $record = Sentinel::for($invoice)->history()[0];

    expect($record->id)->toBe($entry)
        ->and($record->version)->toBe(1)
        ->and($record->occurredAt === null)->toBe($time)
        ->and($record->changed)->toBeNull();
});

it('fails ledger entries closed when their ring was removed from the configuration', function (): void {
    config()->set('sentinel.keys.rings.financial', [
        'driver' => 'config', 'algorithms' => ['hmac-sha256'], 'key_id' => 'fin-1', 'algorithm' => 'hmac-sha256', 'key' => TestCase::ROOT_KEY,
    ]);
    $class = definedBy(static fn ($seals) => $seals->seal('ledgered')->attributes('number')->ring('financial'));
    $class::query()->create(['number' => 'R-1']);

    expect(Sentinel::verifyLedger()->clean())->toBeTrue();

    $rings = config('sentinel.keys.rings');
    unset($rings['financial']);
    config()->set('sentinel.keys.rings', $rings);
    app(KeyStoreManager::class)->flush();

    $findings = Sentinel::verifyLedger()->findings;

    expect(array_map(static fn ($finding) => $finding->kind, $findings))->toBe([LedgerFindingKind::EntryInvalid])
        ->and($findings[0]->sealableType)->toBe($class);
});

it('rejects a hand-built signature profile whose ring is not configured as an unknown key', function (): void {
    partnerRing();
    $default = ProfileResolver::resolve();
    $ghost = new SignatureProfile(
        $default->name, 'ghost', $default->label, $default->tag, $default->components, $default->requireQuery,
        $default->requireContentDigest, $default->requireNonce, $default->maxAge, $default->clockSkew, $default->algorithms,
    );

    expect(fn () => app(VerifyRequestSignatureAction::class)->execute(received(signedPartnerRequest()), $ghost))
        ->toThrow(fn (HttpSignatureException $exception) => expect($exception->reason())->toBe(SignatureRejection::UnknownKey));
});

it('refuses unsupported derived components even when the resolver is called directly', function (string $component): void {
    expect(fn () => ComponentResolver::value(new SymfonyRequestView(Request::create('https://api.example.com/x')), $component))
        ->toThrow(fn (HttpSignatureException $exception) => expect($exception->reason())->toBe(SignatureRejection::UnsupportedComponent));
})->with(['@request-target', '@query-param', '@unknown']);

it('surfaces an anchor configuration error instead of recording a failed publication', function (): void {
    Sentinel::extendAnchor('picky', static fn (Container $app, array $config): Anchor => new class implements Anchor
    {
        public function name(): string
        {
            return 'picky';
        }

        public function publish(AnchorPayload $payload): void
        {
            throw InvalidSentinelConfigurationException::invalidValue('ledger.anchor_drivers.picky.bucket', 'is required');
        }

        public function latest(string $connection): ?AnchorPayload
        {
            return null;
        }
    });
    config()->set('sentinel.ledger.anchors', 'picky');
    invoice();

    expect(fn () => Sentinel::checkpoint())->toThrow(InvalidSentinelConfigurationException::class, 'picky.bucket');
});

it('treats a checkpoint without a creation time as malformed', function (): void {
    invoice();
    Sentinel::checkpoint();
    $checkpoint = Checkpoint::query()->firstOrFail();
    // NOT NULL in the schema; a host that relaxed the column must still fail closed.
    $checkpoint->setRawAttributes(['created_at' => null] + $checkpoint->getAttributes(), true);
    $verifier = app(LedgerVerifier::class);

    expect((new ReflectionMethod($verifier, 'checkpointProblem'))->invoke($verifier, $checkpoint))->toBe('malformed');
});

it('stops a re-seal run when the acknowledgement policy refuses', function (): void {
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);
    config()->set('sentinel.acknowledgement.ability', 'acknowledge-tampering');
    Gate::define('acknowledge-tampering', static fn (): bool => false);

    expect(fn () => Sentinel::model(Invoice::class)->reseal('financial', acknowledgeReason: 'INC-9'))
        ->toThrow(AcknowledgementDeniedException::class)
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Tampered);
});

it('counts expired idempotency keys on a dry run without deleting them', function (): void {
    IdempotencyKey::factory()->expired()->count(2)->create();
    IdempotencyKey::factory()->completed()->create();

    expect(Sentinel::prune(new PruneOptions(dryRun: true))->idempotencyKeys)->toBe(2)
        ->and(IdempotencyKey::query()->count())->toBe(3)
        ->and(Artisan::call('sentinel:prune', ['--idempotency' => true]))->toBe(0)
        ->and(IdempotencyKey::query()->count())->toBe(1);
});
