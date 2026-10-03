<?php

declare(strict_types=1);

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\SealingSuspended;
use RoundlyConsulting\Sentinel\Events\TamperAcknowledged;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Exceptions\SealingSuspensionNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

function tampered(): Invoice
{
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00', 'status' => 'void']);

    return $invoice;
}

/**
 * §10 item 13.
 */
it('acknowledges an out-of-band change with actor, reason and changed attributes in the MAC\'d ledger', function (): void {
    Event::fake([TamperAcknowledged::class]);
    $admin = User::query()->create(['name' => 'Admin']);
    $invoice = tampered();

    $result = Sentinel::for($invoice)->by($admin)->because('  INC-88: fixed by the DBA  ')->acknowledge();

    $entry = LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->orderByDesc('version')->firstOrFail();

    expect($result->acknowledged)->toBeTrue()
        ->and($result->before->status)->toBe(VerificationStatus::Tampered)
        ->and($result->seal?->event)->toBe(SealEvent::Acknowledged)
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact)
        ->and($entry->reason)->toBe('INC-88: fixed by the DBA')
        ->and($entry->changed)->toBe(['a:amount', 'a:status'])
        ->and($entry->previous_status)->toBe('tampered')
        ->and((string) $entry->actor_id)->toBe((string) $admin->id)
        ->and(Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->value('reason'))->toBe('INC-88: fixed by the DBA');

    Event::assertDispatched(TamperAcknowledged::class, static fn (TamperAcknowledged $event): bool => $event->previousStatus === VerificationStatus::Tampered && $event->changedAttributes === ['a:amount', 'a:status']);

    // The audit fields are MAC-covered: editing the reason breaks the entry.
    LedgerEntry::query()->whereKey($entry->id)->toBase()->update(['reason' => 'nothing to see']);

    expect(Sentinel::verify($invoice)->reason)->toBe('ledger_entry');
});

it('leaves an intact model alone', function (): void {
    $invoice = invoice();

    $result = $invoice->acknowledgeTampering('nothing happened');

    expect($result->acknowledged)->toBeFalse()->and($result->seal)->toBeNull()
        ->and(LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->count())->toBe(1);
});

it('requires a reason, bounded in length', function (string $reason, string $message): void {
    config()->set('sentinel.sealing.reason_max_length', 10);

    expect(fn () => Sentinel::acknowledge(tampered(), $reason))->toThrow(AcknowledgementDeniedException::class, $message);
})->with([
    'empty' => ['', 'A reason is required'],
    'blank' => ['   ', 'A reason is required'],
    'too long' => ['eleven chars', 'at most 10'],
]);

it('requires an actor outside the console and uses the logged-in user', function (): void {
    app()->instance(Runtime::class, new Runtime(app(), console: false));

    expect(fn () => Sentinel::acknowledge(tampered(), 'fix'))->toThrow(AcknowledgementDeniedException::class, 'actor is required');

    $user = User::query()->create(['name' => 'Ops']);
    $this->actingAs($user);

    $result = Sentinel::acknowledge(tampered(), 'fix');

    expect($result->acknowledged)->toBeTrue()
        ->and((string) LedgerEntry::query()->orderByDesc('id')->value('actor_id'))->toBe((string) $user->id);
});

it('checks the configured Gate ability', function (): void {
    config()->set('sentinel.acknowledgement.ability', 'acknowledge-tampering');
    $admin = User::query()->create(['name' => 'Admin']);
    $intern = User::query()->create(['name' => 'Intern']);
    Gate::define('acknowledge-tampering', static fn (User $user, Invoice $invoice, string $seal): bool => $user->name === 'Admin' && $seal === 'financial');

    expect(fn () => Sentinel::acknowledge(tampered(), 'fix', $intern))->toThrow(AcknowledgementDeniedException::class, 'unauthorized')
        ->and(Sentinel::acknowledge(tampered(), 'fix', $admin)->acknowledged)->toBeTrue();
});

it('seals explicitly, refusing to launder a tampered model', function (): void {
    $invoice = invoice();
    Sentinel::unseal($invoice, 'INC-3: re-imported', seal: 'identity');

    // A lenient seal deliberately unsealed → an explicit seal is the way back.
    expect($invoice->seal('identity')->event)->toBe(SealEvent::Sealed)
        ->and($invoice->seal()->event)->toBe(SealEvent::Resealed);

    $tampered = tampered();

    expect(fn () => $tampered->seal())->toThrow(TamperedModelException::class)
        ->and(fn () => Sentinel::seal(new Invoice))->toThrow(SealingFailedException::class, 'persisted');
});

it('seals explicitly after computed fields drifted, recording the drift', function (): void {
    $invoice = invoice();
    $invoice->lines()->create(['sku' => 'B', 'quantity' => 2]);

    $result = Sentinel::for($invoice)->because('lines changed')->seal();
    $entry = LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->orderByDesc('version')->firstOrFail();

    expect($result->event)->toBe(SealEvent::Resealed)
        ->and($entry->changed)->toBe(['c:lines'])
        ->and($entry->previous_status)->toBe('tampered')
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);
});

it('unseals deliberately with a tombstone', function (): void {
    $invoice = invoice();

    expect(Sentinel::for($invoice, 'identity')->because('archived')->unseal())->toBeTrue()
        ->and(Sentinel::verify($invoice, 'identity')->status)->toBe(VerificationStatus::Unsealed)
        ->and(Sentinel::unseal($invoice, 'again', seal: 'identity'))->toBeFalse()
        ->and(Sentinel::unseal($invoice, 'financial too'))->toBeTrue()
        ->and(Sentinel::verify($invoice)->reason)->toBe('unsealed')
        ->and(fn () => Sentinel::unseal($invoice, ''))->toThrow(AcknowledgementDeniedException::class);

    $history = Sentinel::for($invoice, 'identity')->history();

    expect($history[0]->event)->toBe(SealEvent::Unsealed)
        ->and($history[0]->reason)->toBe('archived')
        ->and($history[0]->previousStatus)->toBe(VerificationStatus::Intact)
        ->and($history[1]->event)->toBe(SealEvent::Sealed)
        ->and(Sentinel::for($invoice)->current())->toBeNull()
        ->and(Sentinel::for($invoice, 'identity')->name())->toBe('identity');
});

it('exposes the current seal row and the ledger history', function (): void {
    $actor = User::query()->create(['name' => 'Ops']);
    $invoice = invoice();
    Sentinel::for($invoice)->by($actor)->because('checked')->seal();

    $current = Sentinel::for($invoice)->current();
    $history = Sentinel::ledgerHistory($invoice, limit: 1);

    expect($current?->version)->toBe(2)
        ->and($current?->manifest[0])->toBe(['a:amount', 'dec:2'])
        ->and($current?->event)->toBe(SealEvent::Resealed)
        ->and($current?->reason)->toBe('checked')
        ->and((string) $current?->sealedById)->toBe((string) $actor->id)
        ->and($current?->sealedAt?->getTimezone()->getName())->toBe('UTC')
        ->and($history)->toHaveCount(1)
        ->and($history[0]->version)->toBe(2)
        ->and($history[0]->checkpointId)->toBeNull()
        ->and(Sentinel::for($invoice)->definition()->name)->toBe('financial');
});

/**
 * §10 item 16: suspension.
 */
it('suspends sealing for a callback, restores it even on failure, and audits it', function (): void {
    Event::fake([SealingSuspended::class]);
    config()->set('sentinel.sealing.allow_suspension', true);

    $inside = Sentinel::withoutSealing(function (): Invoice {
        return Sentinel::withoutSealing(fn (): Invoice => invoice(), 'nested');
    }, 'seeding');

    try {
        Sentinel::withoutSealing(fn () => throw new RuntimeException('boom'), 'failing');
    } catch (RuntimeException) {
    }

    $after = invoice();

    expect(Sentinel::verify($inside)->reason)->toBe('never_sealed')
        ->and(Sentinel::verify($after)->status)->toBe(VerificationStatus::Intact)
        ->and(app(SealingScope::class)->sealingSuspended())->toBeFalse();

    Event::assertDispatched(SealingSuspended::class, 3);
    Event::assertDispatched(SealingSuspended::class, static fn (SealingSuspended $event): bool => $event->reason === 'seeding');
});

it('never lets a suspension outlive its request or job', function (): void {
    $scope = app(SealingScope::class);

    $scope->withoutSealing(function () use ($scope): void {
        app()->forgetScopedInstances();

        expect(app(SealingScope::class))->not->toBe($scope)
            ->and(app(SealingScope::class)->sealingSuspended())->toBeFalse();
    });
});

it('refuses suspension when it is disabled', function (): void {
    config()->set('sentinel.sealing.allow_suspension', 'no');

    expect(fn () => Sentinel::withoutSealing(fn () => null, 'x'))->toThrow(SealingSuspensionNotAllowedException::class)
        ->and(fn () => Sentinel::withoutSealing(fn () => null, ''))->toThrow(SealingSuspensionNotAllowedException::class);
});

/**
 * Owner 2026-10-03: suspension is an explicit opt-in. A key that is not set — absent, null or
 * blank (`SENTINEL_ALLOW_SUSPENSION=`) — takes the shipped default, which is off, so seal
 * protection never pauses by accident.
 */
it('refuses suspension unless the host opts in', function (Closure $leaveUnset): void {
    Event::fake([SealingSuspended::class]);
    $leaveUnset();
    $ran = false;

    expect(function () use (&$ran): void {
        Sentinel::withoutSealing(function () use (&$ran): void {
            $ran = true;
        }, 'import');
    })->toThrow(SealingSuspensionNotAllowedException::class)
        ->and($ran)->toBeFalse()
        ->and(app(SealingScope::class)->sealingSuspended())->toBeFalse();

    Event::assertNotDispatched(SealingSuspended::class);
})->with([
    'the shipped config' => [static function (): void {}],
    'absent' => [static fn () => config()->set('sentinel.sealing', Arr::except((array) config('sentinel.sealing'), 'allow_suspension'))],
    'null' => [static fn () => config()->set('sentinel.sealing.allow_suspension', null)],
    'blank' => [static fn () => config()->set('sentinel.sealing.allow_suspension', '')],
    'whitespace' => [static fn () => config()->set('sentinel.sealing.allow_suspension', "  \t")],
]);

it('ships suspension off, also behind a blank SENTINEL_ALLOW_SUSPENSION=', function (?string $env): void {
    $previous = getenv('SENTINEL_ALLOW_SUSPENSION');
    putenv($env === null ? 'SENTINEL_ALLOW_SUSPENSION' : "SENTINEL_ALLOW_SUSPENSION={$env}");

    try {
        $shipped = (require __DIR__.'/../../../config/sentinel.php')['sealing']['allow_suspension'];
    } finally {
        putenv($previous === false ? 'SENTINEL_ALLOW_SUSPENSION' : "SENTINEL_ALLOW_SUSPENSION={$previous}");
    }

    config()->set('sentinel.sealing.allow_suspension', $shipped);

    expect($shipped)->toBe($env ?? false)
        ->and(Settings::allowSuspension())->toBeFalse()
        ->and(fn () => Sentinel::withoutSealing(fn () => null, 'import'))->toThrow(SealingSuspensionNotAllowedException::class);
})->with(['unset' => [null], 'blank' => ['']]);

it('allows suspension once the host opts in', function (string|bool $value): void {
    Event::fake([SealingSuspended::class]);
    config()->set('sentinel.sealing.allow_suspension', $value);

    expect(Settings::allowSuspension())->toBeTrue()
        ->and(Sentinel::withoutSealing(static fn (): string => 'ran', 'import'))->toBe('ran');

    Event::assertDispatched(SealingSuspended::class, 1);
})->with([
    'true' => ['true'], 'TRUE' => ['TRUE'], '1' => ['1'], 'on' => ['on'], 'yes' => ['yes'], 'bool true' => [true],
]);

it('throws on a junk allow_suspension instead of reading it as either answer', function (mixed $junk): void {
    config()->set('sentinel.sealing.allow_suspension', $junk);
    $ran = false;

    expect(function () use (&$ran): void {
        Sentinel::withoutSealing(function () use (&$ran): void {
            $ran = true;
        }, 'import');
    })->toThrow(InvalidSentinelConfigurationException::class, 'sentinel.sealing.allow_suspension')
        ->and($ran)->toBeFalse();
})->with([
    'disabled' => ['disabled'], 'maybe' => ['maybe'], 'two' => [2], 'array' => [['yes']],
]);

it('suspends verification for a callback', function (): void {
    expect(Sentinel::withoutVerification(fn (): bool => app(SealingScope::class)->verificationSuspended()))->toBeTrue()
        ->and(app(SealingScope::class)->verificationSuspended())->toBeFalse();
});

it('puts unseal() through the acknowledgement policy, so unseal + seal never bypasses it (dual-review O-6)', function (): void {
    config()->set('sentinel.acknowledgement.ability', 'acknowledge-tampering');
    Gate::define('acknowledge-tampering', static fn (User $user): bool => $user->name === 'Admin');
    $clerk = User::query()->create(['name' => 'Clerk']);
    $admin = User::query()->create(['name' => 'Admin']);
    $this->actingAs($clerk);
    app()->instance(Runtime::class, new Runtime(app(), console: false));

    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.01']);

    expect(fn () => Sentinel::acknowledge($invoice, 'please'))->toThrow(AcknowledgementDeniedException::class, 'unauthorized')
        ->and(fn () => Sentinel::unseal($invoice, 'cleanup', seal: 'financial'))->toThrow(AcknowledgementDeniedException::class, 'unauthorized')
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Tampered);

    // An authorised unseal of a strict seal still leaves it to an acknowledgement, never seal().
    expect(Sentinel::unseal($invoice, 'INC-4: cleanup', $admin, 'financial'))->toBeTrue()
        ->and(fn () => Sentinel::seal(Invoice::query()->findOrFail($invoice->id), 'financial'))->toThrow(TamperedModelException::class, 'missing: unsealed')
        ->and(Sentinel::acknowledge($invoice, 'INC-4: re-adopted', $admin, 'financial')->acknowledged)->toBeTrue()
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);
});

it('records the acting user on an unseal, and requires one outside the console (dual-review O-6)', function (): void {
    app()->instance(Runtime::class, new Runtime(app(), console: false));
    $invoice = invoice();

    expect(fn () => Sentinel::unseal($invoice, 'cleanup', seal: 'financial'))->toThrow(AcknowledgementDeniedException::class, 'actor is required');

    $clerk = User::query()->create(['name' => 'Clerk']);
    $this->actingAs($clerk);
    Sentinel::unseal($invoice, 'cleanup', seal: 'financial');

    $entry = LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->orderByDesc('version')->firstOrFail();

    expect((string) $entry->actor_id)->toBe((string) $clerk->id)
        ->and($entry->actor_type)->toBe($clerk->getMorphClass());
});
