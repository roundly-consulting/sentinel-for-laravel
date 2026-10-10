<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Ledger\AnchorCodec;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Anchors\MemoryAnchor;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;

function runArtisan(string $command, array $parameters = []): array
{
    $status = Artisan::call($command, $parameters);

    return [$status, Artisan::output()];
}

it('scans the configured models and exits 0 when everything is intact', function (): void {
    invoice();
    config()->set('sentinel.models', [Invoice::class]);

    [$status, $output] = runArtisan('sentinel:verify');

    expect($status)->toBe(0)
        ->and($output)->toContain('Seals verified')->toContain('Intact');
});

it('exits 1 on a finding and prints names, never values', function (): void {
    $invoice = invoice(['amount' => '4242.42']);
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '313.17']);

    [$status, $output] = runArtisan('sentinel:verify', ['model' => [Invoice::class], '--seal' => 'financial']);

    // Three integer digits: no timestamp in the output can contain these by chance.
    expect($status)->toBe(1)
        ->and($output)->toContain("{$invoice->id}  seal=financial  tampered (mac)  changed=a:amount")
        ->and($output)->not->toContain('4242.42')->not->toContain('313.17');
});

it('fails only on the statuses named in --fail-on', function (): void {
    Invoice::query()->insert(['number' => 'raw']);

    expect(runArtisan('sentinel:verify', ['model' => [Invoice::class], '--fail-on' => ['tampered']])[0])->toBe(0)
        ->and(runArtisan('sentinel:verify', ['model' => [Invoice::class], '--fail-on' => ['missing,tampered']])[0])->toBe(1)
        ->and(runArtisan('sentinel:verify', ['model' => [Invoice::class], '--fail-on' => ['nonsense']])[0])->toBe(2);
});

it('prints a JSON report', function (): void {
    invoice();

    [$status, $output] = runArtisan('sentinel:verify', ['model' => ['RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice'], '--json' => true, '--ledger' => true]);
    $report = json_decode($output, true, 16, JSON_THROW_ON_ERROR);

    expect($status)->toBe(0)
        ->and($report['scanned'])->toBe(2)
        ->and($report['counts'][0])->toBe(['status' => 'intact', 'count' => 2])
        ->and($report['ledger']['clean'])->toBeTrue()
        ->and($report['ledger']['entries'])->toBe(2);
});

it('verifies the ledger and compares a manual anchor', function (): void {
    MemoryAnchor::install();
    invoice();
    Sentinel::checkpoint();
    $anchor = AnchorCodec::encode(AnchorCodec::fromCheckpoint(Checkpoint::query()->firstOrFail(), DB::getDefaultConnection()));
    config()->set('sentinel.ledger.anchors', '');

    [$clean, $output] = runArtisan('sentinel:verify', ['--ledger' => true, '--anchor' => $anchor]);

    expect($clean)->toBe(0)
        ->and($output)->toContain('The ledger is intact')->toContain('No anchor is configured');

    DB::table('sentinel_checkpoints')->update(['root' => str_repeat('x', 43)]);
    [$dirty, $output] = runArtisan('sentinel:verify', ['--ledger' => true, '--anchor' => $anchor]);

    expect($dirty)->toBe(1)
        ->and($output)->toContain('checkpoint_invalid')->toContain('anchor_mismatch')
        ->and(runArtisan('sentinel:verify', ['--ledger' => true, '--anchor' => '{"broken"'])[0])->toBe(2);
});

it('fails on a backlog only when asked to', function (): void {
    invoice();
    $this->travel(2)->hours();

    expect(runArtisan('sentinel:verify', ['--ledger' => true])[0])->toBe(0)
        ->and(runArtisan('sentinel:verify', ['--ledger' => true, '--fail-on' => ['backlog']])[0])->toBe(1);
});

it('refuses unknown models and invalid numbers', function (): void {
    expect(runArtisan('sentinel:verify', ['model' => ['App\\Nope']])[0])->toBe(2)
        ->and(runArtisan('sentinel:verify', ['model' => [Invoice::class], '--chunk' => '0'])[1])->toContain('[--chunk]')
        ->and(runArtisan('sentinel:verify', ['model' => [Seal::class]])[0])->toBe(2);
});

it('checkpoints every connection until nothing is pending', function (): void {
    MemoryAnchor::install();
    invoice();
    invoice();

    [$status, $output] = runArtisan('sentinel:checkpoint', ['--batch' => 3]);

    expect($status)->toBe(0)
        ->and($output)->toContain('checkpoint #1')->toContain('checkpoint #2')->toContain('anchors: memory ✓')
        ->and(Checkpoint::query()->count())->toBe(2)
        ->and(runArtisan('sentinel:checkpoint', ['--connection' => [DB::getDefaultConnection()]])[1])->toContain('nothing to checkpoint')
        ->and(runArtisan('sentinel:checkpoint', ['--batch' => 'many'])[0])->toBe(2);
});

it('skips a connection another run holds', function (): void {
    invoice();
    $lock = cache()->lock('sentinel:checkpoint:'.DB::getDefaultConnection(), 60);
    $lock->get();

    try {
        expect(runArtisan('sentinel:checkpoint')[1])->toContain('Another checkpoint run holds');
    } finally {
        $lock->release();
    }
});

it('reports a checkpoint failure', function (): void {
    invoice();
    config()->set('sentinel.ledger.ring', 'nope');

    expect(runArtisan('sentinel:checkpoint')[0])->toBe(1);
});

it('re-seals from the console and lists what it skipped', function (): void {
    $intact = invoice();
    $tampered = invoice();
    DB::table('invoices')->where('id', $tampered->id)->update(['amount' => '0.00']);

    [$status, $output] = runArtisan('sentinel:reseal', ['model' => Invoice::class, '--seal' => 'financial', '--dry-run' => true]);

    expect($status)->toBe(1)
        ->and($output)->toContain('[dry run] Skipped')->toContain("{$tampered->id}  seal=financial  tampered (mac)")
        ->and(runArtisan('sentinel:reseal', ['model' => Invoice::class, '--seal' => 'financial', '--acknowledge' => 'INC-7'])[0])->toBe(0)
        ->and(Sentinel::verify($tampered)->isIntact())->toBeTrue()
        ->and(runArtisan('sentinel:reseal', ['model' => 'nope'])[0])->toBe(2)
        ->and([$intact->id])->not->toBeEmpty();
});

it('baselines from the console with a required reason', function (): void {
    config()->set('sentinel.sealing.allow_suspension', true);
    $raw = Sentinel::withoutSealing(static fn (): Invoice => invoice(), 'import');

    expect(runArtisan('sentinel:seal-missing', ['model' => Invoice::class])[0])->toBe(2);

    [$status, $output] = runArtisan('sentinel:seal-missing', ['model' => Invoice::class, '--reason' => 'Initial baseline']);

    expect($status)->toBe(0)
        ->and($output)->toContain('Baselined')
        ->and(Sentinel::isIntact($raw))->toBeTrue()
        ->and(runArtisan('sentinel:seal-missing', ['model' => Invoice::class, '--reason' => 'x', '--seal' => 'nope'])[0])->toBe(2);
});

it('inspects one row with values redacted unless asked', function (): void {
    $invoice = invoice(['amount' => '777.77']);
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '991.23']);

    [$status, $output] = runArtisan('sentinel:inspect', ['model' => Invoice::class, 'id' => (string) $invoice->id, '--check-schema' => true]);

    expect($status)->toBe(1)
        ->and($output)->toContain('tampered (mac)')->toContain('a:amount')->toContain('redacted')->toContain('every sealed column exists')
        ->and($output)->not->toContain('991.23');

    [$shown, $values] = runArtisan('sentinel:inspect', ['model' => Invoice::class, 'id' => (string) $invoice->id, '--seal' => 'identity', '--show-values' => true]);

    expect($shown)->toBe(0)
        ->and($values)->toContain('personal data')->toContain('a:number')->toContain('v1  sealed')
        ->and(runArtisan('sentinel:inspect', ['model' => Invoice::class, 'id' => '999999'])[0])->toBe(1)
        ->and(runArtisan('sentinel:inspect', ['model' => Invoice::class, 'id' => '1', '--seal' => 'nope'])[0])->toBe(2);
});

/**
 * Chat review C-28: a corrupt seal row is what inspect exists to show.
 */
it('inspects a seal row whose sealed_at is corrupt', function (): void {
    $invoice = invoice();
    DB::table('sentinel_seals')->where('sealable_id', $invoice->id)->where('seal', 'financial')->update(['sealed_at' => 'garbage']);

    $record = Sentinel::currentSeal($invoice, 'financial');
    [$status, $output] = runArtisan('sentinel:inspect', ['model' => Invoice::class, 'id' => (string) $invoice->id, '--seal' => 'financial']);

    expect($record?->sealedAt)->toBeNull()
        ->and($record?->version)->toBe(1)
        ->and($status)->toBe(1)
        ->and($output)->toContain('malformed (sealed_at)')->toContain('Stored seal')->toContain('v1  sealed');
});
