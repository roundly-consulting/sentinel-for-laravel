<?php

declare(strict_types=1);

/*
 * The coverage gate's second half (plan §11 Phase H, D39): `pest --coverage --min=95` gates
 * the package as a whole; this gates the security-critical namespaces at 100 % of their
 * lines. Reads a Clover report and exits 1 listing every uncovered line.
 *
 *     vendor/bin/pest --coverage --min=95 --coverage-clover=build/coverage.xml
 *     php tests/Support/critical-coverage.php build/coverage.xml
 */

const CRITICAL = ['Actions/', 'Canonical/', 'Engine/', 'Http/Signatures/', 'Http/StructuredFields/', 'Keys/', 'Ledger/'];

$report = $argv[1] ?? 'build/coverage.xml';
$source = realpath(__DIR__.'/../../src').DIRECTORY_SEPARATOR;

if (! is_file($report)) {
    fwrite(STDERR, "No Clover report at {$report}; run pest with --coverage-clover first.\n");
    exit(1);
}

$xml = simplexml_load_file($report);

if ($xml === false) {
    fwrite(STDERR, "{$report} is not a readable Clover report.\n");
    exit(1);
}

$checked = 0;
$failures = [];

foreach ($xml->xpath('//file') ?: [] as $file) {
    $path = (string) $file['name'];

    if (! str_starts_with($path, $source)) {
        continue;
    }

    $relative = substr($path, strlen($source));

    if (! array_filter(CRITICAL, static fn (string $prefix): bool => str_starts_with($relative, $prefix))) {
        continue;
    }

    $checked++;
    $missed = [];

    foreach ($file->line as $line) {
        if ((string) $line['type'] === 'stmt' && (int) $line['count'] === 0) {
            $missed[] = (int) $line['num'];
        }
    }

    if ($missed !== []) {
        $failures[] = sprintf('  %s: lines %s', $relative, implode(', ', $missed));
    }
}

// An empty match means the report or the paths are wrong — never a pass.
if ($checked === 0) {
    fwrite(STDERR, "No critical source file found in {$report}.\n");
    exit(1);
}

if ($failures !== []) {
    fwrite(STDERR, "Critical namespaces must be fully covered; uncovered lines:\n".implode("\n", $failures)."\n");
    exit(1);
}

fwrite(STDOUT, "Critical namespaces fully covered ({$checked} files).\n");
