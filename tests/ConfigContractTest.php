<?php

declare(strict_types=1);

use Illuminate\Foundation\Application;

/**
 * The config contract, pinned in both directions:
 *
 *  - forward — every key the code reads is shipped;
 *  - reverse — every shipped leaf is read (ring sections through `keys.rings.*.<leaf>`
 *    patterns, which prove each leaf for every ring).
 *
 * `KeyType::fromConfig(...)` in the migrations and the toolkit's `Config::using()->enum()` /
 * `->intBetween()` readers are not `config(` tokens, so those exact keys are named as extra
 * read prefixes (never a blanket `sentinel.`, which would also match `sentinel.seal/1`).
 */
it('ships exactly the config keys it reads', function (): void {
    expect(__DIR__.'/../config/sentinel.php')->toSatisfyConfigContract(
        [__DIR__.'/../src', __DIR__.'/../database'],
        [
            'extraReadPrefixes' => [
                'sentinel.actor_key_type', 'sentinel.key_type', 'sentinel.sealing.on_tampered_write',
                'sentinel.sealing.reason_max_length', 'sentinel.sealing.transaction_attempts',
                'sentinel.ledger.batch_size', 'sentinel.ledger.backlog_warning_seconds',
                'sentinel.middleware.verified_status', 'sentinel.verification.retrieve_reaction',
                'sentinel.idempotency.ttl', 'sentinel.idempotency.lock_seconds', 'sentinel.idempotency.min_length',
                'sentinel.idempotency.max_length', 'sentinel.idempotency.max_response_bytes', 'sentinel.nonces.ttl',
                'sentinel.nonces.length',
            ],
            // Each anchor driver's section is read wholesale and indexed with literal offsets.
            'sectionVariables' => ['AnchorManager.php' => ['$config' => 'sentinel.ledger.anchor_drivers.*']],
        ],
    );
});

it('never claims a config handle Laravel ships itself', function (): void {
    // mergeConfigFrom() would merge this package's keys into the framework's own config, and
    // the publish tag would target the host's file of the same name (`auth`, `database`, …).
    $framework = dirname((string) (new ReflectionClass(Application::class))->getFileName(), 4);

    expect($framework.'/config/app.php')->toBeFile()
        ->and($framework.'/config/'.basename(__DIR__.'/../config/sentinel.php'))->not->toBeFile();
});
