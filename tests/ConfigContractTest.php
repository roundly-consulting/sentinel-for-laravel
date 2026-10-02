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
 * `KeyType::fromConfig('sentinel.actor_key_type')` in the migrations is not a `config(`
 * token, so that exact key is named as an extra read prefix.
 */
it('ships exactly the config keys it reads', function (): void {
    expect(__DIR__.'/../config/sentinel.php')->toSatisfyConfigContract(
        [__DIR__.'/../src', __DIR__.'/../database'],
        ['extraReadPrefixes' => ['sentinel.actor_key_type']],
    );
});

it('never claims a config handle Laravel ships itself', function (): void {
    // mergeConfigFrom() would merge this package's keys into the framework's own config, and
    // the publish tag would target the host's file of the same name (`auth`, `database`, …).
    $framework = dirname((string) (new ReflectionClass(Application::class))->getFileName(), 4);

    expect($framework.'/config/app.php')->toBeFile()
        ->and($framework.'/config/'.basename(__DIR__.'/../config/sentinel.php'))->not->toBeFile();
});
