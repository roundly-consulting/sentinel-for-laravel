<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Testing\Arch\ArchPresets;

/**
 * The seven arch presets every roundly package adopts, scoped to what a fresh package
 * actually has. Two are deliberately NOT registered here, for the same reason metrics and
 * enums skip them: this package ships no Eloquent model and no `*_model` config key, so
 * both would be green on the first run and stay green forever — vacuous rather than
 * adopted. Add them back the moment the package gains a swappable model:
 *
 *   - `swappableModelsAreNotFinal` — needs a `Model::class => 'handle.model'` map.
 *   - `modelsResolveThroughSeam` — needs a real model resolved through a Support seam.
 *
 * `morphColumnsUseTheSeam` is likewise skipped until the package ships migrations with
 * polymorphic columns.
 */
ArchPresets::strictTypes('RoundlyConsulting\Sentinel');
// The manager is the one deliberate non-final class: SentinelFake extends it, so an
// injected manager still type-checks under Sentinel::fake().
ArchPresets::finalByDefault('RoundlyConsulting\Sentinel', [SentinelManager::class]);
ArchPresets::noLocalCryptoPrimitives('RoundlyConsulting\Sentinel');

/**
 * The Dependency Policy as a test. No `alsoAllow`: this template's `require` ships only
 * php/illuminate/roundly. If this goes red the graph is wrong — never widen the allow-list
 * to quiet it.
 */
ArchPresets::runtimeRequireIsWhitelisted(__DIR__.'/../composer.json');

ArchPresets::noDebuggingLeftovers();

// Enable once the package has Models/Concerns/Traits — the preset fails on an empty namespace.
// ArchPresets::modelsGoThroughTheFacade('RoundlyConsulting\Sentinel');
