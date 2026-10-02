<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Contracts;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;

/**
 * An Eloquent model with tamper-evident seals. Declare the seals once, on the model:
 *
 * ```php
 * public static function defineSeals(SealBuilder $seals): void
 * {
 *     $seals->seal('financial')->attributes('customer_id', 'amount', 'currency', 'status');
 * }
 * ```
 *
 * Use it with the `HasSeals` trait. `defineSeals()` is compiled once per process, so it must
 * not read request or auth state, and its closures must be `static`.
 *
 * @phpstan-require-extends Model
 */
interface Sealable
{
    public static function defineSeals(SealBuilder $seals): void;
}
