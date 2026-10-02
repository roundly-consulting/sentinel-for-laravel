<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property int $invoice_id
 * @property string $sku
 * @property int $quantity
 */
final class InvoiceLine extends Model
{
    public $timestamps = false;

    protected $table = 'invoice_lines';

    protected $guarded = [];
}
