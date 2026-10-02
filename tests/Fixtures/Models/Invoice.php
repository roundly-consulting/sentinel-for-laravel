<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Definitions\PartyIdentitySeal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\InvoiceStatus;

/**
 * @property int $id
 * @property int $tenant_id
 * @property int|null $customer_id
 * @property string|null $number
 * @property string $currency
 * @property string $amount
 * @property InvoiceStatus $status
 * @property bool $paid
 * @property string|null $secret
 * @property string $region
 * @property string|null $note
 */
final class Invoice extends Model implements Sealable
{
    use HasSeals;
    use SoftDeletes;

    protected $table = 'invoices';

    protected $guarded = [];

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('financial')
            ->attributes('customer_id', 'currency', 'amount', 'status', 'paid', 'due_on', 'region')
            ->computed('lines', static fn (Invoice $invoice): array => $invoice->lines()->orderBy('id')->get()
                ->map(static fn (InvoiceLine $line): array => ['quantity' => (int) $line->quantity, 'sku' => $line->sku])
                ->all())
            ->scope(static fn (Invoice $invoice): string => (string) $invoice->tenant_id);

        $seals->seal('identity')->using(PartyIdentitySeal::class)->lenient();
    }

    /**
     * @return HasMany<InvoiceLine, $this>
     */
    public function lines(): HasMany
    {
        return $this->hasMany(InvoiceLine::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'amount' => 'decimal:2',
            'paid' => 'boolean',
            'due_on' => 'date',
            'meta' => 'array',
            'secret' => 'encrypted',
            'status' => InvoiceStatus::class,
        ];
    }
}
