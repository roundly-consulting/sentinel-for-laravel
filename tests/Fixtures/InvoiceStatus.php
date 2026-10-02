<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Fixtures;

enum InvoiceStatus: string
{
    case Draft = 'draft';
    case Paid = 'paid';
    case Void = 'void';
}
