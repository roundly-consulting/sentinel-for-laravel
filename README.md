<!-- roundly-hero:start -->
<p align="center">
  <a href="https://roundly-consulting.com/open-source/docs/sentinel-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=sentinel-for-laravel">
    <img src="https://raw.githubusercontent.com/roundly-consulting/sentinel-for-laravel/main/art/hero.png" alt="Sentinel for Laravel — Roundly open source" width="100%">
  </a>
</p>
<!-- roundly-hero:end -->

<!-- roundly-badges:start -->
<p align="center">
  <a href="https://packagist.org/packages/roundly-consulting/sentinel-for-laravel"><img src="https://img.shields.io/packagist/v/roundly-consulting/sentinel-for-laravel?style=flat-square&label=release" alt="Latest release"></a>
  <a href="https://github.com/roundly-consulting/sentinel-for-laravel/actions/workflows/run-tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/sentinel-for-laravel/run-tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://github.com/roundly-consulting/sentinel-for-laravel/actions/workflows/fix-php-code-style-issues.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/sentinel-for-laravel/fix-php-code-style-issues.yml?branch=main&style=flat-square&label=code%20style" alt="Code style"></a>
  <a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/donate-support%20our%20open%20source-F24E29?style=flat-square&logo=stripe&logoColor=white" alt="Donate"></a>
  <a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/patreon-become%20a%20patron-F96854?style=flat-square&logo=patreon&logoColor=white" alt="Patreon"></a>
  <a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=sentinel-for-laravel#crypto"><img src="https://img.shields.io/badge/crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=flat-square&logo=bitcoin&logoColor=white" alt="Crypto"></a>
</p>
<!-- roundly-badges:end -->

# Sentinel for Laravel

Know when your data was changed behind your application's back, and make every request count
once. Sentinel seals Eloquent models with keyed MACs or signatures, detects any change made
outside the application (a SQL console, a mass `update()`, a restored backup), and adds
idempotency keys, single-use nonces and URLs, and RFC 9421 HTTP message signatures.

## Installation

Requires PHP 8.4+ (`ext-hash`, `ext-mbstring`; `ext-sodium` for Ed25519 keys), Laravel 12 or 13,
and SQLite, PostgreSQL or MySQL.

```bash
composer require roundly-consulting/sentinel-for-laravel
php artisan sentinel:install   # publishes config + migrations, prints the key lines for .env
php artisan migrate
```

If your sealed models or users have UUID/ULID keys, set `sentinel.key_type` /
`sentinel.actor_key_type` **before** migrating. `php artisan sentinel:check` confirms the setup.

## Usage

Declare a seal on the model — every Eloquent write now seals the row:

```php
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;

final class Invoice extends Model implements Sealable
{
    use HasSeals;

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('financial')->attributes('customer_id', 'currency', 'amount', 'status');
    }
}
```

Verify wherever it matters:

```php
use RoundlyConsulting\Sentinel\Facades\Sentinel;

$invoice->isIntact();                          // true when every seal verifies
Sentinel::for($invoice)->verifyOrFail();       // throws TamperedModelException otherwise

Route::get('/invoices/{invoice}', ShowInvoice::class)->middleware('sentinel.verified');
```

Someone runs `UPDATE invoices SET amount = 0 WHERE id = 42` in a SQL console:

```php
Sentinel::for($invoice)->verify();
// VerificationResult { status: Tampered, reason: 'mac', changedAttributes: ['a:amount'], … }

$invoice->update(['note' => 'x']);             // TamperedModelException: refused until acknowledged

Sentinel::for($invoice)->by($admin)->because('INC-88: refund fixed by the DBA')->acknowledge();
```

<!-- roundly-docs:start -->
## Documentation

The full documentation — configuration, every feature and its API, and testing — lives on our
website: **[roundly-consulting.com/open-source/docs/sentinel-for-laravel](https://roundly-consulting.com/open-source/docs/sentinel-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=sentinel-for-laravel)**

Release notes are in [CHANGELOG.md](CHANGELOG.md). To contribute, see the
[contributing guide](https://github.com/roundly-consulting/.github/blob/main/CONTRIBUTING.md).
<!-- roundly-docs:end -->

<!-- roundly-support:start -->
## Support our work

This package is free and open source, built and maintained by
[Roundly Consulting](https://roundly-consulting.com/open-source?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=sentinel-for-laravel).
If it saves you time, please consider supporting our open-source work — a one-time donation, a
monthly pledge on Patreon or a crypto donation helps fund maintenance, new features and new
packages.

<a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/Donate-Support%20Roundly%20open%20source-F24E29?style=for-the-badge&logo=stripe&logoColor=white" alt="Donate to Roundly open source"></a>
<a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/Patreon-Become%20a%20patron-F96854?style=for-the-badge&logo=patreon&logoColor=white" alt="Become a patron on Patreon"></a>
<a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=sentinel-for-laravel#crypto"><img src="https://img.shields.io/badge/Crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate crypto: BTC, ETH, BNB or SOL"></a>
<!-- roundly-support:end -->

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
