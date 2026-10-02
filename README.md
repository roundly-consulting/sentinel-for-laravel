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

Tamper-evident seals for Eloquent models (keyed MACs and signatures, key rotation, an
append-only ledger), idempotency keys, nonces and RFC 9421 HTTP message signatures —
native, built only on Laravel and the Roundly Tier-0 packages.

> **Work in progress.** This README grows with the package; the complete installation,
> configuration and usage reference is written once the public API is finished.

## Requirements

- PHP ^8.4 (`ext-sodium` for `ed25519` keys)
- Laravel 12.x or 13.x

## Installation

```bash
composer require roundly-consulting/sentinel-for-laravel
```

Publish the configuration and migrations, then generate a key for the default ring:

```bash
php artisan vendor:publish --tag="sentinel-config"
php artisan vendor:publish --tag="sentinel-migrations"
php artisan migrate
php artisan sentinel:key:generate   # prints SENTINEL_KEY_ID / SENTINEL_KEY — add them to .env (secret)
```

## Naming

The facade is `RoundlyConsulting\Sentinel\Facades\Sentinel` and the injectable manager is
`RoundlyConsulting\Sentinel\SentinelManager`. The package registers **no global alias**:
`cartalyst/sentinel` registers a global `Sentinel` alias that ours would replace, and
`laravel/sentinel` (pulled in by Horizon, Pulse and Telescope) ships its own
`Laravel\Sentinel\Sentinel` and `SentinelManager`. Always import the full
`RoundlyConsulting\Sentinel\…` names.

## Testing

```bash
composer test
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

See the organisation's [contributing guide](https://github.com/roundly-consulting/.github/blob/main/CONTRIBUTING.md).

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
