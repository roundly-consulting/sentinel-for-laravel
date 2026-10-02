<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * The `php artisan about` section, pinned with testing-for-laravel's render check: it proves
 * the capture is not empty before anything else is trusted. Rows are presence/flags only —
 * never key material. The Manager row disambiguates from laravel/sentinel's own manager.
 */
it('renders its about section', function (): void {
    expect('sentinel')->toLeakNoSecrets([], mustRender: ['Manager', SentinelManager::class]);
});
