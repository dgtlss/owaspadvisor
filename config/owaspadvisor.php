<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Security Audit Settings
    |--------------------------------------------------------------------------
    |
    | Configure the security audit settings for your application.
    |
    */

    'checks' => [
        'access_control' => [
            'enabled' => true,
            'strict_mode' => false,
        ],
        
        'cryptography' => [
            'enabled' => true,
            'minimum_key_length' => 256,
            'allowed_algorithms' => ['aes-256-cbc', 'aes-256-gcm'],
        ],
        
        'injection' => [
            'enabled' => true,
            'scan_directories' => [
                'app',
                'routes',
                'resources/views',
            ],
        ],
        
        'authentication' => [
            'enabled' => true,
            'password_requirements' => [
                'min_length' => 12,
                'require_numbers' => true,
                'require_symbols' => true,
                'require_mixed_case' => true,
            ],
            'session_timeout' => 120, // minutes
        ],
        
        'headers' => [
            'enabled' => true,
            'recommended' => [
                'X-Frame-Options' => 'SAMEORIGIN',
                'X-XSS-Protection' => '1; mode=block',
                'X-Content-Type-Options' => 'nosniff',
                'Referrer-Policy' => 'strict-origin-when-cross-origin',
                'Content-Security-Policy' => "default-src 'self'",
                'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Reporting Settings
    |--------------------------------------------------------------------------
    |
    | Configure how security audit reports are generated and stored.
    |
    */
    'reporting' => [
        'output_format' => 'json', // Options: json, html, console
        'store_reports' => true,
        'report_path' => storage_path('security-reports'),
        'notify_on_high_risk' => true,
        'notification_channels' => ['mail'], // Options: mail, slack
    ],

    /*
    |--------------------------------------------------------------------------
    | Monitoring Settings
    |--------------------------------------------------------------------------
    |
    | Configure real-time security monitoring settings.
    |
    */
    'monitoring' => [
        'enabled' => true,
        'log_failed_attempts' => true,
        'max_failed_attempts' => 5,
        'lockout_time' => 15, // minutes
        'notify_on_lockout' => true,
    ],
]; 