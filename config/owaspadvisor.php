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
        // A01: Broken Access Control
        'access_control' => [
            'enabled' => true,
            'strict_mode' => false,
        ],
        
        // A02: Security Misconfiguration
        'configuration' => [
            'enabled' => true,
            'check_debug_mode' => true,
            'check_headers' => true,
            'check_error_handling' => true,
        ],
        
        // A03: Software Supply Chain Failures
        'supply_chain' => [
            'enabled' => true,
            'check_composer_audit' => true,
            'check_security_tools' => true,
            'check_git_signing' => true,
        ],
        
        // A04: Cryptographic Failures
        'cryptography' => [
            'enabled' => true,
            'minimum_key_length' => 256,
            'allowed_algorithms' => ['aes-256-cbc', 'aes-256-gcm'],
        ],
        
        // A05: Injection
        'injection' => [
            'enabled' => true,
            'scan_directories' => [
                'app',
                'routes',
                'resources/views',
            ],
        ],
        
        // A06: Insecure Design
        'design' => [
            'enabled' => true,
            'check_threat_modeling' => true,
            'check_design_patterns' => true,
            'check_business_logic' => true,
        ],
        
        // A07: Authentication Failures
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
        
        // A08: Software or Data Integrity Failures
        'integrity' => [
            'enabled' => true,
            'check_ci_integrity' => true,
            'check_database_integrity' => true,
            'check_update_mechanisms' => true,
        ],
        
        // A09: Security Logging and Alerting Failures
        'logging' => [
            'enabled' => true,
            'check_security_events' => true,
            'check_alerting' => true,
            'log_retention_days' => 30,
        ],
        
        // A10: Mishandling of Exceptional Conditions
        'exception_handling' => [
            'enabled' => true,
            'check_empty_catch_blocks' => true,
            'check_fail_open' => true,
            'check_resource_cleanup' => true,
            'check_timeout_handling' => true,
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
]; 