<?php

namespace Dgtlss\OWASPAdvisor\Tests\Unit;

use Orchestra\Testbench\TestCase;
use Dgtlss\OWASPAdvisor\OWASPAdvisor;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Config;

class AccessControlTest extends TestCase
{
    protected OWASPAdvisor $advisor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->advisor = new OWASPAdvisor();
    }

    protected function getPackageProviders($app)
    {
        return [
            'Dgtlss\OWASPAdvisor\OWASPAdvisorServiceProvider'
        ];
    }

    public function test_auth_middleware_check_with_no_routes()
    {
        $results = $this->advisor->runSecurityAudit();
        $check = $results['access_control']['checks']['middleware_usage'];
        
        $this->assertEquals('warning', $check['status']);
        $this->assertEquals('No routes found to analyze.', $check['message']);
    }

    public function test_auth_middleware_check_with_unprotected_routes()
    {
        Route::get('/test1', function () {})->name('test1');
        Route::get('/test2', function () {})->name('test2');
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['access_control']['checks']['middleware_usage'];
        
        $this->assertEquals('error', $check['status']);
        $this->assertStringContainsString('0.0% of routes are protected', $check['message']);
    }

    public function test_auth_middleware_check_with_protected_routes()
    {
        Route::get('/test1', function () {})->middleware('auth')->name('test1');
        Route::get('/test2', function () {})->middleware('auth')->name('test2');
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['access_control']['checks']['middleware_usage'];
        
        $this->assertEquals('success', $check['status']);
        $this->assertStringContainsString('100.0% of routes are properly protected', $check['message']);
    }

    public function test_cors_check_with_no_config()
    {
        Config::set('cors', []);
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['access_control']['checks']['cors_config'];
        
        $this->assertEquals('error', $check['status']);
        $this->assertStringContainsString('CORS configuration not found', $check['message']);
    }

    public function test_cors_check_with_wildcard_config()
    {
        Config::set('cors', [
            'paths' => ['*'],
            'allowed_origins' => ['*'],
            'allowed_methods' => ['*'],
            'allowed_headers' => ['*'],
            'exposed_headers' => [],
            'max_age' => 0,
            'supports_credentials' => true
        ]);
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['access_control']['checks']['cors_config'];
        
        $this->assertEquals('error', $check['status']);
        $this->assertStringContainsString('All origins allowed (*)', $check['message']);
        $this->assertStringContainsString('CORS enabled for all paths (*)', $check['message']);
        $this->assertStringContainsString('All HTTP methods allowed (*)', $check['message']);
        $this->assertStringContainsString('All headers allowed (*)', $check['message']);
    }

    public function test_cors_check_with_specific_config()
    {
        Config::set('cors', [
            'paths' => ['api/*'],
            'allowed_origins' => ['https://example.com'],
            'allowed_methods' => ['GET', 'POST'],
            'allowed_headers' => ['X-Custom-Header', 'Content-Type'],
            'exposed_headers' => ['X-Custom-Response-Header'],
            'max_age' => 3600,
            'supports_credentials' => false
        ]);
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['access_control']['checks']['cors_config'];
        
        $this->assertEquals('success', $check['status']);
        $this->assertStringContainsString('CORS is properly configured', $check['message']);
    }

    public function test_cors_check_with_partial_issues()
    {
        Config::set('cors', [
            'paths' => ['api/*'],
            'allowed_origins' => ['https://example.com'],
            'allowed_methods' => ['GET', 'POST'],
            'allowed_headers' => ['*'], // This is a security concern
            'exposed_headers' => [],
            'max_age' => 3600,
            'supports_credentials' => true
        ]);
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['access_control']['checks']['cors_config'];
        
        $this->assertEquals('error', $check['status']);
        $this->assertStringContainsString('All headers allowed (*)', $check['message']);
        $this->assertStringContainsString('Credentials support enabled', $check['message']);
    }

    public function test_role_check_with_spatie_permission()
    {
        // Simulate Spatie Permission package being installed
        $this->assertTrue(class_exists('\Spatie\Permission\PermissionServiceProvider'));
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['access_control']['checks']['role_permissions'];
        
        $this->assertEquals('success', $check['status']);
        $this->assertStringContainsString('spatie/laravel-permission', $check['message']);
    }
} 