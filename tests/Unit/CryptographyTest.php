<?php

namespace Dgtlss\OWASPAdvisor\Tests\Unit;

use Orchestra\Testbench\TestCase;
use Dgtlss\OWASPAdvisor\OWASPAdvisor;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;
use Illuminate\Database\Schema\Blueprint;

class CryptographyTest extends TestCase
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

    public function test_https_check_with_insecure_config()
    {
        Config::set('session.secure', false);
        Config::set('app.middleware', []);
        Config::set('app.url', 'http://example.com');
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['crypto']['checks']['https_only'];
        
        $this->assertEquals('error', $check['status']);
        $this->assertStringContainsString('Session cookies are not set to HTTPS-only', $check['message']);
        $this->assertStringContainsString('HSTS middleware is not configured', $check['message']);
        $this->assertStringContainsString('Application URL is not configured to use HTTPS', $check['message']);
    }

    public function test_https_check_with_secure_config()
    {
        Config::set('session.secure', true);
        Config::set('app.middleware', ['App\Http\Middleware\HandleHSTS']);
        Config::set('app.url', 'https://example.com');
        Config::set('trustedproxy.proxies', ['10.0.0.0/8']);
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['crypto']['checks']['https_only'];
        
        $this->assertEquals('success', $check['status']);
        $this->assertStringContainsString('HTTPS is properly configured', $check['message']);
    }

    public function test_encryption_check_with_missing_key()
    {
        Config::set('app.key', '');
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['crypto']['checks']['encryption_at_rest'];
        
        $this->assertEquals('error', $check['status']);
        $this->assertStringContainsString('Application encryption key is not set', $check['message']);
    }

    public function test_encryption_check_with_weak_key()
    {
        Config::set('app.key', 'base64:' . base64_encode('weak_key'));
        Config::set('app.cipher', 'AES-128-CBC');
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['crypto']['checks']['encryption_at_rest'];
        
        $this->assertEquals('warning', $check['status']);
        $this->assertStringContainsString('Encryption key does not meet minimum security requirements', $check['message']);
        $this->assertStringContainsString('Insecure encryption algorithm in use', $check['message']);
    }

    public function test_encryption_check_with_secure_config()
    {
        Config::set('app.key', 'base64:' . base64_encode(random_bytes(32)));
        Config::set('app.cipher', 'AES-256-GCM');
        
        // Create a test table with encrypted fields
        Schema::create('test_users', function (Blueprint $table) {
            $table->id();
            $table->string('encrypted_data');
            $table->timestamps();
        });
        
        // Add some encrypted data
        DB::table('test_users')->insert([
            'encrypted_data' => 'eyJpdiI6IjEyMzQ1Njc4OTAiLCJ2YWx1ZSI6ImVuY3J5cHRlZF9kYXRhIiwidGFnIjoiYWJjZGVmIn0='
        ]);
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['crypto']['checks']['encryption_at_rest'];
        
        $this->assertEquals('success', $check['status']);
        $this->assertStringContainsString('Data encryption is properly configured', $check['message']);
        
        Schema::dropIfExists('test_users');
    }

    public function test_password_hashing_check_with_insecure_driver()
    {
        Config::set('hashing.driver', 'md5');
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['crypto']['checks']['password_hashing'];
        
        $this->assertEquals('error', $check['status']);
        $this->assertStringContainsString('Insecure password hashing driver in use', $check['message']);
    }

    public function test_password_hashing_check_with_weak_bcrypt()
    {
        Config::set('hashing.driver', 'bcrypt');
        Config::set('hashing.bcrypt.rounds', 5);
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['crypto']['checks']['password_hashing'];
        
        $this->assertEquals('warning', $check['status']);
        $this->assertStringContainsString('Bcrypt rounds are set too low', $check['message']);
    }

    public function test_password_hashing_check_with_weak_argon2()
    {
        Config::set('hashing.driver', 'argon2id');
        Config::set('hashing.argon.memory', 512);
        Config::set('hashing.argon.time', 1);
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['crypto']['checks']['password_hashing'];
        
        $this->assertEquals('warning', $check['status']);
        $this->assertStringContainsString('Argon2 memory cost is set too low', $check['message']);
        $this->assertStringContainsString('Argon2 time cost is set too low', $check['message']);
    }

    public function test_password_hashing_check_with_secure_config()
    {
        Config::set('hashing.driver', 'bcrypt');
        Config::set('hashing.bcrypt.rounds', 12);
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['crypto']['checks']['password_hashing'];
        
        $this->assertEquals('success', $check['status']);
        $this->assertStringContainsString('Password hashing is properly configured using BCRYPT', $check['message']);
    }

    public function test_detects_unhashed_passwords()
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('password');
            $table->timestamps();
        });
        
        DB::table('users')->insert([
            'password' => 'plaintext_password'
        ]);
        
        $results = $this->advisor->runSecurityAudit();
        $check = $results['crypto']['checks']['password_hashing'];
        
        $this->assertEquals('warning', $check['status']);
        $this->assertStringContainsString('Potentially unhashed password fields found', $check['message']);
        
        Schema::dropIfExists('users');
    }
} 