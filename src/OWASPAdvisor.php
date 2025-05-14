<?php

namespace Dgtlss\OWASPAdvisor;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\App;
use Spatie\Permission\PermissionServiceProvider;
use Zizaco\Entrust\EntrustServiceProvider;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;

class OWASPAdvisor
{
    /**
     * @var ConfigRepository
     */
    protected $config;

    /**
     * @var DatabaseManager
     */
    protected $db;

    /**
     * @var Str
     */
    protected $str;

    /**
     * Create a new OWASPAdvisor instance.
     *
     * @param ConfigRepository $config
     * @param DatabaseManager $db
     * @param Str $str
     */
    public function __construct(ConfigRepository $config, DatabaseManager $db, Str $str)
    {
        $this->config = $config;
        $this->db = $db;
        $this->str = $str;
    }

    /**
     * OWASP Top 10 Categories (2021)
     */
    protected const CATEGORIES = [
        'A01' => 'Broken Access Control',
        'A02' => 'Cryptographic Failures',
        'A03' => 'Injection',
        'A04' => 'Insecure Design',
        'A05' => 'Security Misconfiguration',
        'A06' => 'Vulnerable and Outdated Components',
        'A07' => 'Identification and Authentication Failures',
        'A08' => 'Software and Data Integrity Failures',
        'A09' => 'Security Logging and Monitoring Failures',
        'A10' => 'Server-Side Request Forgery'
    ];

    /**
     * Get the application base path
     */
    protected function getAppPath(): string
    {
        return app()->basePath('app');
    }

    /**
     * Run security audit checks
     *
     * @return array
     */
    public function runSecurityAudit(): array
    {
        $results = [];
        
        $results['access_control'] = $this->checkAccessControl();
        $results['crypto'] = $this->checkCryptography();
        $results['injection'] = $this->checkInjectionVulnerabilities();
        $results['configuration'] = $this->checkSecurityConfiguration();
        $results['authentication'] = $this->checkAuthentication();
        
        return $results;
    }

    /**
     * Check for broken access control vulnerabilities
     */
    protected function checkAccessControl(): array
    {
        $status = 'success';
        $checks = [
            'middleware_usage' => $this->checkAuthMiddleware(),
            'role_permissions' => $this->checkRoleBasedAccess(),
            'cors_config' => $this->checkCORSConfiguration(),
        ];

        // If any check has warning or error, update overall status
        foreach ($checks as $check) {
            if ($check['status'] === 'error') {
                $status = 'error';
                break;
            } elseif ($check['status'] === 'warning' && $status !== 'error') {
                $status = 'warning';
            }
        }

        return [
            'status' => $status,
            'checks' => $checks
        ];
    }

    /**
     * Check for cryptographic failures
     */
    protected function checkCryptography(): array
    {
        $status = 'success';
        $checks = [
            'https_only' => $this->checkHTTPSConfiguration(),
            'encryption_at_rest' => $this->checkEncryptionAtRest(),
            'password_hashing' => $this->checkPasswordHashing(),
        ];

        // If any check has warning or error, update overall status
        foreach ($checks as $check) {
            if ($check['status'] === 'error') {
                $status = 'error';
                break;
            } elseif ($check['status'] === 'warning' && $status !== 'error') {
                $status = 'warning';
            }
        }

        return [
            'status' => $status,
            'checks' => $checks
        ];
    }

    /**
     * Check for injection vulnerabilities
     */
    protected function checkInjectionVulnerabilities(): array
    {
        return [
            'status' => 'warning',
            'checks' => [
                'sql_injection' => $this->checkSQLInjection(),
                'xss' => $this->checkXSSVulnerabilities(),
                'csrf' => $this->checkCSRFProtection(),
            ]
        ];
    }

    /**
     * Check security configuration
     */
    protected function checkSecurityConfiguration(): array
    {
        return [
            'status' => 'warning',
            'checks' => [
                'debug_mode' => $this->checkDebugMode(),
                'secure_headers' => $this->checkSecurityHeaders(),
                'error_handling' => $this->checkErrorHandling(),
            ]
        ];
    }

    /**
     * Check authentication mechanisms
     */
    protected function checkAuthentication(): array
    {
        return [
            'status' => 'warning',
            'checks' => [
                'password_policies' => $this->checkPasswordPolicies(),
                'session_security' => $this->checkSessionSecurity(),
                'rate_limiting' => $this->checkRateLimiting(),
            ]
        ];
    }

    /**
     * Check authentication middleware usage across routes
     */
    protected function checkAuthMiddleware(): array
    {
        $routes = Route::getRoutes();
        $unprotectedRoutes = [];
        $protectedCount = 0;
        $totalRoutes = 0;
        $excludedPaths = ['_ignition', 'sanctum', 'api/documentation', 'login', 'register', 'password'];

        foreach ($routes->getRoutes() as $route) {
            $path = $route->uri();
            
            // Skip excluded paths
            if (Str::contains($path, $excludedPaths)) {
                continue;
            }

            $totalRoutes++;
            $middleware = $route->middleware();
            
            $hasAuthMiddleware = false;
            foreach ($middleware as $m) {
                if (Str::contains($m, ['auth', 'authenticate'])) {
                    $hasAuthMiddleware = true;
                    $protectedCount++;
                    break;
                }
            }

            if (!$hasAuthMiddleware) {
                $unprotectedRoutes[] = $path;
            }
        }

        if ($totalRoutes === 0) {
            return [
                'status' => 'warning',
                'message' => 'No routes found to analyze.'
            ];
        }

        $protectionRatio = $protectedCount / $totalRoutes;

        if ($protectionRatio < 0.5) {
            return [
                'status' => 'error',
                'message' => sprintf(
                    '%.1f%% of routes are protected by authentication middleware. ' . PHP_EOL . 'Consider reviewing these unprotected routes:' . PHP_EOL . '%s',
                    $protectionRatio * 100,
                    implode(PHP_EOL, $unprotectedRoutes)
                )
            ];
        } elseif ($protectionRatio < 0.8) {
            return [
                'status' => 'warning',
                'message' => sprintf(
                    '%.1f%% of routes are protected. Consider reviewing these unprotected routes:' . PHP_EOL . '%s',
                    $protectionRatio * 100,
                    implode(PHP_EOL, $unprotectedRoutes)
                )
            ];
        }

        return [
            'status' => 'success',
            'message' => sprintf('%.1f%% of routes are properly protected by authentication middleware.', $protectionRatio * 100)
        ];
    }

    /**
     * Check role-based access control implementation
     */
    protected function checkRoleBasedAccess(): array
    {
        $appPath = $this->getAppPath();
        $hasSpatie = class_exists(\Spatie\Permission\PermissionServiceProvider::class);
        $hasEntrust = class_exists(\Zizaco\Entrust\EntrustServiceProvider::class);
        $hasCustomRoles = false;

        // Check for custom role implementation
        if (File::exists($appPath)) {
            $files = File::allFiles($appPath);
            foreach ($files as $file) {
                $content = file_get_contents($file->getPathname());
                if (preg_match('/(hasRole|can|ability|permission)/i', $content)) {
                    $hasCustomRoles = true;
                    break;
                }
            }
        }

        if ($hasSpatie || $hasEntrust) {
            return [
                'status' => 'success',
                'message' => 'Using a well-established role/permission package: ' . 
                            ($hasSpatie ? 'spatie/laravel-permission' : 'zizaco/entrust')
            ];
        }

        if ($hasCustomRoles) {
            return [
                'status' => 'warning',
                'message' => 'Custom role implementation detected. Consider using a well-tested package like spatie/laravel-permission.'
            ];
        }

        return [
            'status' => 'error',
            'message' => 'No role-based access control implementation detected. Implement RBAC to better control access to resources.'
        ];
    }

    /**
     * Check CORS configuration
     */
    protected function checkCORSConfiguration(): array
    {
        $corsConfig = config('cors', []);
        $issues = [];

        if (empty($corsConfig)) {
            return [
                'status' => 'error',
                'message' => 'CORS configuration not found. Consider using Laravel\'s built-in CORS middleware.'
            ];
        }

        // Check allowed origins
        if (isset($corsConfig['allowed_origins']) && in_array('*', $corsConfig['allowed_origins'])) {
            $issues[] = 'Wildcard (*) origin allowed';
        }

        // Check allowed methods
        if (isset($corsConfig['allowed_methods']) && in_array('*', $corsConfig['allowed_methods'])) {
            $issues[] = 'All HTTP methods allowed';
        }

        // Check allowed headers
        if (isset($corsConfig['allowed_headers']) && in_array('*', $corsConfig['allowed_headers'])) {
            $issues[] = 'All headers allowed';
        }

        if (count($issues) > 0) {
            return [
                'status' => 'warning',
                'message' => 'CORS configuration could be more restrictive: ' . implode(', ', $issues)
            ];
        }

        return [
            'status' => 'success',
            'message' => 'CORS is properly configured with specific allowed origins, methods, and headers.'
        ];
    }

    protected function checkHTTPSConfiguration(): array
    {
        $issues = [];
        
        // Check if session cookies are secure
        if (!$this->config->get('session.secure', false)) {
            $issues[] = 'Session cookies are not set to HTTPS-only';
        }

        // Check if HSTS middleware is configured
        $middleware = $this->config->get('app.middleware', []);
        $hasHSTS = false;
        foreach ($middleware as $m) {
            if ($this->str->contains($m, ['HSTS', 'HttpsProtocol'])) {
                $hasHSTS = true;
                break;
            }
        }
        if (!$hasHSTS) {
            $issues[] = 'HSTS middleware is not configured';
        }

        // Check if app URL is HTTPS
        $appUrl = $this->config->get('app.url');
        if (!$this->str->startsWith($appUrl, 'https://')) {
            $issues[] = 'Application URL is not configured to use HTTPS';
        }

        // Check trusted proxies configuration for proper SSL handling
        $trustedProxies = $this->config->get('trustedproxy.proxies', []);
        if (empty($trustedProxies)) {
            $issues[] = 'Trusted proxies not configured for SSL handling';
        }

        if (count($issues) > 0) {
            return [
                'status' => 'error',
                'message' => 'HTTPS configuration issues found: ' . implode(', ', $issues)
            ];
        }

        return [
            'status' => 'success',
            'message' => 'HTTPS is properly configured with secure session cookies, HSTS, and proper SSL handling'
        ];
    }

    protected function checkEncryptionAtRest(): array
    {
        $issues = [];
        
        // Check if encryption key is set
        $appKey = $this->config->get('app.key');
        if (empty($appKey)) {
            return [
                'status' => 'error',
                'message' => 'Application encryption key is not set'
            ];
        }

        // Check key strength
        $keyLength = strlen(base64_decode(substr($appKey, 7)));
        $minKeyLength = $this->config->get('owaspadvisor.checks.cryptography.minimum_key_length', 256) / 8;
        if ($keyLength < $minKeyLength) {
            $issues[] = 'Encryption key does not meet minimum security requirements';
        }

        // Check cipher algorithm
        $cipher = $this->config->get('app.cipher');
        $allowedAlgorithms = $this->config->get('owaspadvisor.checks.cryptography.allowed_algorithms', ['aes-256-cbc', 'aes-256-gcm']);
        if (!in_array($cipher, $allowedAlgorithms)) {
            $issues[] = 'Insecure encryption algorithm in use';
        }

        // Check for encrypted database fields
        try {
            $hasEncryptedFields = false;
            $encryptedFields = [];
            
            // Get all tables in the database
            $tables = $this->db->select('SHOW TABLES');
            
            // Common patterns for encrypted fields
            $encryptionPatterns = [
                'encrypted_',
                'secret_',
                '_encrypted',
                '_secret',
                'token',
                'api_key',
                'password', // Include password fields as they should be hashed
                'remember_token', // Laravel's remember token
                'personal_access_token', // Laravel Sanctum tokens
            ];
            
            foreach ($tables as $table) {
                $tableName = current((array)$table);
                
                // Get column information for each table
                $columns = $this->db->select('SHOW COLUMNS FROM ' . $tableName);
                
                foreach ($columns as $column) {
                    $columnName = $column->Field;

                    // Check if column matches encryption patterns
                    foreach ($encryptionPatterns as $pattern) {
                        if ($this->str->contains($columnName, $pattern)) {
                            $hasEncryptedFields = true;
                            $encryptedFields[] = "{$tableName}.{$columnName}";
                            break;
                        }
                    }

                    // Sample data to check for potential encryption
                    if (!$hasEncryptedFields) {
                        $sample = $this->db->table($tableName)
                            ->where($columnName, 'LIKE', 'eyJ%')
                            ->orWhere($columnName, 'LIKE', '$2y$%')
                            ->first();
                        
                        if ($sample) {
                            $hasEncryptedFields = true;
                            $encryptedFields[] = "{$tableName}.{$columnName}";
                        }
                    }
                }
            }

            if (!$hasEncryptedFields) {
                $issues[] = 'No encrypted or hashed fields detected in the database';
            } else {
                // Add information about found encrypted fields
                return [
                    'status' => 'success',
                    'message' => 'Found encrypted/hashed fields: ' . implode(', ', array_slice($encryptedFields, 0, 5)) . 
                                (count($encryptedFields) > 5 ? ' and ' . (count($encryptedFields) - 5) . ' more' : '')
                ];
            }
        } catch (\Exception $e) {
            $issues[] = 'Could not verify database encryption: ' . $e->getMessage();
        }

        if (count($issues) > 0) {
            return [
                'status' => count($issues) > 1 ? 'error' : 'warning',
                'message' => 'Encryption issues found: ' . implode(', ', $issues)
            ];
        }

        return [
            'status' => 'success',
            'message' => 'Data encryption is properly configured with strong key and secure algorithm'
        ];
    }

    protected function checkPasswordHashing(): array
    {
        $issues = [];
        
        // Check hashing driver
        $driver = $this->config->get('hashing.driver', 'bcrypt');
        if (!in_array($driver, ['bcrypt', 'argon2i', 'argon2id'])) {
            return [
                'status' => 'error',
                'message' => 'Insecure password hashing driver in use'
            ];
        }

        // Check bcrypt configuration
        if ($driver === 'bcrypt') {
            $rounds = $this->config->get('hashing.bcrypt.rounds', 10);
            if ($rounds < 10) {
                $issues[] = 'Bcrypt rounds are set too low (minimum recommended: 10)';
            }
        }

        // Check Argon2 configuration
        if ($this->str->startsWith($driver, 'argon2')) {
            $memory = $this->config->get('hashing.argon.memory', 1024);
            $time = $this->config->get('hashing.argon.time', 2);
            $threads = $this->config->get('hashing.argon.threads', 2);

            if ($memory < 1024) {
                $issues[] = 'Argon2 memory cost is set too low (minimum recommended: 1024MB)';
            }
            if ($time < 2) {
                $issues[] = 'Argon2 time cost is set too low (minimum recommended: 2)';
            }
            if ($threads < 2) {
                $issues[] = 'Argon2 threads are set too low (minimum recommended: 2)';
            }
        }

        // Check for unhashed password fields in database
        try {
            // Get all tables in the database
            $tables = $this->db->select('SHOW TABLES');
            
            foreach ($tables as $table) {
                $tableName = current((array)$table);
                
                // Check if table has a password column
                $columns = $this->db->select('SHOW COLUMNS FROM ' . $tableName);
                foreach ($columns as $column) {
                    if ($column->Field === 'password') {
                        // Sample a row to check if passwords look hashed
                        $row = $this->db->table($tableName)->first();
                        if ($row && isset($row->password)) {
                            $password = $row->password;
                            // Check if it looks like a hash (length and format)
                            if (strlen($password) < 40 || !preg_match('/[$2y$|$argon2i$|$argon2id$]/', $password)) {
                                $issues[] = "Potentially unhashed password fields found in table '{$tableName}'";
                            }
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            $issues[] = 'Could not verify password hashing in database: ' . $e->getMessage();
        }

        if (count($issues) > 0) {
            return [
                'status' => count($issues) > 1 ? 'error' : 'warning',
                'message' => 'Password hashing issues found: ' . implode(', ', $issues)
            ];
        }

        return [
            'status' => 'success',
            'message' => "Password hashing is properly configured using " . strtoupper($driver)
        ];
    }

    protected function checkSQLInjection(): array
    {
        $issues = [];
        $appPath = $this->getAppPath();
        
        try {
            // Check if query builder is being used consistently
            if (File::exists($appPath)) {
                $files = File::allFiles($appPath);
                $rawSqlPatterns = [
                    'DB::raw\(',
                    'DB::unprepared\(',
                    '\->whereRaw\(',
                    '\->havingRaw\(',
                    '\->orderByRaw\(',
                    '\->selectRaw\(',
                    'mysql_query\(',
                    'mysqli_query\(',
                ];
                
                $rawSqlUsage = [];
                foreach ($files as $file) {
                    $content = file_get_contents($file->getPathname());
                    foreach ($rawSqlPatterns as $pattern) {
                        if (preg_match_all('/' . $pattern . '/', $content, $matches)) {
                            $rawSqlUsage[] = [
                                'file' => $file->getRelativePathname(),
                                'pattern' => $pattern,
                                'count' => count($matches[0])
                            ];
                        }
                    }
                }
                
                if (!empty($rawSqlUsage)) {
                    $issues[] = sprintf(
                        'Found %d instances of raw SQL usage which could be vulnerable to SQL injection: %s',
                        array_sum(array_column($rawSqlUsage, 'count')),
                        implode(', ', array_map(fn($usage) => "{$usage['file']} ({$usage['count']})", array_slice($rawSqlUsage, 0, 3)))
                    );
                }
            }

            // Check for proper parameter binding in queries
            $parameterBindingIssues = $this->checkParameterBinding();
            if (!empty($parameterBindingIssues)) {
                $issues = array_merge($issues, $parameterBindingIssues);
            }

            // Check database configuration for proper character escaping
            $charset = $this->config->get('database.connections.mysql.charset', '');
            $collation = $this->config->get('database.connections.mysql.collation', '');
            
            if ($charset !== 'utf8mb4') {
                $issues[] = 'Database charset should be set to utf8mb4 to prevent character encoding based SQL injection';
            }
            
            if ($collation !== 'utf8mb4_unicode_ci' && $collation !== 'utf8mb4_general_ci') {
                $issues[] = 'Database collation should be set to utf8mb4_unicode_ci or utf8mb4_general_ci';
            }

            if (empty($issues)) {
                return [
                    'status' => 'success',
                    'message' => 'No obvious SQL injection vulnerabilities found. Query builder is being used properly.'
                ];
            }

            return [
                'status' => count($issues) > 2 ? 'error' : 'warning',
                'message' => implode('. ', $issues)
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Error while checking for SQL injection vulnerabilities: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Helper method to check for proper parameter binding in queries
     */
    protected function checkParameterBinding(): array
    {
        $issues = [];
        $appPath = $this->getAppPath();
        
        if (!File::exists($appPath)) {
            return $issues;
        }

        $files = File::allFiles($appPath);
        $suspiciousPatterns = [
            'DB::select\([\'"].*?\$.*?[\'"]\)',  // String concatenation in DB::select
            'DB::insert\([\'"].*?\$.*?[\'"]\)',  // String concatenation in DB::insert
            'DB::update\([\'"].*?\$.*?[\'"]\)',  // String concatenation in DB::update
            'DB::delete\([\'"].*?\$.*?[\'"]\)',  // String concatenation in DB::delete
            '\->where\([\'"].*?\$.*?[\'"]\)',    // String concatenation in where clauses
        ];

        foreach ($files as $file) {
            $content = file_get_contents($file->getPathname());
            foreach ($suspiciousPatterns as $pattern) {
                if (preg_match_all('/' . $pattern . '/', $content, $matches)) {
                    $issues[] = "Potential unsafe parameter binding found in {$file->getRelativePathname()}";
                    break;  // One issue per file is enough
                }
            }
        }

        return $issues;
    }

    protected function checkXSSVulnerabilities(): array
    {
        $issues = [];
        $appPath = $this->getAppPath();
        
        try {
            // Check Content Security Policy headers
            $middleware = $this->config->get('app.middleware', []);
            $hasCSP = false;
            foreach ($middleware as $m) {
                if ($this->str->contains($m, ['CSP', 'ContentSecurityPolicy'])) {
                    $hasCSP = true;
                    break;
                }
            }
            
            if (!$hasCSP) {
                $issues[] = 'Content Security Policy (CSP) middleware is not configured';
            }

            // Check security headers configuration
            $headers = $this->config->get('owaspadvisor.checks.headers.recommended', []);
            if (empty($headers['X-XSS-Protection']) || $headers['X-XSS-Protection'] !== '1; mode=block') {
                $issues[] = 'X-XSS-Protection header is not properly configured';
            }
            
            if (empty($headers['Content-Security-Policy'])) {
                $issues[] = 'Content-Security-Policy header is not configured';
            }

            // Check blade templates for potential XSS vulnerabilities
            if (File::exists(base_path('resources/views'))) {
                $files = File::allFiles(base_path('resources/views'));
                $xssPatterns = [
                    '{!! .*?\$.*? !!}',  // Unescaped blade output
                    '<script[^>]*>.*?\$.*?<\/script>',  // JavaScript with PHP variables
                    'v-html=[\'"]\$.*?[\'"]',  // Vue.js v-html directive
                    'dangerouslySetInnerHTML',  // React innerHTML equivalent
                    'innerHTML\s*=.*?\$.*?[\'"]',  // Direct innerHTML assignment
                ];
                
                $xssIssues = [];
                foreach ($files as $file) {
                    if (!$this->str->endsWith($file->getRelativePathname(), ['.blade.php', '.vue', '.jsx', '.tsx'])) {
                        continue;
                    }
                    
                    $content = file_get_contents($file->getPathname());
                    foreach ($xssPatterns as $pattern) {
                        if (preg_match_all('/' . $pattern . '/s', $content, $matches)) {
                            $xssIssues[] = [
                                'file' => $file->getRelativePathname(),
                                'count' => count($matches[0])
                            ];
                        }
                    }
                }
                
                if (!empty($xssIssues)) {
                    $issues[] = sprintf(
                        'Found %d potential XSS vulnerabilities in templates: %s',
                        array_sum(array_column($xssIssues, 'count')),
                        implode(', ', array_map(fn($issue) => "{$issue['file']} ({$issue['count']})", array_slice($xssIssues, 0, 3)))
                    );
                }
            }

            // Check JavaScript files for unsafe practices
            if (File::exists(public_path('js'))) {
                $files = File::allFiles(public_path('js'));
                $jsVulnerablePatterns = [
                    'eval\(',
                    'document\.write\(',
                    'innerHTML\s*=',
                    'outerHTML\s*=',
                    'insertAdjacentHTML\(',
                ];
                
                $jsIssues = [];
                foreach ($files as $file) {
                    if (!$this->str->endsWith($file->getRelativePathname(), '.js')) {
                        continue;
                    }
                    
                    $content = file_get_contents($file->getPathname());
                    foreach ($jsVulnerablePatterns as $pattern) {
                        if (preg_match_all('/' . $pattern . '/', $content, $matches)) {
                            $jsIssues[] = [
                                'file' => $file->getRelativePathname(),
                                'count' => count($matches[0])
                            ];
                        }
                    }
                }
                
                if (!empty($jsIssues)) {
                    $issues[] = sprintf(
                        'Found %d potentially unsafe JavaScript practices: %s',
                        array_sum(array_column($jsIssues, 'count')),
                        implode(', ', array_map(fn($issue) => "{$issue['file']} ({$issue['count']})", array_slice($jsIssues, 0, 3)))
                    );
                }
            }

            if (empty($issues)) {
                return [
                    'status' => 'success',
                    'message' => 'No obvious XSS vulnerabilities found. Content Security Policy and output escaping are properly configured.'
                ];
            }

            return [
                'status' => count($issues) > 2 ? 'error' : 'warning',
                'message' => implode('. ', $issues)
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Error while checking for XSS vulnerabilities: ' . $e->getMessage()
            ];
        }
    }

    protected function checkCSRFProtection(): array
    {
        $issues = [];
        
        try {
            // Check if CSRF middleware is enabled globally
            $middleware = $this->config->get('app.middleware', []);
            $hasCSRFMiddleware = false;
            foreach ($middleware as $m) {
                if ($this->str->contains($m, ['VerifyCsrfToken', 'csrf'])) {
                    $hasCSRFMiddleware = true;
                    break;
                }
            }
            
            if (!$hasCSRFMiddleware) {
                $issues[] = 'CSRF middleware is not enabled globally';
            }

            // Check CSRF token configuration
            $csrfTimeout = $this->config->get('session.lifetime', 120);
            if ($csrfTimeout > 120) {  // 2 hours
                $issues[] = 'CSRF token lifetime is set too high (> 2 hours)';
            }

            // Check for CSRF token verification in forms
            if (File::exists(base_path('resources/views'))) {
                $files = File::allFiles(base_path('resources/views'));
                $formIssues = [];
                $csrfPatterns = [
                    '<form[^>]*method=[\'"]POST[\'"][^>]*>(?!.*@csrf).*?<\/form>',  // Forms without @csrf
                    '<form[^>]*method=[\'"]post[\'"][^>]*>(?!.*@csrf).*?<\/form>',  // Forms without @csrf (lowercase)
                    'fetch\([^)]*method:\s*[\'"]POST[\'"]\s*[^)]*\)',  // Fetch POST requests
                    'axios\.[post|put|delete|patch]\(',  // Axios requests
                    '\$\.(?:post|ajax)\(',  // jQuery AJAX calls
                ];
                
                foreach ($files as $file) {
                    if (!$this->str->endsWith($file->getRelativePathname(), ['.blade.php', '.php', '.vue', '.jsx', '.tsx'])) {
                        continue;
                    }
                    
                    $content = file_get_contents($file->getPathname());
                    foreach ($csrfPatterns as $pattern) {
                        if (preg_match_all('/' . $pattern . '/si', $content, $matches)) {
                            // Check if CSRF token is included in other ways
                            $hasCSRFToken = $this->str->contains($content, [
                                'csrf_token()',
                                'csrf_field()',
                                '_token',
                                'X-CSRF-TOKEN',
                                'XSRF-TOKEN'
                            ]);
                            
                            if (!$hasCSRFToken) {
                                $formIssues[] = [
                                    'file' => $file->getRelativePathname(),
                                    'count' => count($matches[0])
                                ];
                            }
                        }
                    }
                }
                
                if (!empty($formIssues)) {
                    $issues[] = sprintf(
                        'Found %d forms/requests without CSRF protection: %s',
                        array_sum(array_column($formIssues, 'count')),
                        implode(', ', array_map(fn($issue) => "{$issue['file']} ({$issue['count']})", array_slice($formIssues, 0, 3)))
                    );
                }
            }

            // Check CSRF exclusions
            $excludedUrls = $this->config->get('app.csrf_exclude', []);
            if (!empty($excludedUrls)) {
                $issues[] = sprintf(
                    'Found %d URLs excluded from CSRF protection. Review if necessary: %s',
                    count($excludedUrls),
                    implode(', ', array_slice($excludedUrls, 0, 3)) . (count($excludedUrls) > 3 ? '...' : '')
                );
            }

            // Check for SameSite cookie setting
            $sameSite = $this->config->get('session.same_site', null);
            if (!$sameSite || $sameSite === 'none') {
                $issues[] = 'Session cookie SameSite attribute is not properly configured (should be "lax" or "strict")';
            }

            if (empty($issues)) {
                return [
                    'status' => 'success',
                    'message' => 'CSRF protection is properly configured and implemented across the application'
                ];
            }

            return [
                'status' => count($issues) > 2 ? 'error' : 'warning',
                'message' => implode('. ', $issues)
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Error while checking CSRF protection: ' . $e->getMessage()
            ];
        }
    }

    protected function checkDebugMode(): array
    {
        $issues = [];
        
        try {
            // Check if debug mode is enabled in production
            $appEnv = $this->config->get('app.env', 'production');
            $debugMode = $this->config->get('app.debug', false);
            
            if ($appEnv === 'production' && $debugMode) {
                $issues[] = 'Debug mode is enabled in production environment';
            }

            // Check for debug related packages in production
            if ($appEnv === 'production') {
                $composerJson = base_path('composer.json');
                if (file_exists($composerJson)) {
                    $composer = json_decode(file_get_contents($composerJson), true);
                    $debugPackages = [
                        'barryvdh/laravel-debugbar',
                        'symfony/var-dumper',
                        'filp/whoops',
                        'laravel/telescope',
                    ];
                    
                    $foundDebugPackages = [];
                    foreach ($debugPackages as $package) {
                        if (isset($composer['require'][$package]) || isset($composer['require-dev'][$package])) {
                            $foundDebugPackages[] = $package;
                        }
                    }
                    
                    if (!empty($foundDebugPackages)) {
                        $issues[] = sprintf(
                            'Debug packages found in production: %s',
                            implode(', ', $foundDebugPackages)
                        );
                    }
                }
            }

            // Check for debug statements in code
            $appPath = $this->getAppPath();
            if (File::exists($appPath)) {
                $files = File::allFiles($appPath);
                $debugPatterns = [
                    'dd\(',
                    'dump\(',
                    'var_dump\(',
                    'print_r\(',
                    'error_reporting\(E_ALL\)',
                    'ini_set\([\'"]display_errors[\'"]\s*,\s*[\'"]1[\'"]\)',
                ];
                
                $debugIssues = [];
                foreach ($files as $file) {
                    if (!$this->str->endsWith($file->getRelativePathname(), '.php')) {
                        continue;
                    }
                    
                    $content = file_get_contents($file->getPathname());
                    foreach ($debugPatterns as $pattern) {
                        if (preg_match_all('/' . $pattern . '/', $content, $matches)) {
                            $debugIssues[] = [
                                'file' => $file->getRelativePathname(),
                                'count' => count($matches[0])
                            ];
                        }
                    }
                }
                
                if (!empty($debugIssues)) {
                    $issues[] = sprintf(
                        'Found %d debug statements that should be removed in production: %s',
                        array_sum(array_column($debugIssues, 'count')),
                        implode(', ', array_map(fn($issue) => "{$issue['file']} ({$issue['count']})", array_slice($debugIssues, 0, 3)))
                    );
                }
            }

            if (empty($issues)) {
                return [
                    'status' => 'success',
                    'message' => 'Debug mode is properly configured for the current environment'
                ];
            }

            return [
                'status' => count($issues) > 1 ? 'error' : 'warning',
                'message' => implode('. ', $issues)
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Error while checking debug mode: ' . $e->getMessage()
            ];
        }
    }

    protected function checkSecurityHeaders(): array
    {
        $issues = [];
        
        try {
            // Get recommended headers from config
            $recommendedHeaders = $this->config->get('owaspadvisor.checks.headers.recommended', []);
            
            // Check if security headers middleware is configured
            $middleware = $this->config->get('app.middleware', []);
            $hasSecurityHeaders = false;
            foreach ($middleware as $m) {
                if ($this->str->contains($m, ['SecurityHeaders', 'SecureHeaders'])) {
                    $hasSecurityHeaders = true;
                    break;
                }
            }
            
            if (!$hasSecurityHeaders) {
                $issues[] = 'Security headers middleware is not configured';
            }

            // Check for essential security headers
            $essentialHeaders = [
                'X-Frame-Options' => ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection' => ['1; mode=block'],
                'X-Content-Type-Options' => ['nosniff'],
                'Referrer-Policy' => ['strict-origin-when-cross-origin', 'same-origin', 'no-referrer'],
                'Content-Security-Policy' => null,  // Any non-empty value is initially acceptable
                'Strict-Transport-Security' => null,  // Any non-empty value is initially acceptable
                'Permissions-Policy' => null,  // Any non-empty value is initially acceptable
            ];

            foreach ($essentialHeaders as $header => $allowedValues) {
                $value = $recommendedHeaders[$header] ?? null;
                
                if (empty($value)) {
                    $issues[] = sprintf('%s header is not configured', $header);
                } elseif ($allowedValues !== null && !in_array($value, $allowedValues)) {
                    $issues[] = sprintf(
                        '%s header has potentially unsafe value: %s (recommended: %s)',
                        $header,
                        $value,
                        implode(' or ', $allowedValues)
                    );
                }
            }

            // Specific checks for complex headers
            if (isset($recommendedHeaders['Content-Security-Policy'])) {
                $csp = $recommendedHeaders['Content-Security-Policy'];
                if ($this->str->contains($csp, "unsafe-inline") || $this->str->contains($csp, "unsafe-eval")) {
                    $issues[] = 'Content Security Policy contains unsafe directives (unsafe-inline or unsafe-eval)';
                }
            }

            if (isset($recommendedHeaders['Strict-Transport-Security'])) {
                $hsts = $recommendedHeaders['Strict-Transport-Security'];
                if (!$this->str->contains($hsts, 'max-age=') || !$this->str->contains($hsts, 'includeSubDomains')) {
                    $issues[] = 'HSTS header should include max-age and includeSubDomains directives';
                }
            }

            if (empty($issues)) {
                return [
                    'status' => 'success',
                    'message' => 'Security headers are properly configured'
                ];
            }

            return [
                'status' => count($issues) > 2 ? 'error' : 'warning',
                'message' => implode('. ', $issues)
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Error while checking security headers: ' . $e->getMessage()
            ];
        }
    }

    protected function checkErrorHandling(): array
    {
        $issues = [];
        
        try {
            // Check error reporting configuration
            $appEnv = $this->config->get('app.env', 'production');
            $debugMode = $this->config->get('app.debug', false);
            
            if ($appEnv === 'production') {
                if ($debugMode) {
                    $issues[] = 'Detailed error reporting is enabled in production';
                }
                
                // Check error display configuration in php.ini
                if (ini_get('display_errors') === '1') {
                    $issues[] = 'PHP display_errors is enabled in production';
                }
                
                if (ini_get('display_startup_errors') === '1') {
                    $issues[] = 'PHP display_startup_errors is enabled in production';
                }
            }

            // Check error log configuration
            $errorLog = $this->config->get('logging.default');
            $channels = $this->config->get('logging.channels', []);
            
            if (empty($errorLog) || empty($channels[$errorLog])) {
                $issues[] = 'Error logging is not properly configured';
            } else {
                $logChannel = $channels[$errorLog];
                if ($logChannel['driver'] === 'single' && $appEnv === 'production') {
                    $issues[] = 'Using single log file in production is not recommended';
                }
            }

            // Check for custom exception handler
            $appPath = $this->getAppPath();
            $hasCustomHandler = false;
            
            if (File::exists($appPath . '/Exceptions')) {
                $files = File::allFiles($appPath . '/Exceptions');
                foreach ($files as $file) {
                    $content = file_get_contents($file->getPathname());
                    if (preg_match('/class\s+.*Handler\s+extends\s+ExceptionHandler/', $content)) {
                        $hasCustomHandler = true;
                        
                        // Check for common security issues in exception handling
                        $unsafePatterns = [
                            'getMessage\(\)',  // Exposing exception messages
                            'getTrace\(\)',    // Exposing stack traces
                            'toArray\(\)',     // Converting exceptions to array
                        ];
                        
                        foreach ($unsafePatterns as $pattern) {
                            if (preg_match('/' . $pattern . '/', $content)) {
                                $issues[] = sprintf(
                                    'Exception handler might expose sensitive information through %s',
                                    $pattern
                                );
                            }
                        }
                        break;
                    }
                }
            }
            
            if (!$hasCustomHandler) {
                $issues[] = 'No custom exception handler found';
            }

            // Check for proper HTTP exception handling
            $commonStatusCodes = [403, 404, 419, 429, 500, 503];
            $hasErrorPages = true;
            
            foreach ($commonStatusCodes as $code) {
                if (!File::exists(base_path("resources/views/errors/{$code}.blade.php"))) {
                    $hasErrorPages = false;
                    break;
                }
            }
            
            if (!$hasErrorPages) {
                $issues[] = 'Custom error pages are not implemented for common HTTP status codes';
            }

            if (empty($issues)) {
                return [
                    'status' => 'success',
                    'message' => 'Error handling is properly configured for the current environment'
                ];
            }

            return [
                'status' => count($issues) > 2 ? 'error' : 'warning',
                'message' => implode('. ', $issues)
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Error while checking error handling: ' . $e->getMessage()
            ];
        }
    }

    protected function checkPasswordPolicies(): array
    {
        $issues = [];
        
        try {
            // Get password requirements from config
            $requirements = $this->config->get('owaspadvisor.checks.authentication.password_requirements', []);
            
            // Check minimum password length
            $minLength = $requirements['min_length'] ?? 8;
            if ($minLength < 12) {
                $issues[] = 'Minimum password length should be at least 12 characters';
            }

            // Check password complexity requirements
            if (!($requirements['require_numbers'] ?? false)) {
                $issues[] = 'Password policy does not require numbers';
            }
            if (!($requirements['require_symbols'] ?? false)) {
                $issues[] = 'Password policy does not require special characters';
            }
            if (!($requirements['require_mixed_case'] ?? false)) {
                $issues[] = 'Password policy does not require mixed case letters';
            }

            // Check for password validation rules in code
            $appPath = $this->getAppPath();
            $foundValidation = false;
            
            if (File::exists($appPath)) {
                $files = File::allFiles($appPath);
                foreach ($files as $file) {
                    if (!$this->str->endsWith($file->getRelativePathname(), ['.php'])) {
                        continue;
                    }
                    
                    $content = file_get_contents($file->getPathname());
                    if (preg_match('/[\'"]password[\'"]\s*=>\s*\[[^\]]*(?:min|regex|rules)/', $content)) {
                        $foundValidation = true;
                        
                        // Check for common password validation patterns
                        $weakPatterns = [
                            'min:6',
                            'min:8',
                            'min:10',
                            'required\|string\|min:\d+$',  // Only length validation
                        ];
                        
                        foreach ($weakPatterns as $pattern) {
                            if (preg_match('/' . $pattern . '/', $content)) {
                                $issues[] = sprintf(
                                    'Weak password validation found in %s: %s',
                                    $file->getRelativePathname(),
                                    $pattern
                                );
                            }
                        }
                    }
                }
            }
            
            if (!$foundValidation) {
                $issues[] = 'No password validation rules found in the application code';
            }

            // Check for password history/reuse prevention
            $historyCount = $this->config->get('auth.password_history', 0);
            if ($historyCount < 5) {
                $issues[] = 'Password history should keep track of at least 5 previous passwords';
            }

            // Check for password expiration policy
            $maxAge = $this->config->get('auth.password_expires_days', 0);
            if ($maxAge === 0) {
                $issues[] = 'No password expiration policy configured';
            } elseif ($maxAge > 90) {
                $issues[] = 'Password expiration period should not exceed 90 days';
            }

            if (empty($issues)) {
                return [
                    'status' => 'success',
                    'message' => 'Password policies are properly configured and enforced'
                ];
            }

            return [
                'status' => count($issues) > 2 ? 'error' : 'warning',
                'message' => implode('. ', $issues)
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Error while checking password policies: ' . $e->getMessage()
            ];
        }
    }

    protected function checkSessionSecurity(): array
    {
        $issues = [];
        
        try {
            // Check session driver
            $sessionDriver = $this->config->get('session.driver', 'file');
            if ($sessionDriver === 'file') {
                $issues[] = 'Using file session driver in production is not recommended';
            }

            // Check session configuration
            $lifetime = $this->config->get('session.lifetime', 120);
            if ($lifetime > 120) {  // 2 hours
                $issues[] = 'Session lifetime is set too high (> 2 hours)';
            }

            $secure = $this->config->get('session.secure', false);
            if (!$secure) {
                $issues[] = 'Session cookies are not set to secure-only';
            }

            $httpOnly = $this->config->get('session.http_only', true);
            if (!$httpOnly) {
                $issues[] = 'Session cookies are not set to HTTP-only';
            }

            $sameSite = $this->config->get('session.same_site', 'lax');
            if ($sameSite === 'none' || empty($sameSite)) {
                $issues[] = 'Session cookie SameSite attribute should be set to "lax" or "strict"';
            }

            // Check session configuration in code
            $appPath = $this->getAppPath();
            if (File::exists($appPath)) {
                $files = File::allFiles($appPath);
                $sessionIssues = [];
                $unsafePatterns = [
                    'Session::put\([^,]+,\s*\$.*\)',  // Potential unfiltered data in session
                    '\$request->session\(\)->put\([^,]+,\s*\$.*\)',  // Same as above
                    'session\([^,]+,\s*\$.*\)',  // Helper function version
                ];
                
                foreach ($files as $file) {
                    if (!$this->str->endsWith($file->getRelativePathname(), '.php')) {
                        continue;
                    }
                    
                    $content = file_get_contents($file->getPathname());
                    foreach ($unsafePatterns as $pattern) {
                        if (preg_match_all('/' . $pattern . '/', $content, $matches)) {
                            $sessionIssues[] = [
                                'file' => $file->getRelativePathname(),
                                'count' => count($matches[0])
                            ];
                        }
                    }
                }
                
                if (!empty($sessionIssues)) {
                    $issues[] = sprintf(
                        'Found %d potential unsafe session operations: %s',
                        array_sum(array_column($sessionIssues, 'count')),
                        implode(', ', array_map(fn($issue) => "{$issue['file']} ({$issue['count']})", array_slice($sessionIssues, 0, 3)))
                    );
                }
            }

            // Check for session fixation protection
            $regenerateOnLogin = false;
            if (File::exists($appPath . '/Http/Controllers/Auth')) {
                $files = File::allFiles($appPath . '/Http/Controllers/Auth');
                foreach ($files as $file) {
                    $content = file_get_contents($file->getPathname());
                    if (preg_match('/regenerate\(\)|session\(\)->invalidate\(\)/', $content)) {
                        $regenerateOnLogin = true;
                        break;
                    }
                }
            }
            
            if (!$regenerateOnLogin) {
                $issues[] = 'No session regeneration found after login (vulnerable to session fixation)';
            }

            if (empty($issues)) {
                return [
                    'status' => 'success',
                    'message' => 'Session security is properly configured'
                ];
            }

            return [
                'status' => count($issues) > 2 ? 'error' : 'warning',
                'message' => implode('. ', $issues)
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Error while checking session security: ' . $e->getMessage()
            ];
        }
    }

    protected function checkRateLimiting(): array
    {
        $issues = [];
        
        try {
            // Check global rate limiting middleware
            $middleware = $this->config->get('app.middleware', []);
            $hasRateLimiting = false;
            foreach ($middleware as $m) {
                if ($this->str->contains($m, ['ThrottleRequests', 'RateLimiter'])) {
                    $hasRateLimiting = true;
                    break;
                }
            }
            
            if (!$hasRateLimiting) {
                $issues[] = 'Global rate limiting middleware is not configured';
            }

            // Check rate limiting configuration
            $maxAttempts = $this->config->get('auth.max_attempts', 0);
            $decayMinutes = $this->config->get('auth.decay_minutes', 0);
            
            if ($maxAttempts === 0 || $decayMinutes === 0) {
                $issues[] = 'Authentication rate limiting is not configured';
            } elseif ($maxAttempts > 5) {
                $issues[] = 'Maximum login attempts should not exceed 5 per time window';
            }

            // Check for rate limiting in routes and controllers
            $appPath = $this->getAppPath();
            $routesPath = base_path('routes');
            $paths = [$appPath, $routesPath];
            $sensitiveEndpoints = [];
            
            foreach ($paths as $path) {
                if (!File::exists($path)) {
                    continue;
                }

                $files = File::allFiles($path);
                foreach ($files as $file) {
                    if (!$this->str->endsWith($file->getRelativePathname(), '.php')) {
                        continue;
                    }
                    
                    $content = file_get_contents($file->getPathname());
                    
                    // Check for sensitive routes without rate limiting
                    if (preg_match_all('/(?:Route::|->)(?:post|put|patch|delete)\(\s*[\'"]([^\'"]+)[\'"]/', $content, $matches)) {
                        foreach ($matches[1] as $route) {
                            if (!preg_match('/throttle|rateLimit/', $content)) {
                                $sensitiveEndpoints[] = $route;
                            }
                        }
                    }
                }
            }
            
            if (!empty($sensitiveEndpoints)) {
                $issues[] = sprintf(
                    'Found %d sensitive endpoints without rate limiting: %s',
                    count($sensitiveEndpoints),
                    implode(', ', array_slice($sensitiveEndpoints, 0, 3)) . (count($sensitiveEndpoints) > 3 ? '...' : '')
                );
            }

            // Check for API rate limiting
            $hasApiRateLimit = false;
            if (File::exists($routesPath . '/api.php')) {
                $content = file_get_contents($routesPath . '/api.php');
                if (preg_match('/throttle|rateLimit/', $content)) {
                    $hasApiRateLimit = true;
                }
            }
            
            if (!$hasApiRateLimit) {
                $issues[] = 'No rate limiting found for API routes';
            }

            if (empty($issues)) {
                return [
                    'status' => 'success',
                    'message' => 'Rate limiting is properly configured across the application'
                ];
            }

            return [
                'status' => count($issues) > 2 ? 'error' : 'warning',
                'message' => implode('. ', $issues)
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Error while checking rate limiting: ' . $e->getMessage()
            ];
        }
    }
} 