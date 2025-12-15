# OWASP Advisor for Laravel

A Laravel package that helps developers ensure their applications follow OWASP Top 10 security guidelines.

## Features

- Automated security audits based on OWASP Top 10 guidelines (2025)
- Comprehensive security checks across multiple categories:
  - A01: Broken Access Control
  - A02: Security Misconfiguration
  - A03: Software Supply Chain Failures
  - A04: Cryptographic Failures
  - A05: Injection
  - A06: Insecure Design
  - A07: Authentication Failures
  - A08: Software or Data Integrity Failures
  - A09: Security Logging and Alerting Failures
  - A10: Mishandling of Exceptional Conditions
- Multiple report formats (Console, JSON, HTML)
- Configurable security checks and thresholds
- Integration with Laravel's notification system for security alerts
- Interactive command-line interface with detailed OWASP information

## Installation

You can install the package via composer:

```bash
composer require dgtlss/owaspadvisor --dev
```

After installation, publish the configuration file:

```bash
php artisan vendor:publish --provider="Dgtlss\OWASPAdvisor\OWASPAdvisorServiceProvider" --tag=config
```

To publish the views:

```bash
php artisan vendor:publish --provider="Dgtlss\OWASPAdvisor\OWASPAdvisorServiceProvider" --tag=views
```

## Usage

### Learning About OWASP Top 10

To learn more about the OWASP Top 10 security risks and get detailed descriptions:

```bash
php artisan owasp:info
```

This interactive command will:
- Display information about each OWASP Top 10 category
- Provide descriptions and context for each security risk
- Offer the option to run a security audit immediately
- Link to the official OWASP documentation

### Running a Security Audit

To perform a quick OWASP security audit of your Laravel application, use:


```bash
# Run a basic security audit with console output
php artisan owasp:audit

# Generate a JSON report
php artisan owasp:audit --format=json

# Generate and save an HTML report
php artisan owasp:audit --format=html --save
```

### OWASP Security Checks

The package performs comprehensive checks in the following categories:

1. **Broken Access Control (A01:2025)**
   - Authorization middleware usage
   - Role-based access control implementation
   - CORS configuration validation
   - Server-Side Request Forgery (SSRF) protection

2. **Security Misconfiguration (A02:2025)**
   - Debug mode settings
   - Security headers
   - Error handling configuration
   - Environment-specific configurations

3. **Software Supply Chain Failures (A03:2025)**
   - Dependency vulnerability scanning
   - Package integrity verification
   - Build pipeline security
   - Third-party component management

4. **Cryptographic Failures (A04:2025)**
   - HTTPS configuration
   - Encryption at rest
   - Password hashing algorithms and settings
   - Key management practices

5. **Injection (A05:2025)**
   - SQL injection prevention
   - XSS vulnerabilities
   - CSRF protection
   - Command injection prevention

6. **Insecure Design (A06:2025)**
   - Threat modeling documentation
   - Secure design patterns
   - Business logic validation
   - Defense in depth implementation

7. **Authentication Failures (A07:2025)**
   - Password policies
   - Session security
   - Rate limiting implementation
   - Multi-factor authentication

8. **Software or Data Integrity Failures (A08:2025)**
   - CI/CD pipeline integrity
   - Code signing verification
   - Database integrity checks
   - Update mechanism security

9. **Security Logging and Alerting Failures (A09:2025)**
   - Security event logging
   - Alerting mechanisms
   - Log retention policies
   - Monitoring integration

10. **Mishandling of Exceptional Conditions (A10:2025)**
    - Exception handling best practices
    - Resource cleanup
    - Timeout handling
    - Circuit breaker patterns

## Security Reports

Reports can be generated in three formats:

### Console Output
```
BROKEN ACCESS CONTROL (A01:2025)
---------------------------------
✓ Authorization Middleware: Properly configured
⚠ Role Permissions: Some endpoints lack role checks
✓ CORS Configuration: Secure configuration detected
✓ SSRF Protection: External request validation found

SECURITY MISCONFIGURATION (A02:2025)
------------------------------------
⚠ Debug Mode: Debug mode enabled in non-production
✓ Security Headers: All recommended headers configured
✓ Error Handling: Custom exception handler implemented

SOFTWARE SUPPLY CHAIN (A03:2025)
----------------------------------
✓ Dependency Audit: Security scanning tools configured
⚠ Package Signing: Git commit signing not configured
✓ Build Pipeline: CI/CD integrity checks in place

CRYPTOGRAPHIC FAILURES (A04:2025)
-------------------------------
✓ HTTPS Only: Enforced
✓ Encryption at Rest: Using AES-256
⚠ Password Hashing: Using default algorithm
```

### JSON Format
```json
{
  "access_control": {
    "status": "warning",
    "checks": {
      "middleware_usage": {
        "status": "success",
        "message": "Authorization middleware properly configured"
      },
      "ssrf_protection": {
        "status": "success", 
        "message": "External request validation implemented"
      }
    }
  },
  "supply_chain": {
    "status": "warning",
    "checks": {
      "dependency_audit": {
        "status": "success",
        "message": "Security scanning tools configured"
      }
    }
  }
}
```

### HTML Report
A detailed HTML report that can be saved to your storage directory.

## Configuration

The package configuration file (`config/owaspadvisor.php`) allows you to customize:

- Security check thresholds
- Report storage location
- Notification settings
- Security headers configuration
- Password requirements
- Rate limiting rules

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.