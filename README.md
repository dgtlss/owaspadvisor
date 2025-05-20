# OWASP Advisor for Laravel

A Laravel package that helps developers ensure their applications follow OWASP Top 10 security guidelines.

## Features

- Automated security audits based on OWASP Top 10 guidelines (2021)
- Comprehensive security checks across multiple categories:
  - A01: Broken Access Control
  - A02: Cryptographic Failures
  - A03: Injection
  - A04: Insecure Design
  - A05: Security Misconfiguration
  - A06: Vulnerable and Outdated Components
  - A07: Identification and Authentication Failures
  - A08: Software and Data Integrity Failures
  - A09: Security Logging and Monitoring Failures
  - A10: Server-Side Request Forgery
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

1. **Broken Access Control (A01:2021)**
   - Authorization middleware usage
   - Role-based access control implementation
   - CORS configuration validation

2. **Cryptographic Failures (A02:2021)**
   - HTTPS configuration
   - Encryption at rest
   - Password hashing algorithms and settings

3. **Injection (A03:2021)**
   - SQL injection prevention
   - XSS vulnerabilities
   - CSRF protection

4. **Security Configuration (A04:2021)**
   - Debug mode settings
   - Security headers
   - Error handling configuration

5. **Authentication (A05:2021)**
   - Password policies
   - Session security
   - Rate limiting implementation

## Security Reports

Reports can be generated in three formats:

### Console Output
```
ACCESS CONTROL
-------------
✓ Authorization Middleware: Properly configured
⚠ Role Permissions: Some endpoints lack role checks
✓ CORS Configuration: Secure configuration detected

CRYPTOGRAPHY
-----------
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