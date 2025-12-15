<?php

namespace Dgtlss\OWASPAdvisor\Commands;

use Illuminate\Console\Command;
use function Laravel\Prompts\confirm;


class OWASPInfoCommand extends Command
{
    protected $signature = 'owasp:info';
    protected $description = 'Display information about the OWASP Advisor tool';

    public function handle()
    {
        $this->info('OWASP Top 10 Security Risks (2025)');
        $this->newLine();

        $categories = [
            'A01' => [
                'name' => 'Broken Access Control',
                'description' => 'Maintains position at #1 as the most serious application security risk. 3.73% of applications tested had one or more CWEs in this category. Server-Side Request Forgery (SSRF) has been rolled into this category.'
            ],
            'A02' => [
                'name' => 'Security Misconfiguration',
                'description' => 'Moved up from #5 in 2021 to #2 in 2025. Misconfigurations are more prevalent in the data. 3.00% of applications tested had one or more CWEs in this category.'
            ],
            'A03' => [
                'name' => 'Software Supply Chain Failures',
                'description' => 'New category expanding on Vulnerable and Outdated Components. Includes broader scope of compromises across software dependencies, build systems, and distribution infrastructure. Voted top concern in community survey.'
            ],
            'A04' => [
                'name' => 'Cryptographic Failures',
                'description' => 'Falls two spots from #2 to #4. 3.80% of applications have one or more CWEs in this category. Often leads to sensitive data exposure or system compromise.'
            ],
            'A05' => [
                'name' => 'Injection',
                'description' => 'Falls two spots from #3 to #5. One of the most tested categories with the greatest number of CVEs. Includes Cross-site Scripting (high frequency/low impact) to SQL Injection (low frequency/high impact).'
            ],
            'A06' => [
                'name' => 'Insecure Design',
                'description' => 'Slides two spots from #4 to #6. Noticeable improvements in industry related to threat modeling and greater emphasis on secure design since 2021.'
            ],
            'A07' => [
                'name' => 'Authentication Failures',
                'description' => 'Maintains position at #7 with slight name change from "Identification and Authentication Failures". Increased use of standardized frameworks for authentication appears beneficial.'
            ],
            'A08' => [
                'name' => 'Software or Data Integrity Failures',
                'description' => 'Continues at #8. Focused on failure to maintain trust boundaries and verify integrity of software, code, and data artifacts at lower level than Software Supply Chain Failures.'
            ],
            'A09' => [
                'name' => 'Security Logging & Alerting Failures',
                'description' => 'Retains position at #9. Slight name change to emphasize importance of alerting functionality. Great logging with no alerting has minimal value in identifying security incidents.'
            ],
            'A10' => [
                'name' => 'Mishandling of Exceptional Conditions',
                'description' => 'New category for 2025. Contains 24 CWEs focusing on improper error handling, logical errors, failing open, and other scenarios from abnormal conditions that systems may encounter.'
            ]
        ];

        foreach ($categories as $code => $data) {
            $this->line(sprintf('%s: %s', $code, $data['name'].':'));
            $this->line(sprintf('%s', $data['description']));
            $this->newLine();
        }

        $this->info('For more details visit: https://owasp.org/Top10/2025/');
        $runNow = confirm('Would you like to run the security audit now?', default: true);
        if ($runNow) {
            $this->call('owasp:audit');
        } else {
            $this->info('Run php artisan owasp:audit when you are ready to start the OWASP Security Audit.');
        }
    }
} 