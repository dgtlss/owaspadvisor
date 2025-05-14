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
        $this->info('OWASP Top 10 Security Risks (2021)');
        $this->newLine();

        $categories = [
            'A01' => [
                'name' => 'Broken Access Control',
                'description' => 'Moved up from fifth position. 3.81% of applications had one or more CWEs with over 318k occurrences in this category. The 34 CWEs mapped to Broken Access Control had more occurrences than any other category.'
            ],
            'A02' => [
                'name' => 'Cryptographic Failures',
                'description' => 'Previously known as Sensitive Data Exposure, shifted up to #2. Focuses on failures related to cryptography that often lead to sensitive data exposure or system compromise.'
            ],
            'A03' => [
                'name' => 'Injection',
                'description' => 'Moved to third position. 94% of applications were tested for injection with 3.37% average incidence rate and 274k occurrences across 33 CWEs. Now includes Cross-site Scripting.'
            ],
            'A04' => [
                'name' => 'Insecure Design',
                'description' => 'New category focusing on design flaws. Emphasizes need for threat modeling, secure design patterns and principles. Cannot be fixed by implementation alone.'
            ],
            'A05' => [
                'name' => 'Security Misconfiguration',
                'description' => 'Moved up from #6. 90% of applications tested with 4.5% average incidence rate and 208k+ CWE occurrences. Now includes former XXE category.'
            ],
            'A06' => [
                'name' => 'Vulnerable and Outdated Components',
                'description' => 'Moved up from #9. Ranked #2 in community survey. Challenging to test and assess risk. Only category without CVEs mapped to included CWEs.'
            ],
            'A07' => [
                'name' => 'Identification and Authentication Failures',
                'description' => 'Previously Broken Authentication, moved down from #2. Includes identification failures. Standardized frameworks helping reduce incidents.'
            ],
            'A08' => [
                'name' => 'Software and Data Integrity Failures',
                'description' => 'New category focusing on software updates, critical data, and CI/CD pipeline integrity. Includes former Insecure Deserialization category.'
            ],
            'A09' => [
                'name' => 'Security Logging and Monitoring Failures',
                'description' => 'Moved up from #10. Expanded to include more failure types. Challenging to test but critical for visibility and forensics.'
            ],
            'A10' => [
                'name' => 'Server-Side Request Forgery',
                'description' => 'Added from community survey (#1). Shows low incidence rate but high exploit and impact potential. Identified as important by security community.'
            ]
        ];

        foreach ($categories as $code => $data) {
            $this->line(sprintf('%s: %s', $code, $data['name'].':'));
            $this->line(sprintf('%s', $data['description']));
            $this->newLine();
        }

        $this->info('For more details visit: https://owasp.org/www-project-top-ten/');
        $runNow = confirm('Would you like to run the security audit now?', default: true);
        if ($runNow) {
            $this->call('owasp:audit');
        } else {
            $this->info('Run php artisan owasp:audit when you are ready to start the OWASP Security Audit.');
        }
    }
} 