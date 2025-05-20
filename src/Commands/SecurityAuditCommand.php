<?php

namespace Dgtlss\OWASPAdvisor\Commands;

use Illuminate\Console\Command;
use Dgtlss\OWASPAdvisor\OWASPAdvisor;

class SecurityAuditCommand extends Command
{
    protected $signature = 'owasp:audit 
        {--format=console : Output format (console, json, html)}
        {--save : Save the report to storage}';

    protected $description = 'Run OWASP security audit on your Laravel application';

    protected $advisor;

    public function __construct(OWASPAdvisor $advisor)
    {
        parent::__construct();
        $this->advisor = $advisor;
    }

    public function handle(): void
    {
        $this->info('Starting OWASP Security Audit...');
        $this->newLine();

        $results = $this->advisor->runSecurityAudit();
        
        $format = $this->option('format');
        
        switch ($format) {
            case 'json':
                $this->outputJson($results);
                break;
            case 'html':
                $this->outputHtml($results);
                break;
            default:
                $this->outputConsole($results);

        }

        $this->newLine();
        $this->info('OWASP Security Audit completed.');
        $this->info('Please review the report and take action to improve your application\'s security.');
        $this->newLine();
        $this->info('If you found this tool helpful, please consider starring the repository: https://github.com/dgtlss/owaspadvisor');
        $this->newLine();
        $this->info('Thank you for using OWASP Advisor!');

        if ($this->option('save')) {
            $this->saveReport($results);
        }
    }

    protected function outputConsole(array $results): void
    {
        foreach ($results as $category => $data) {
            $this->info(strtoupper($category));
            $this->line(str_repeat('-', strlen($category)));

            foreach ($data['checks'] as $check => $result) {
                $status = $result['status'];
                $message = $result['message'];

                $statusSymbol = match($status) {
                    'success' => '✓',
                    'warning' => '⚠',
                    'error' => '✗',
                    default => '?'
                };

                $this->line(sprintf(
                    '%s %s: %s',
                    $statusSymbol,
                    ucfirst(str_replace('_', ' ', $check)),
                    $message
                ));
            }

            $this->newLine();
        }
    }

    protected function outputJson(array $results): void
    {
        $this->line(json_encode($results, JSON_PRETTY_PRINT));
    }

    protected function outputHtml(array $results): void
    {
        // Generate HTML report using a blade view
        $html = view('owaspadvisor::report', compact('results'))->render();
        $this->line($html);
    }

    protected function saveReport(array $results): void
    {
        $format = $this->option('format');
        $filename = sprintf(
            'security-audit-%s.%s',
            date('Y-m-d-His'),
            $format === 'html' ? 'html' : 'json'
        );

        $reportPath = config('owaspadvisor.reporting.report_path', storage_path('security-reports'));
        
        if (!file_exists($reportPath)) {
            mkdir($reportPath, 0755, true);
        }

        $fullPath = $reportPath . '/' . $filename;
        
        $content = match($format) {
            'html' => view('owaspadvisor::report', compact('results'))->render(),
            default => json_encode($results, JSON_PRETTY_PRINT)
        };

        file_put_contents($fullPath, $content);
        
        $this->info(sprintf('Report saved to: %s', $fullPath));
    }
} 