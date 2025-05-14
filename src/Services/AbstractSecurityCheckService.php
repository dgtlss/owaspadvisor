<?php

namespace Dgtlss\OWASPAdvisor\Services;

use Dgtlss\OWASPAdvisor\Contracts\SecurityCheckService;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Str;

abstract class AbstractSecurityCheckService implements SecurityCheckService
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
     * Create a new security check service instance.
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
     * Get the application base path
     */
    protected function getAppPath(): string
    {
        return app()->basePath('app');
    }

    /**
     * Update the overall status based on check results
     *
     * @param array $checks
     * @return string
     */
    protected function determineOverallStatus(array $checks): string
    {
        $status = 'success';
        
        foreach ($checks as $check) {
            if ($check['status'] === 'error') {
                return 'error';
            } elseif ($check['status'] === 'warning' && $status !== 'error') {
                $status = 'warning';
            }
        }

        return $status;
    }

    /**
     * Format the check results
     *
     * @param array $checks
     * @return array
     */
    protected function formatResults(array $checks): array
    {
        return [
            'status' => $this->determineOverallStatus($checks),
            'checks' => $checks
        ];
    }
} 