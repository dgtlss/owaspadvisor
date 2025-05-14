<?php

namespace Dgtlss\OWASPAdvisor\Contracts;

interface SecurityCheckService
{
    /**
     * Run security checks for this service.
     *
     * @return array
     */
    public function check(): array;

    /**
     * Get the category name for this service.
     *
     * @return string
     */
    public function getCategory(): string;
} 