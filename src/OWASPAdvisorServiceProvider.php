<?php

namespace Dgtlss\OWASPAdvisor;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Dgtlss\OWASPAdvisor\OWASPAdvisor;
use Dgtlss\OWASPAdvisor\Commands\SecurityAuditCommand;
use Dgtlss\OWASPAdvisor\Commands\OWASPInfoCommand;

class OWASPAdvisorServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/owaspadvisor.php', 'owaspadvisor'
        );

        $this->app->singleton('owaspadvisor', function ($app) {
            return new OWASPAdvisor(
                $app['config'],
                $app['db'],
                new Str
            );
        });
    }

    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/owaspadvisor.php' => config_path('owaspadvisor.php'),
            ], 'config');

            $this->publishes([
                __DIR__.'/../resources/views' => resource_path('views/vendor/owaspadvisor'),
            ], 'views');

            $this->commands([
                SecurityAuditCommand::class,
                OWASPInfoCommand::class,
            ]);
        }

        $this->loadViewsFrom(__DIR__.'/../resources/views', 'owaspadvisor');
    }
} 