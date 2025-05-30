<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit0a9d42c2c568f01b0f7bdbd5c7758562
{
    public static $prefixLengthsPsr4 = array (
        'd' => 
        array (
            'dgtlss\\OWASPAdvisor\\' => 20,
        ),
        'A' => 
        array (
            'App\\' => 4,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'dgtlss\\OWASPAdvisor\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
        'App\\' => 
        array (
            0 => __DIR__ . '/../..' . '/app',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
        'Dgtlss\\OWASPAdvisor\\Commands\\OWASPInfoCommand' => __DIR__ . '/../..' . '/src/Commands/OWASPInfoCommand.php',
        'Dgtlss\\OWASPAdvisor\\Commands\\SecurityAuditCommand' => __DIR__ . '/../..' . '/src/Commands/SecurityAuditCommand.php',
        'Dgtlss\\OWASPAdvisor\\Contracts\\SecurityCheckService' => __DIR__ . '/../..' . '/src/Contracts/SecurityCheckService.php',
        'Dgtlss\\OWASPAdvisor\\OWASPAdvisor' => __DIR__ . '/../..' . '/src/OWASPAdvisor.php',
        'Dgtlss\\OWASPAdvisor\\OWASPAdvisorServiceProvider' => __DIR__ . '/../..' . '/src/OWASPAdvisorServiceProvider.php',
        'Dgtlss\\OWASPAdvisor\\Services\\AbstractSecurityCheckService' => __DIR__ . '/../..' . '/src/Services/AbstractSecurityCheckService.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit0a9d42c2c568f01b0f7bdbd5c7758562::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit0a9d42c2c568f01b0f7bdbd5c7758562::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit0a9d42c2c568f01b0f7bdbd5c7758562::$classMap;

        }, null, ClassLoader::class);
    }
}
