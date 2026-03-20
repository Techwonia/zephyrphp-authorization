<?php

declare(strict_types=1);

namespace ZephyrPHP\Authorization;

use ZephyrPHP\Container\Container;
use ZephyrPHP\Config\Config;

class AuthorizationServiceProvider
{
    public function register(Container $container): void
    {
        // Register Gate
        $container->singleton(Gate::class, function () {
            return new Gate();
        });

        // Register alias
        $container->alias('gate', Gate::class);
    }

    public function boot(): void
    {
        // Load policies from config
        $policies = Config::get('authorization.policies', []);

        if (!empty($policies)) {
            Gate::policies($policies);
        }

        // Register before callback for super admins
        $superAdminRole = Config::get('authorization.super_admin_ability');
        if ($superAdminRole) {
            // Handle boolean true as default 'super-admin' role slug
            if ($superAdminRole === true) {
                $superAdminRole = 'super-admin';
            }
            Gate::before(function ($user, $ability) use ($superAdminRole) {
                if ($user && method_exists($user, 'hasRole') && $user->hasRole($superAdminRole)) {
                    return true;
                }
                return null;
            });
        }

        // Wire auto-discovery and policy namespace
        $autoDiscover = Config::get('authorization.auto_discover', true);
        Gate::setAutoDiscover($autoDiscover);

        $policyNamespace = Config::get('authorization.policy_namespace', '');
        if (empty($policyNamespace)) {
            $policyNamespace = $this->detectPolicyNamespace();
        }
        Gate::setPolicyNamespace($policyNamespace);
    }

    private function detectPolicyNamespace(): string
    {
        $basePath = defined('BASE_PATH') ? BASE_PATH : getcwd();
        $composerFile = $basePath . '/composer.json';

        if (file_exists($composerFile)) {
            $composer = json_decode(file_get_contents($composerFile), true);
            $psr4 = $composer['autoload']['psr-4'] ?? [];
            foreach ($psr4 as $namespace => $path) {
                $policiesDir = $basePath . '/' . rtrim($path, '/') . '/Policies';
                if (is_dir($policiesDir)) {
                    return rtrim($namespace, '\\') . '\\Policies\\';
                }
            }
            // Use the first PSR-4 namespace as base
            foreach ($psr4 as $namespace => $path) {
                return rtrim($namespace, '\\') . '\\Policies\\';
            }
        }

        return 'App\\Policies\\';
    }
}
