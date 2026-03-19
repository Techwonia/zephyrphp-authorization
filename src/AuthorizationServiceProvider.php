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

        $policyNamespace = Config::get('authorization.policy_namespace', 'App\\Policies\\');
        Gate::setPolicyNamespace($policyNamespace);
    }
}
