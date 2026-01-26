<?php

declare(strict_types=1);

namespace Zephyr\Authorization;

use Zephyr\Container\Container;
use Zephyr\Config\Config;

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
        $superAdminAbility = Config::get('authorization.super_admin_ability');
        if ($superAdminAbility) {
            Gate::before(function ($user, $ability) use ($superAdminAbility) {
                if ($user && method_exists($user, 'hasRole') && $user->hasRole('super-admin')) {
                    return true;
                }
                return null;
            });
        }
    }
}
