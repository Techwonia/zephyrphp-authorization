<?php

/**
 * Authorization Configuration
 *
 * Configure gates, policies, and authorization behavior.
 */

return [
    /*
    |--------------------------------------------------------------------------
    | Model to Policy Mappings
    |--------------------------------------------------------------------------
    |
    | Register your model to policy mappings here.
    | Format: 'Model\Class' => 'Policy\Class'
    |
    */
    'policies' => [
        // 'App\Models\Post' => 'App\Policies\PostPolicy',
        // 'App\Models\Comment' => 'App\Policies\CommentPolicy',
    ],

    /*
    |--------------------------------------------------------------------------
    | Super Admin Bypass
    |--------------------------------------------------------------------------
    |
    | When enabled, users with the 'super-admin' role will bypass all
    | authorization checks. Set to false to disable.
    |
    */
    'super_admin_ability' => 'super-admin',

    /*
    |--------------------------------------------------------------------------
    | Policy Discovery
    |--------------------------------------------------------------------------
    |
    | Enable automatic policy discovery. When enabled, the Gate will
    | automatically look for policies in App\Policies based on model names.
    |
    */
    'auto_discover' => true,

    /*
    |--------------------------------------------------------------------------
    | Policy Namespace
    |--------------------------------------------------------------------------
    |
    | The namespace where policies are located for auto-discovery.
    |
    */
    'policy_namespace' => '', // Auto-detected from composer.json PSR-4 mapping
];
