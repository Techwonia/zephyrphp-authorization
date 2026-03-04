<?php

declare(strict_types=1);

namespace ZephyrPHP\Authorization;

use ZephyrPHP\Auth\Auth;
use ZephyrPHP\Auth\AuthenticatableInterface;

/**
 * Authorization Gate
 *
 * Provides a simple way to authorize user actions using abilities and policies.
 *
 * Usage:
 *   // Define abilities
 *   Gate::define('edit-post', function($user, $post) {
 *       return $user->id === $post->user_id;
 *   });
 *
 *   // Check abilities
 *   if (Gate::allows('edit-post', $post)) { ... }
 *   if (Gate::denies('edit-post', $post)) { ... }
 *
 *   // Authorize (throws exception if denied)
 *   Gate::authorize('edit-post', $post);
 *
 *   // Use policies
 *   Gate::policy(Post::class, PostPolicy::class);
 */
class Gate
{
    /** @var array<string, callable> Registered abilities */
    private static array $abilities = [];

    /** @var array<string, string> Model to policy class mappings */
    private static array $policies = [];

    /** @var array<string, callable> Before callbacks */
    private static array $beforeCallbacks = [];

    /** @var array<string, callable> After callbacks */
    private static array $afterCallbacks = [];

    /** @var callable|null User resolver */
    private static $userResolver = null;

    /**
     * Define an authorization ability
     *
     * @param string $ability The ability name
     * @param callable $callback The authorization callback
     */
    public static function define(string $ability, callable $callback): void
    {
        self::$abilities[$ability] = $callback;
    }

    /**
     * Register a policy class for a model
     *
     * @param string $model The model class
     * @param string $policy The policy class
     */
    public static function policy(string $model, string $policy): void
    {
        self::$policies[$model] = $policy;
    }

    /**
     * Register multiple policies at once
     *
     * @param array<string, string> $policies Model => Policy mappings
     */
    public static function policies(array $policies): void
    {
        foreach ($policies as $model => $policy) {
            self::policy($model, $policy);
        }
    }

    /**
     * Check if the user is allowed to perform an ability
     *
     * @param string $ability The ability name
     * @param mixed ...$arguments Additional arguments (usually the model)
     * @return bool True if allowed
     */
    public static function allows(string $ability, mixed ...$arguments): bool
    {
        return self::check($ability, ...$arguments);
    }

    /**
     * Check if the user is denied from performing an ability
     *
     * @param string $ability The ability name
     * @param mixed ...$arguments Additional arguments
     * @return bool True if denied
     */
    public static function denies(string $ability, mixed ...$arguments): bool
    {
        return !self::allows($ability, ...$arguments);
    }

    /**
     * Check if the user can perform an ability
     *
     * @param string $ability The ability name
     * @param mixed ...$arguments Additional arguments
     * @return bool True if allowed
     */
    public static function check(string $ability, mixed ...$arguments): bool
    {
        $user = self::resolveUser();

        // Run before callbacks
        foreach (self::$beforeCallbacks as $callback) {
            $result = $callback($user, $ability, $arguments);
            if ($result !== null) {
                return (bool) $result;
            }
        }

        // Check policy first
        $result = self::checkPolicy($user, $ability, $arguments);

        // Fall back to defined ability
        if ($result === null) {
            $result = self::checkAbility($user, $ability, $arguments);
        }

        // Run after callbacks
        foreach (self::$afterCallbacks as $callback) {
            $afterResult = $callback($user, $ability, $result, $arguments);
            if ($afterResult !== null) {
                $result = $afterResult;
            }
        }

        return (bool) $result;
    }

    /**
     * Check multiple abilities at once (all must pass)
     *
     * @param array $abilities Array of abilities or ability => arguments pairs
     * @return bool True if all are allowed
     */
    public static function all(array $abilities): bool
    {
        foreach ($abilities as $ability => $arguments) {
            if (is_int($ability)) {
                $ability = $arguments;
                $arguments = [];
            }

            $arguments = is_array($arguments) ? $arguments : [$arguments];

            if (!self::check($ability, ...$arguments)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check multiple abilities at once (any must pass)
     *
     * @param array $abilities Array of abilities or ability => arguments pairs
     * @return bool True if any is allowed
     */
    public static function any(array $abilities): bool
    {
        foreach ($abilities as $ability => $arguments) {
            if (is_int($ability)) {
                $ability = $arguments;
                $arguments = [];
            }

            $arguments = is_array($arguments) ? $arguments : [$arguments];

            if (self::check($ability, ...$arguments)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if no abilities pass
     *
     * @param array $abilities Array of abilities
     * @return bool True if none are allowed
     */
    public static function none(array $abilities): bool
    {
        return !self::any($abilities);
    }

    /**
     * Authorize an ability (throws exception if denied)
     *
     * @param string $ability The ability name
     * @param mixed ...$arguments Additional arguments
     * @throws AuthorizationException If denied
     */
    public static function authorize(string $ability, mixed ...$arguments): void
    {
        if (self::denies($ability, ...$arguments)) {
            throw new AuthorizationException("This action is unauthorized: {$ability}");
        }
    }

    /**
     * Get the policy for a model
     *
     * @param object|string $model The model instance or class
     * @return object|null The policy instance
     */
    public static function getPolicyFor(object|string $model): ?object
    {
        $class = is_object($model) ? get_class($model) : $model;

        if (!isset(self::$policies[$class])) {
            // Try to auto-discover policy
            $policyClass = self::guessPolicyName($class);
            if (class_exists($policyClass)) {
                self::$policies[$class] = $policyClass;
            } else {
                return null;
            }
        }

        $policyClass = self::$policies[$class];
        return new $policyClass();
    }

    /**
     * Register a before callback
     *
     * @param callable $callback Callback that runs before ability check
     */
    public static function before(callable $callback): void
    {
        self::$beforeCallbacks[] = $callback;
    }

    /**
     * Register an after callback
     *
     * @param callable $callback Callback that runs after ability check
     */
    public static function after(callable $callback): void
    {
        self::$afterCallbacks[] = $callback;
    }

    /**
     * Set the user resolver
     *
     * @param callable $resolver Function that returns the current user
     */
    public static function setUserResolver(callable $resolver): void
    {
        self::$userResolver = $resolver;
    }

    /**
     * Check a policy for authorization
     */
    private static function checkPolicy(?AuthenticatableInterface $user, string $ability, array $arguments): ?bool
    {
        // Get the first argument to determine the model
        $model = $arguments[0] ?? null;

        if ($model === null) {
            return null;
        }

        $policy = self::getPolicyFor($model);
        if ($policy === null) {
            return null;
        }

        // Convert ability to method name (e.g., 'edit-post' => 'editPost')
        $method = self::formatAbilityMethod($ability);

        if (!method_exists($policy, $method)) {
            return null;
        }

        // Call the policy method
        return $policy->$method($user, ...$arguments);
    }

    /**
     * Check a defined ability
     */
    private static function checkAbility(?AuthenticatableInterface $user, string $ability, array $arguments): ?bool
    {
        if (!isset(self::$abilities[$ability])) {
            return false;
        }

        $callback = self::$abilities[$ability];

        return $callback($user, ...$arguments);
    }

    /**
     * Resolve the current user
     */
    private static function resolveUser(): ?AuthenticatableInterface
    {
        if (self::$userResolver !== null) {
            return (self::$userResolver)();
        }

        // Default to Auth::user()
        return Auth::user();
    }

    /**
     * Format ability name to method name
     */
    private static function formatAbilityMethod(string $ability): string
    {
        // Convert 'edit-post' or 'edit_post' to 'editPost'
        return lcfirst(str_replace(' ', '', ucwords(str_replace(['-', '_'], ' ', $ability))));
    }

    /**
     * Guess the policy name for a model
     */
    private static function guessPolicyName(string $model): string
    {
        // App\Models\Post => App\Policies\PostPolicy
        $class = class_basename($model);
        $namespace = 'App\\Policies\\';

        return $namespace . $class . 'Policy';
    }

    /**
     * Check if an ability is defined
     */
    public static function has(string $ability): bool
    {
        return isset(self::$abilities[$ability]);
    }

    /**
     * Get all defined abilities
     */
    public static function abilities(): array
    {
        return array_keys(self::$abilities);
    }

    /**
     * Reset all gates (for testing)
     */
    public static function reset(): void
    {
        self::$abilities = [];
        self::$policies = [];
        self::$beforeCallbacks = [];
        self::$afterCallbacks = [];
        self::$userResolver = null;
    }
}
