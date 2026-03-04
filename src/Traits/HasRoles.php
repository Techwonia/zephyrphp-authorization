<?php

declare(strict_types=1);

namespace ZephyrPHP\Authorization\Traits;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;

/**
 * HasRoles Trait
 *
 * Provides role management for User models via Doctrine ManyToMany.
 * The Role entity class is resolved from the user's app namespace.
 *
 * Usage:
 *   class User extends Model implements AuthenticatableInterface
 *   {
 *       use Authenticatable, HasRoles;
 *   }
 */
trait HasRoles
{
    /**
     * Initialize roles collection
     * Call this in the entity constructor: $this->initializeRoles()
     */
    protected function initializeRoles(): void
    {
        if (!isset($this->roles) || $this->roles === null) {
            $this->roles = new ArrayCollection();
        }
    }

    /**
     * Get all roles
     */
    public function getRoles(): Collection
    {
        return $this->roles ?? new ArrayCollection();
    }

    /**
     * Check if user has a specific role by name
     */
    public function hasRole(string $roleName): bool
    {
        foreach ($this->getRoles() as $role) {
            if (method_exists($role, 'getName') && $role->getName() === $roleName) {
                return true;
            }
            if (method_exists($role, 'getSlug') && $role->getSlug() === $roleName) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has any of the given roles
     */
    public function hasAnyRole(array $roleNames): bool
    {
        foreach ($roleNames as $roleName) {
            if ($this->hasRole($roleName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has all of the given roles
     */
    public function hasAllRoles(array $roleNames): bool
    {
        foreach ($roleNames as $roleName) {
            if (!$this->hasRole($roleName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Assign a role to the user
     *
     * @param object|string $role Role entity instance or role name
     */
    public function assignRole(object|string $role): self
    {
        if (is_string($role)) {
            // Caller must resolve the Role entity before assigning
            // This is a convenience check — if a string is passed, skip silently
            return $this;
        }

        if (!$this->getRoles()->contains($role)) {
            $this->getRoles()->add($role);
        }

        return $this;
    }

    /**
     * Remove a role from the user
     *
     * @param object|string $role Role entity instance or role name
     */
    public function removeRole(object|string $role): self
    {
        if (is_string($role)) {
            // Find role by name and remove it
            foreach ($this->getRoles() as $existingRole) {
                $name = method_exists($existingRole, 'getName') ? $existingRole->getName() : '';
                if ($name === $role) {
                    $this->getRoles()->removeElement($existingRole);
                    break;
                }
            }
            return $this;
        }

        $this->getRoles()->removeElement($role);

        return $this;
    }

    /**
     * Sync roles — replace all current roles with the given ones
     *
     * @param array $roles Array of Role entity instances
     */
    public function syncRoles(array $roles): self
    {
        $this->roles = new ArrayCollection($roles);
        return $this;
    }

    /**
     * Get role names as an array of strings
     */
    public function getRoleNames(): array
    {
        $names = [];
        foreach ($this->getRoles() as $role) {
            if (method_exists($role, 'getName')) {
                $names[] = $role->getName();
            }
        }

        return $names;
    }
}
