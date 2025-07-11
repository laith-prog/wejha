<?php

namespace Modules\User\Helpers;

use App\Models\User;
use Modules\User\Models\Role;

class UserRoleHelper
{
    /**
     * Assign a role to a user
     *
     * @param User $user
     * @param string $roleName
     * @return bool
     */
    public static function assignRole(User $user, string $roleName): bool
    {
        $role = Role::where('name', $roleName)->first();
        
        if (!$role) {
            return false;
        }
        
        $user->roles()->syncWithoutDetaching([$role->id]);
        
        return true;
    }
    
    /**
     * Remove a role from a user
     *
     * @param User $user
     * @param string $roleName
     * @return bool
     */
    public static function removeRole(User $user, string $roleName): bool
    {
        $role = Role::where('name', $roleName)->first();
        
        if (!$role) {
            return false;
        }
        
        $user->roles()->detach($role->id);
        
        return true;
    }
    
    /**
     * Check if a user has a specific role
     *
     * @param User $user
     * @param string $roleName
     * @return bool
     */
    public static function hasRole(User $user, string $roleName): bool
    {
        return $user->hasRole($roleName);
    }
} 