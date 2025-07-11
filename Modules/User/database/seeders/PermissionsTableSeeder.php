<?php

namespace Modules\User\Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Modules\User\Models\Role;
use Modules\User\Models\Permission;

class PermissionsTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Define permissions
        $permissions = [
            // User management
            ['name' => 'users.view', 'display_name' => 'View Users', 'description' => 'Can view user details'],
            ['name' => 'users.create', 'display_name' => 'Create Users', 'description' => 'Can create new users'],
            ['name' => 'users.edit', 'display_name' => 'Edit Users', 'description' => 'Can edit user details'],
            ['name' => 'users.delete', 'display_name' => 'Delete Users', 'description' => 'Can delete users'],
            
            // Role management
            ['name' => 'roles.view', 'display_name' => 'View Roles', 'description' => 'Can view roles'],
            ['name' => 'roles.create', 'display_name' => 'Create Roles', 'description' => 'Can create new roles'],
            ['name' => 'roles.edit', 'display_name' => 'Edit Roles', 'description' => 'Can edit roles'],
            ['name' => 'roles.delete', 'display_name' => 'Delete Roles', 'description' => 'Can delete roles'],
            
            // Permission management
            ['name' => 'permissions.view', 'display_name' => 'View Permissions', 'description' => 'Can view permissions'],
            ['name' => 'permissions.create', 'display_name' => 'Create Permissions', 'description' => 'Can create new permissions'],
            ['name' => 'permissions.edit', 'display_name' => 'Edit Permissions', 'description' => 'Can edit permissions'],
            ['name' => 'permissions.delete', 'display_name' => 'Delete Permissions', 'description' => 'Can delete permissions'],
        ];

        // Insert permissions
        foreach ($permissions as $permission) {
            Permission::create($permission);
        }
    }
} 