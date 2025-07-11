<?php

namespace Modules\User\Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Modules\User\Models\Role;
use Modules\User\Models\Permission;

class RolesAndPermissionsSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Create roles
        $adminRole = Role::create([
            'name' => 'admin',
            'display_name' => 'Administrator',
            'description' => 'Full access to all system features'
        ]);

        $serviceProviderRole = Role::create([
            'name' => 'service_provider',
            'display_name' => 'Service Provider',
            'description' => 'Can manage their own services and bookings'
        ]);

        $customerRole = Role::create([
            'name' => 'customer',
            'display_name' => 'Customer',
            'description' => 'Can book services and manage their own bookings'
        ]);

        // Create permissions
        // User management permissions
        $viewUsers = Permission::create(['name' => 'users.view', 'display_name' => 'View Users', 'description' => 'Can view user details']);
        $createUsers = Permission::create(['name' => 'users.create', 'display_name' => 'Create Users', 'description' => 'Can create new users']);
        $editUsers = Permission::create(['name' => 'users.edit', 'display_name' => 'Edit Users', 'description' => 'Can edit user details']);
        $deleteUsers = Permission::create(['name' => 'users.delete', 'display_name' => 'Delete Users', 'description' => 'Can delete users']);

        // Service management permissions
        $viewServices = Permission::create(['name' => 'services.view', 'display_name' => 'View Services', 'description' => 'Can view services']);
        $createServices = Permission::create(['name' => 'services.create', 'display_name' => 'Create Services', 'description' => 'Can create new services']);
        $editServices = Permission::create(['name' => 'services.edit', 'display_name' => 'Edit Services', 'description' => 'Can edit services']);
        $deleteServices = Permission::create(['name' => 'services.delete', 'display_name' => 'Delete Services', 'description' => 'Can delete services']);

        // Booking management permissions
        $viewBookings = Permission::create(['name' => 'bookings.view', 'display_name' => 'View Bookings', 'description' => 'Can view bookings']);
        $createBookings = Permission::create(['name' => 'bookings.create', 'display_name' => 'Create Bookings', 'description' => 'Can create new bookings']);
        $editBookings = Permission::create(['name' => 'bookings.edit', 'display_name' => 'Edit Bookings', 'description' => 'Can edit bookings']);
        $deleteBookings = Permission::create(['name' => 'bookings.delete', 'display_name' => 'Delete Bookings', 'description' => 'Can delete bookings']);

        // System management permissions
        $manageSystem = Permission::create(['name' => 'system.manage', 'display_name' => 'Manage System', 'description' => 'Can manage system settings']);

        // Assign permissions to roles
        
        // Admin has all permissions
        $adminPermissions = Permission::all();
        $adminRole->permissions()->attach($adminPermissions);

        // Service Provider permissions
        $serviceProviderPermissions = [
            $viewUsers->id,
            $viewServices->id, $createServices->id, $editServices->id,
            $viewBookings->id, $editBookings->id
        ];
        $serviceProviderRole->permissions()->attach($serviceProviderPermissions);

        // Customer permissions
        $customerPermissions = [
            $viewServices->id,
            $viewBookings->id, $createBookings->id, $editBookings->id
        ];
        $customerRole->permissions()->attach($customerPermissions);
    }
} 