<?php

namespace Modules\User\Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class RolesTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        DB::table('roles')->insert([
            [
                'id' => 1,
                'name' => 'admin',
                'display_name' => 'Administrator',
                'description' => 'Full access to all system features',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'id' => 2,
                'name' => 'service_provider',
                'display_name' => 'Service Provider',
                'description' => 'Can manage their own services and bookings',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'id' => 3,
                'name' => 'customer',
                'display_name' => 'Customer',
                'description' => 'Can book services and manage their own bookings',
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);
    }
} 