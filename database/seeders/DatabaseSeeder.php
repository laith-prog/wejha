<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Modules\User\Database\Seeders\RolesTableSeeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        // Run the roles seeder first
        $this->call(RolesTableSeeder::class);

        // Then create users
        User::factory()->create([
            'fname' => 'Test',
            'lname' => 'User',
            'email' => 'test@example.com',
            'role_id' => 3, // Customer role
        ]);
    }
}
