<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('user_role', function (Blueprint $table) {
            $table->id();
            $table->uuid('user_id');
            $table->foreignId('role_id')->constrained()->onDelete('cascade');
            $table->timestamps();

            // Foreign key to users table with UUID
            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');

            // Ensure unique user-role combinations
            $table->unique(['user_id', 'role_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('user_role');
    }
}; 