<?php

use Illuminate\Support\Facades\Route;
use Modules\User\Http\Controllers\UserController;
use Modules\User\Http\Controllers\RoleController;
use Modules\User\Http\Controllers\PermissionController;

// Routes that require authentication
Route::middleware(['jwt.auth'])->prefix('v1')->group(function () {
    // User routes
    Route::apiResource('users', UserController::class)->names('user');
    Route::get('profile', [UserController::class, 'getProfile'])->name('user.profile');
    
    // Role and permission routes (admin only)
    Route::middleware(['role:admin'])->group(function () {
        Route::apiResource('roles', RoleController::class);
        Route::apiResource('permissions', PermissionController::class);
    });
});
