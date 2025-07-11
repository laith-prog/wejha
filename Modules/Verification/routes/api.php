<?php

use Illuminate\Support\Facades\Route;
use Modules\Verification\Http\Controllers\VerificationController;

// Routes that require authentication
Route::middleware(['auth:sanctum'])->prefix('v1')->group(function () {
    Route::apiResource('verifications', VerificationController::class)->names('verification');
});

// Public routes for registration process
Route::prefix('v1')->group(function () {
    Route::post('verification/send', [VerificationController::class, 'sendCode']);
    Route::post('verification/verify', [VerificationController::class, 'verifyCode']);
});
