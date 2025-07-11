<?php

use Illuminate\Support\Facades\Route;
use Modules\Verification\Http\Controllers\VerificationController;

Route::middleware(['auth', 'verified'])->group(function () {
    Route::resource('verifications', VerificationController::class)->names('verification');
});
