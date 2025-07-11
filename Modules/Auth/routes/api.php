<?php

use Illuminate\Support\Facades\Route;
use Modules\Auth\Http\Controllers\AuthController;
use Modules\Auth\Http\Controllers\RegisterController;
use Modules\Auth\Http\Controllers\PasswordResetController;
use Illuminate\Support\Facades\Mail;
use App\Mail\VerificationCodeMail;

// Public routes for authentication
Route::prefix('v1')->group(function () {
    // Get available authentication methods
    Route::get('auth/methods', [AuthController::class, 'loginMethods']);
    
    // Debug endpoint to check user information
    Route::post('auth/check-user', [AuthController::class, 'checkUser']);
    
    // Manual registration
    Route::post('register/complete', [RegisterController::class, 'completeRegistration']);
    
    // Manual login
    Route::post('login', [AuthController::class, 'login']);
    
    // Set or reset password
    Route::post('auth/set-password', [AuthController::class, 'setPassword']);
    
    // Google OAuth routes
    Route::get('auth/google/redirect', [AuthController::class, 'redirectToGoogle']);
    Route::get('auth/google/callback', [AuthController::class, 'processGoogleCallback']);
    
    // Complete profile after social authentication
    Route::post('auth/complete-profile', [AuthController::class, 'completeProfile']);
    
    // Refresh token
    Route::post('auth/refresh', [AuthController::class, 'refresh']);
    
    // Password reset routes
    Route::post('auth/forgot-password', [PasswordResetController::class, 'forgotPassword']);
    Route::post('auth/verify-reset-code', [PasswordResetController::class, 'verifyCode']);
    Route::post('auth/reset-password', [PasswordResetController::class, 'resetPassword']);
    
    // Test email sending
    Route::get('auth/test-email', function() {
        try {
            $emailData = [
                'code' => '123456',
                'name' => 'Test User',
                'type' => 'test'
            ];
            
            Mail::to('test@example.com')->send(new VerificationCodeMail($emailData));
            
            return response()->json([
                'message' => 'Test email sent successfully',
                'mail_driver' => config('mail.default'),
                'mail_from' => config('mail.from')
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Failed to send test email',
                'error' => $e->getMessage(),
                'mail_driver' => config('mail.default')
            ], 500);
        }
    });
});

// Protected routes
Route::middleware(['jwt.auth'])->prefix('v1')->group(function () {
    Route::post('logout', [AuthController::class, 'logout']);
    Route::get('user', [AuthController::class, 'user']);
    
    // Test route
    Route::get('auth/test', function() {
        return response()->json([
            'message' => 'JWT authentication works!',
            'user' => auth('api')->user(),
            'status' => 'success'
        ]);
    });
});
