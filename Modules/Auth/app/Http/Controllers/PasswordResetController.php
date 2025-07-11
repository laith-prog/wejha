<?php

namespace Modules\Auth\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Mail\VerificationCodeMail;
use Carbon\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;

class PasswordResetController extends Controller
{
    /**
     * Send a password reset code to the user's email
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function forgotPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        // Check if user exists
        $user = User::where('email', $request->email)->first();
        
        if (!$user) {
            return response()->json([
                'message' => 'User not found with this email',
                'status' => 'error'
            ], 404);
        }

        // Generate a random 6-digit code
        $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        
        Log::info('Generating password reset code', [
            'email' => $user->email,
            'code' => $code
        ]);
        
        try {
            // Store the code in the verification_codes table with type 'password_reset'
            DB::table('verification_codes')->updateOrInsert(
                ['email' => $user->email, 'type' => 'password_reset'],
                [
                    'code' => $code,
                    'fname' => $user->fname,
                    'lname' => $user->lname,
                    'verified' => false,
                    'type' => 'password_reset',
                    'expires_at' => Carbon::now()->addMinutes(15),
                    'created_at' => Carbon::now(),
                    'updated_at' => Carbon::now(),
                ]
            );
            
            Log::info('Verification code stored in database', [
                'email' => $user->email,
                'type' => 'password_reset'
            ]);
            
            // Send the verification code email
            $emailData = [
                'code' => $code,
                'name' => $user->fname,
                'type' => 'password_reset'
            ];
            
            Log::info('Attempting to send password reset email', $emailData);
            
            Mail::to($user->email)->send(new VerificationCodeMail($emailData));
            
            Log::info('Password reset email sent successfully');
            
            return response()->json([
                'message' => 'Password reset code sent to your email',
                'status' => 'success',
                'data' => [
                    'email' => $user->email,
                    'expires_in' => 15, // minutes
                    'mail_driver' => config('mail.default')
                ]
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to send password reset code', [
                'email' => $user->email,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            return response()->json([
                'message' => 'Failed to send password reset code',
                'error' => $e->getMessage(),
                'status' => 'error'
            ], 500);
        }
    }
    
    /**
     * Verify the password reset code
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function verifyCode(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'code' => 'required|string|size:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }
        
        // Check if the code exists and is valid
        $verification = DB::table('verification_codes')
            ->where('email', $request->email)
            ->where('code', $request->code)
            ->where('type', 'password_reset')
            ->first();
            
        if (!$verification) {
            return response()->json([
                'message' => 'Invalid verification code',
                'status' => 'error'
            ], 400);
        }
        
        // Check if the code has expired
        if (Carbon::parse($verification->expires_at)->isPast()) {
            return response()->json([
                'message' => 'Verification code has expired',
                'status' => 'error'
            ], 400);
        }
        
        // Mark the code as verified
        DB::table('verification_codes')
            ->where('email', $request->email)
            ->where('type', 'password_reset')
            ->update([
                'verified' => true,
                'updated_at' => Carbon::now(),
            ]);
            
        return response()->json([
            'message' => 'Verification code is valid',
            'status' => 'success',
            'data' => [
                'email' => $request->email,
                'can_reset_password' => true
            ]
        ]);
    }
    
    /**
     * Reset the password after verification
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function resetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }
        
        // Check if the email has been verified for password reset
        $verification = DB::table('verification_codes')
            ->where('email', $request->email)
            ->where('type', 'password_reset')
            ->where('verified', true)
            ->first();
            
        if (!$verification) {
            return response()->json([
                'message' => 'Email not verified for password reset',
                'status' => 'error'
            ], 400);
        }
        
        // Find the user
        $user = User::where('email', $request->email)->first();
        
        if (!$user) {
            return response()->json([
                'message' => 'User not found',
                'status' => 'error'
            ], 404);
        }
        
        try {
            // Update the password
            $user->update([
                'password' => Hash::make($request->password)
            ]);
            
            // Delete the verification code
            DB::table('verification_codes')
                ->where('email', $request->email)
                ->where('type', 'password_reset')
                ->delete();
                
            // Generate JWT tokens
            Auth::guard('api')->login($user);
            
            // Create access token
            $access_token = JWTAuth::fromUser($user);
            
            // Create refresh token with custom claims
            $refresh_token = JWTAuth::customClaims([
                'sub' => $user->id,
                'refresh' => true,
                'exp' => now()->addDays(30)->timestamp // 30 days expiry for refresh token
            ])->fromUser($user);
            
            return response()->json([
                'message' => 'Password reset successful',
                'status' => 'success',
                'data' => [
                    'user' => $user,
                    'access_token' => $access_token,
                    'refresh_token' => $refresh_token,
                    'token_type' => 'access',
                    'expires_in' => auth('api')->factory()->getTTL() * 60
                ]
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to reset password', [
                'email' => $user->email,
                'error' => $e->getMessage()
            ]);
            
            return response()->json([
                'message' => 'Failed to reset password',
                'error' => $e->getMessage(),
                'status' => 'error'
            ], 500);
        }
    }
} 