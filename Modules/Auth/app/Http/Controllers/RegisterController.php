<?php

namespace Modules\Auth\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Storage;
use App\Models\User;
use Illuminate\Validation\Rules\Password;
use Tymon\JWTAuth\Facades\JWTAuth;
use Modules\User\Helpers\UserRoleHelper;

class RegisterController extends Controller
{
    /**
     * Complete registration after email verification.
     * 
     * Use multipart/form-data content type when uploading a photo.
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function completeRegistration(Request $request)
    {
        // Validate the request
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|unique:users,email',
            'password' => [
                'required',
                'confirmed',
                Password::min(8)
                    ->mixedCase()
                    ->numbers()
                    ->symbols()],
            'phone' => 'nullable|string',
            'gender' => 'nullable|in:male,female,other',
            'birthday' => 'nullable|date',
            'photo' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:8096',
            'role_id' => 'required|in:2,3', // 2 = service_provider, 3 = customer
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        // Check if email is verified
        $verification = DB::table('verification_codes')
            ->where('email', $request->email)
            ->where('verified', true)
            ->where('type', 'registration')
            ->first();

        if (!$verification) {
            return response()->json([
                'message' => 'Email not verified. Please verify your email first.',
                'status' => 'error'
            ], 422);
        }

        try {
            // Handle photo upload if provided
            $photoPath = null;
            if ($request->hasFile('photo') && $request->file('photo')->isValid()) {
                $photoName = time() . '_' . uniqid() . '.' . $request->photo->extension();
                $photoPath = $request->photo->storeAs('users/photos', $photoName, 'public');
                $photoPath = 'storage/' . $photoPath;
            }

            // Create the user with additional fields including role_id
            $user = User::create([
                'fname' => $verification->fname,
                'lname' => $verification->lname,
                'email' => $verification->email,
                'password' => Hash::make($request->password),
                'email_verified_at' => now(),
                'phone' => $request->phone,
                'gender' => $request->gender,
                'birthday' => $request->birthday,
                'photo' => $photoPath,
                'role_id' => $request->role_id, // Set the role ID directly
            ]);

            // Delete the verification code record
            DB::table('verification_codes')
                ->where('email', $request->email)
                ->where('type', 'registration')
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

            // Return response with tokens and user info
            return response()->json([
                'message' => 'Registration completed successfully',
                'status' => 'success',
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'fname' => $user->fname,
                        'lname' => $user->lname,
                        'email' => $user->email,
                        'role' => $user->role->name,
                    ],
                    'tokens' => [
                        'access_token' => $access_token,
                        'refresh_token' => $refresh_token,
                        'token_type' => 'bearer',
                    ]
                ]
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Failed to complete registration',
                'error' => $e->getMessage(),
                'status' => 'error'
            ], 500);
        }
    }
} 