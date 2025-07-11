<?php

namespace Modules\Auth\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Str;
use Exception;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    /**
     * Debug endpoint to check user information
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function checkUser(Request $request)
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

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json([
                'message' => 'User not found',
                'status' => 'error'
            ], 404);
        }

        return response()->json([
            'message' => 'User found',
            'status' => 'success',
            'data' => [
                'user' => [
                    'id' => $user->id,
                    'fname' => $user->fname,
                    'lname' => $user->lname,
                    'email' => $user->email,
                    'email_verified_at' => $user->email_verified_at,
                    'auth_provider' => $user->auth_provider,
                    'has_password' => !empty($user->password),
                    'created_at' => $user->created_at,
                    'updated_at' => $user->updated_at,
                ]
            ]
        ]);
    }

    /**
     * Get available authentication methods
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function loginMethods()
    {
        return response()->json([
            'message' => 'Available authentication methods',
            'methods' => [
                [
                    'name' => 'Manual Login',
                    'description' => 'Login with email and password',
                    'endpoint' => '/api/v1/login',
                    'method' => 'POST',
                    'parameters' => [
                        'email' => 'required|email',
                        'password' => 'required|string',
                    ]
                ],
                [
                    'name' => 'Manual Registration',
                    'description' => 'Complete registration after email verification',
                    'endpoint' => '/api/v1/register/complete',
                    'method' => 'POST',
                    'parameters' => [
                        'email' => 'required|email|unique:users,email',
                        'password' => 'required|confirmed|min:8',
                        'password_confirmation' => 'required|same:password',
                        'phone' => 'nullable|string',
                        'gender' => 'nullable|in:male,female,other',
                        'birthday' => 'nullable|date',
                        'photo' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048',
                    ],
                    'note' => 'This endpoint requires multipart/form-data when uploading a photo'
                ],
                [
                    'name' => 'Google Authentication',
                    'description' => 'Register or Login with Google account',
                    'endpoint' => '/api/v1/auth/google',
                    'method' => 'GET',
                    'flow' => [
                        'step1' => 'Make GET request to /api/v1/auth/google',
                        'step2' => 'Open the returned redirect_url in browser',
                        'step3' => 'Select Google account and authorize',
                        'step4' => 'You will be automatically registered or logged in'
                    ]
                ]
            ]
        ]);
    }

    /**
     * Login user with email and password
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        // Check email
        $user = User::where('email', $request->email)->first();
        
        if (!$user) {
            return response()->json([
                'message' => 'User not found with this email',
                'status' => 'error'
            ], 401);
        }
        
        // Check password
        if (!Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Password is incorrect',
                'status' => 'error'
            ], 401);
        }

        try {
            // Create tokens
            $token = $this->createTokens($user);
            
            return response()->json([
                'message' => 'Login successful',
                'status' => 'success',
                'data' => [
                    'user' => $user,
                    'access_token' => $token['access_token'],
                    'refresh_token' => $token['refresh_token'],
                    'token_type' => 'Bearer',
                    'expires_in' => auth('api')->factory()->getTTL() * 60
                ]
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'message' => 'Could not create token',
                'status' => 'error'
            ], 500);
        }
    }

    /**
     * Set or reset password for an account
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function setPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
            'password_confirmation' => 'required|same:password',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $user = User::where('email', $request->email)->first();
            
            if (!$user) {
                return response()->json([
                    'message' => 'User not found with this email',
                    'status' => 'error'
                ], 404);
            }
            
            // Update the password
            $user->update([
                'password' => Hash::make($request->password)
            ]);
    
            // Generate token
            $token = $this->createTokens($user);
    
            return response()->json([
                'message' => 'Password set successfully',
                'status' => 'success',
                'data' => [
                    'user' => $user,
                    'access_token' => $token['access_token'],
                    'refresh_token' => $token['refresh_token'],
                    'token_type' => 'Bearer',
                    'expires_in' => auth('api')->factory()->getTTL() * 60
                ]
            ]);
        } catch (Exception $e) {
            Log::error('Error setting password: ' . $e->getMessage());
            return response()->json([
                'message' => 'Error setting password',
                'error' => $e->getMessage(),
                'status' => 'error'
            ], 500);
        }
    }

    /**
     * Handle Google OAuth authentication
     */
    public function handleGoogleAuth(Request $request)
    {
        try {
            // Check if we have an error from Google
            if ($request->has('error')) {
                return response()->json([
                    'message' => 'Google authentication failed',
                    'error' => $request->get('error')
                ], 400);
            }
            
            // Get user data from Google
            $googleUser = Socialite::driver('google')->stateless()->user();
            
            // Check if user exists
            $user = User::where('email', $googleUser->getEmail())->first();
            
            $isNewUser = false;
            $needsProfileCompletion = false;
            
            if (!$user) {
                // This is a registration scenario
                $isNewUser = true;
                
                // Extract name parts
                $nameParts = $this->extractNameParts($googleUser->getName());
                
                // Create user with all available data from Google
                $user = User::create([
                    'fname' => $nameParts['first_name'],
                    'lname' => $nameParts['last_name'],
                    'email' => $googleUser->getEmail(),
                    'password' => Hash::make(Str::random(16)), // Random password
                    'email_verified_at' => now(),
                    'auth_provider' => 'google',
                    'photo' => $googleUser->getAvatar(),
                    // Don't set role_id yet as it's required for new users
                ]);
                
                // New users need to select a role
                $needsProfileCompletion = true;
            } else {
                // This is a login scenario
                // Update existing user with Google info if they're using Google auth
                if ($user->auth_provider == 'google' || $user->auth_provider == null) {
                    $user->update([
                        'auth_provider' => 'google',
                        'photo' => $googleUser->getAvatar() ?: $user->photo,
                        'email_verified_at' => $user->email_verified_at ?? now(),
                    ]);
                }
            }
            
            // Generate tokens
            $tokens = $this->generateTokens($user);
            
            // Prepare response
            $response = [
                'message' => $isNewUser ? 'Registration successful' : 'Login successful',
                'status' => 'success',
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'fname' => $user->fname,
                        'lname' => $user->lname,
                        'email' => $user->email,
                        'is_new_user' => $isNewUser,
                        'needs_profile_completion' => $needsProfileCompletion,
                    ],
                    'tokens' => $tokens
                ]
            ];
            
            // For API requests, return JSON
            if ($request->expectsJson() || $request->ajax()) {
                return response()->json($response);
            }
            
            // For web requests, redirect with parameters
            $frontendUrl = config('app.frontend_url', 'http://localhost:3000');
            $redirectUrl = $frontendUrl . '/auth/google-callback';
            
            // Add query parameters
            $queryParams = [
                'access_token' => $tokens['access_token'],
                'refresh_token' => $tokens['refresh_token'],
                'is_new_user' => $isNewUser ? '1' : '0',
                'needs_profile_completion' => $needsProfileCompletion ? '1' : '0',
                'user_id' => $user->id
            ];
            
            $redirectUrl .= '?' . http_build_query($queryParams);
            
            return redirect()->away($redirectUrl);
            
        } catch (\Exception $e) {
            Log::error('Google auth error', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            if ($request->expectsJson() || $request->ajax()) {
            return response()->json([
                    'message' => 'Authentication failed',
                    'error' => $e->getMessage(),
                    'status' => 'error'
            ], 500);
            }
            
            // Redirect to frontend error page
            $frontendUrl = config('app.frontend_url', 'http://localhost:3000');
            return redirect()->away($frontendUrl . '/auth/error?message=' . urlencode('Authentication failed: ' . $e->getMessage()));
        }
    }

    /**
     * Handle Google callback - process registration or login
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    protected function handleGoogleCallback(Request $request)
    {
        try {
            // Check if we have an error from Google
            if ($request->has('error')) {
                return response()->json([
                    'message' => 'Google authentication failed',
                    'error' => $request->get('error')
                ], 400);
            }
            
            // Get user data from Google
            $googleUser = Socialite::driver('google')->stateless()->user();
            
            // Check if user exists
            $user = User::where('email', $googleUser->getEmail())->first();
            
            $isNewUser = false;
            
            if (!$user) {
                // This is a registration scenario
                $isNewUser = true;
                
                // Extract name parts
                $nameParts = $this->extractNameParts($googleUser->getName());
                
                // Create user
                $user = User::create([
                    'fname' => $nameParts['first_name'],
                    'lname' => $nameParts['last_name'],
                    'email' => $googleUser->getEmail(),
                    'password' => Hash::make(Str::random(16)), // Random password
                    'email_verified_at' => now(),
                    'auth_provider' => 'google',
                    'photo' => $googleUser->getAvatar(),
                ]);
            } else {
                // This is a login scenario
                // Update existing user with Google info if they're using Google auth
                if ($user->auth_provider == 'google' || $user->auth_provider == null) {
                    $user->update([
                        'auth_provider' => 'google',
                        'photo' => $googleUser->getAvatar(),
                        'email_verified_at' => $user->email_verified_at ?? now(),
                    ]);
                }
            }
            
            // Generate token
            $token = $this->createTokens($user);
            
            return response()->json([
                'message' => $isNewUser ? 'Google registration successful' : 'Google login successful',
                'status' => 'success',
                'is_new_user' => $isNewUser,
                'google_user_data' => [
                    'id' => $googleUser->getId(),
                    'name' => $googleUser->getName(),
                    'email' => $googleUser->getEmail(),
                    'avatar' => $googleUser->getAvatar(),
                ],
                'data' => [
                    'user' => $user,
                    'access_token' => $token['access_token'],
                    'refresh_token' => $token['refresh_token'],
                    'token_type' => 'Bearer',
                    'expires_in' => auth('api')->factory()->getTTL() * 60
                ]
            ]);
            
        } catch (Exception $e) {
            return response()->json([
                'message' => 'Google authentication failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Logout user (Revoke the token)
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        try {
            auth('api')->logout();
            return response()->json([
                'message' => 'Successfully logged out',
                'status' => 'success'
            ]);
        } catch (Exception $e) {
            return response()->json([
                'message' => 'Logout failed',
                'error' => $e->getMessage(),
                'status' => 'error'
            ], 500);
        }
    }

    /**
     * Get the authenticated User
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function user(Request $request)
    {
        return response()->json([
            'data' => auth('api')->user(),
            'status' => 'success'
        ]);
    }
    
    /**
     * Extract first and last name from full name
     */
    private function extractNameParts($fullName)
    {
        $parts = explode(' ', $fullName, 2);
        return [
            'first_name' => $parts[0],
            'last_name' => isset($parts[1]) ? $parts[1] : ''
        ];
    }

    /**
     * Refresh a token.
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'refresh_token' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            // Set the refresh token
            JWTAuth::setToken($request->refresh_token);
            
            // Verify the token
            $payload = JWTAuth::getPayload();
            
            // Check if token is a refresh token
            if (!isset($payload['refresh']) || !$payload['refresh']) {
                return response()->json([
                    'message' => 'Invalid refresh token',
                    'status' => 'error'
                ], 401);
            }
            
            // Get user from token
            $user = User::find($payload['sub']);
            
            if (!$user) {
                return response()->json([
                    'message' => 'User not found',
                    'status' => 'error'
                ], 404);
            }
            
            // Generate new tokens
            $tokens = $this->createTokens($user);
            
            return response()->json([
                'message' => 'Token refreshed successfully',
                'status' => 'success',
                'data' => [
                    'access_token' => $tokens['access_token'],
                    'refresh_token' => $tokens['refresh_token'],
                    'token_type' => 'Bearer',
                    'expires_in' => auth('api')->factory()->getTTL() * 60
                ]
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'message' => 'Could not refresh token',
                'error' => $e->getMessage(),
                'status' => 'error'
            ], 401);
        }
    }
    
    /**
     * Create access and refresh tokens for a user
     *
     * @param User $user
     * @return array
     */
    private function createTokens(User $user)
    {
        // Login the user to get the token
        Auth::guard('api')->login($user);
        
        // Create access token
        $access_token = JWTAuth::fromUser($user);
        
        // Create refresh token with custom claims
        $refresh_token = JWTAuth::customClaims([
            'sub' => $user->id,
            'refresh' => true,
            'exp' => now()->addDays(30)->timestamp // 30 days expiry for refresh token
        ])->fromUser($user);
        
        return [
            'access_token' => $access_token,
            'refresh_token' => $refresh_token
        ];
    }

    /**
     * Check if a user needs to complete their profile
     */
    private function needsProfileCompletion($user)
    {
        // Check if user is missing role_id or other required fields
        if (empty($user->role_id) || empty($user->phone)) {
            return true;
        }
        
        return false;
    }

    /**
     * Complete user profile after social authentication
     */
    public function completeProfile(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|string|exists:users,id',
            'role_id' => 'required|in:2,3', // 2 = service_provider, 3 = customer
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $user = User::findOrFail($request->user_id);
            
            // Update user with role_id
            $user->update(['role_id' => $request->role_id]);
            
            // Add any other optional fields if provided
            $optionalFields = ['phone', 'gender', 'birthday'];
            $updateData = [];
            
            foreach ($optionalFields as $field) {
                if ($request->has($field)) {
                    $updateData[$field] = $request->$field;
                }
            }
            
            if (!empty($updateData)) {
                $user->update($updateData);
            }
            
            return response()->json([
                'message' => 'Profile completed successfully',
                'status' => 'success',
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'fname' => $user->fname,
                        'lname' => $user->lname,
                        'email' => $user->email,
                        'phone' => $user->phone,
                        'gender' => $user->gender,
                        'birthday' => $user->birthday,
                        'role' => $user->role ? $user->role->name : null,
                    ]
                ]
            ]);
            
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Failed to complete profile',
                'error' => $e->getMessage(),
                'status' => 'error'
            ], 500);
        }
    }

    /**
     * Redirect to Google OAuth
     */
    public function redirectToGoogle()
    {
        return Socialite::driver('google')
            ->stateless()
            ->redirect();
    }

    /**
     * Process Google callback
     */
    public function processGoogleCallback(Request $request)
    {
        try {
            // Get user data from Google
            $googleUser = Socialite::driver('google')->stateless()->user();
            
            // Check if user exists
            $user = User::where('email', $googleUser->getEmail())->first();
            
            $isNewUser = false;
            $needsProfileCompletion = false;
            
            if (!$user) {
                // This is a registration scenario
                $isNewUser = true;
                
                // Extract name parts
                $nameParts = $this->extractNameParts($googleUser->getName());
                
                // Create user with all available data from Google
                $user = User::create([
                    'fname' => $nameParts['first_name'],
                    'lname' => $nameParts['last_name'],
                    'email' => $googleUser->getEmail(),
                    'password' => Hash::make(Str::random(16)), // Random password
                    'email_verified_at' => now(),
                    'auth_provider' => 'google',
                    'photo' => $googleUser->getAvatar(),
                ]);
                
                // New users need to select a role
                $needsProfileCompletion = true;
            } else {
                // This is a login scenario
                // Update existing user with Google info if they're using Google auth
                if ($user->auth_provider == 'google' || $user->auth_provider == null) {
                    $user->update([
                        'auth_provider' => 'google',
                        'photo' => $googleUser->getAvatar() ?: $user->photo,
                        'email_verified_at' => $user->email_verified_at ?? now(),
                    ]);
                }
            }
            
            // Generate tokens
            $tokens = $this->generateTokens($user);
            
            // Prepare response data
            $responseData = [
                'access_token' => $tokens['access_token'],
                'refresh_token' => $tokens['refresh_token'],
                'user' => [
                    'id' => $user->id,
                    'fname' => $user->fname,
                    'lname' => $user->lname,
                    'email' => $user->email,
                    'photo' => $user->photo,
                ],
                'is_new_user' => $isNewUser,
                'needs_profile_completion' => $needsProfileCompletion
            ];
            
            // Create a URL with a custom scheme that your Flutter app can handle
            $flutterScheme = 'wejha://auth';
            $queryParams = http_build_query($responseData);
            $redirectUrl = $flutterScheme . '?' . $queryParams;
            
            return redirect()->away($redirectUrl);
            
        } catch (\Exception $e) {
            Log::error('Google auth error', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            // Create error URL for Flutter app
            $flutterScheme = 'wejha://auth-error';
            $queryParams = http_build_query([
                'error' => $e->getMessage()
            ]);
            $redirectUrl = $flutterScheme . '?' . $queryParams;
            
            return redirect()->away($redirectUrl);
        }
    }
}
