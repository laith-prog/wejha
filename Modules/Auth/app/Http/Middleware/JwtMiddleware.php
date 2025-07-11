<?php

namespace Modules\Auth\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class JwtMiddleware extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            // Check if the token is a refresh token
            $payload = JWTAuth::parseToken()->getPayload();
            if (isset($payload['refresh']) && $payload['refresh']) {
                return response()->json([
                    'message' => 'Cannot use refresh token for authentication',
                    'status' => 'error'
                ], 401);
            }
            
            $user = JWTAuth::parseToken()->authenticate();
            if (!$user) {
                return response()->json([
                    'message' => 'User not found',
                    'status' => 'error'
                ], 404);
            }
        } catch (Exception $e) {
            if ($e instanceof TokenInvalidException) {
                return response()->json([
                    'message' => 'Token is invalid',
                    'status' => 'error'
                ], 401);
            } else if ($e instanceof TokenExpiredException) {
                return response()->json([
                    'message' => 'Token has expired',
                    'status' => 'error'
                ], 401);
            } else {
                return response()->json([
                    'message' => 'Authorization token not found',
                    'status' => 'error'
                ], 401);
            }
        }
        
        return $next($request);
    }
} 