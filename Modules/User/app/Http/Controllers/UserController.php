<?php

namespace Modules\User\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class UserController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        return view('user::index');
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        return view('user::create');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request) {}

    /**
     * Show the specified resource.
     */
    public function show($id)
    {
        return view('user::show');
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit($id)
    {
        return view('user::edit');
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, $id) {}

    /**
     * Remove the specified resource from storage.
     */
    public function destroy($id) {}

    /**
     * Get the authenticated user's profile information
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function getProfile(Request $request)
    {
        $user = Auth::guard('api')->user();
        
        if (!$user) {
            return response()->json([
                'message' => 'User not found',
                'status' => 'error'
            ], 404);
        }

        return response()->json([
            'message' => 'User profile retrieved successfully',
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
                    'photo' => $user->photo,
                    'type' => $user->type,
                    'email_verified_at' => $user->email_verified_at,
                    'auth_provider' => $user->auth_provider,
                    'created_at' => $user->created_at,
                    'updated_at' => $user->updated_at,
                ]
            ]
        ]);
    }
}
