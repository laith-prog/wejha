<?php

namespace Modules\User\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Modules\User\Models\Permission;

class PermissionController extends Controller
{
    /**
     * Display a listing of the permissions.
     */
    public function index()
    {
        $permissions = Permission::all();
        
        return response()->json([
            'message' => 'Permissions retrieved successfully',
            'status' => 'success',
            'data' => $permissions
        ]);
    }

    /**
     * Store a newly created permission in storage.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|unique:permissions,name',
            'display_name' => 'required|string',
            'description' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $permission = Permission::create([
            'name' => $request->name,
            'display_name' => $request->display_name,
            'description' => $request->description,
        ]);

        return response()->json([
            'message' => 'Permission created successfully',
            'status' => 'success',
            'data' => $permission
        ], 201);
    }

    /**
     * Display the specified permission.
     */
    public function show($id)
    {
        $permission = Permission::find($id);
        
        if (!$permission) {
            return response()->json([
                'message' => 'Permission not found',
                'status' => 'error'
            ], 404);
        }

        return response()->json([
            'message' => 'Permission retrieved successfully',
            'status' => 'success',
            'data' => $permission
        ]);
    }

    /**
     * Update the specified permission in storage.
     */
    public function update(Request $request, $id)
    {
        $permission = Permission::find($id);
        
        if (!$permission) {
            return response()->json([
                'message' => 'Permission not found',
                'status' => 'error'
            ], 404);
        }

        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|required|string|unique:permissions,name,' . $id,
            'display_name' => 'sometimes|required|string',
            'description' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $permission->update($request->only(['name', 'display_name', 'description']));

        return response()->json([
            'message' => 'Permission updated successfully',
            'status' => 'success',
            'data' => $permission
        ]);
    }

    /**
     * Remove the specified permission from storage.
     */
    public function destroy($id)
    {
        $permission = Permission::find($id);
        
        if (!$permission) {
            return response()->json([
                'message' => 'Permission not found',
                'status' => 'error'
            ], 404);
        }

        $permission->delete();

        return response()->json([
            'message' => 'Permission deleted successfully',
            'status' => 'success'
        ]);
    }
} 