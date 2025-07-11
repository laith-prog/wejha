<?php

namespace Modules\User\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Modules\User\Models\Role;
use Modules\User\Models\Permission;

class RoleController extends Controller
{
    /**
     * Display a listing of the roles.
     */
    public function index()
    {
        $roles = Role::with('permissions')->get();
        
        return response()->json([
            'message' => 'Roles retrieved successfully',
            'status' => 'success',
            'data' => $roles
        ]);
    }

    /**
     * Store a newly created role in storage.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|unique:roles,name',
            'display_name' => 'required|string',
            'description' => 'nullable|string',
            'permissions' => 'nullable|array',
            'permissions.*' => 'exists:permissions,name',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $role = Role::create([
            'name' => $request->name,
            'display_name' => $request->display_name,
            'description' => $request->description,
        ]);

        if ($request->has('permissions')) {
            $role->givePermissionTo($request->permissions);
        }

        return response()->json([
            'message' => 'Role created successfully',
            'status' => 'success',
            'data' => $role->load('permissions')
        ], 201);
    }

    /**
     * Display the specified role.
     */
    public function show($id)
    {
        $role = Role::with('permissions')->find($id);
        
        if (!$role) {
            return response()->json([
                'message' => 'Role not found',
                'status' => 'error'
            ], 404);
        }

        return response()->json([
            'message' => 'Role retrieved successfully',
            'status' => 'success',
            'data' => $role
        ]);
    }

    /**
     * Update the specified role in storage.
     */
    public function update(Request $request, $id)
    {
        $role = Role::find($id);
        
        if (!$role) {
            return response()->json([
                'message' => 'Role not found',
                'status' => 'error'
            ], 404);
        }

        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|required|string|unique:roles,name,' . $id,
            'display_name' => 'sometimes|required|string',
            'description' => 'nullable|string',
            'permissions' => 'nullable|array',
            'permissions.*' => 'exists:permissions,name',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $role->update($request->only(['name', 'display_name', 'description']));

        if ($request->has('permissions')) {
            // Sync permissions
            $permissionIds = Permission::whereIn('name', $request->permissions)->pluck('id');
            $role->permissions()->sync($permissionIds);
        }

        return response()->json([
            'message' => 'Role updated successfully',
            'status' => 'success',
            'data' => $role->load('permissions')
        ]);
    }

    /**
     * Remove the specified role from storage.
     */
    public function destroy($id)
    {
        $role = Role::find($id);
        
        if (!$role) {
            return response()->json([
                'message' => 'Role not found',
                'status' => 'error'
            ], 404);
        }

        // Don't allow deletion of core roles
        if (in_array($role->name, ['admin', 'service_provider', 'customer'])) {
            return response()->json([
                'message' => 'Cannot delete core system roles',
                'status' => 'error'
            ], 403);
        }

        $role->delete();

        return response()->json([
            'message' => 'Role deleted successfully',
            'status' => 'success'
        ]);
    }
} 