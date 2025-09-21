<?php

// app/Http/Controllers/Api/RoleController.php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;

class RoleController extends Controller
{
    // public function __construct()
    // {
    //     $this->middleware('auth:sanctum');

    //     $this->middleware('permission:view roles')->only(['index','show']);
    //     $this->middleware('permission:create roles')->only(['store']);
    //     $this->middleware('permission:update roles')->only(['update','attachPermissions','detachPermission']);
    //     $this->middleware('permission:delete roles')->only(['destroy']);
    // }

    // GET /api/roles
    public function index()
    {
        $roles = Role::query()
            ->with('permissions')
            ->get();

        return response()->json($roles);
    }

    // POST /api/roles
    public function store(Request $request)
    {
        $data = $request->validate([
            'name' => ['required','string','max:255','unique:roles,name'],
            'permissions'   => ['sometimes','array'],
            'permissions.*' => ['string'],
        ]);

        $role = Role::create(['name' => $data['name'], 'guard_name' => 'web']);

        if (!empty($data['permissions'])) {
            $role->syncPermissions($data['permissions']);
        }

        return response()->json($role->load('permissions'), 201);
    }

    // GET /api/roles/{role}
    public function show(Role $role)
    {
        return response()->json($role->load('permissions'));
    }

    // PUT /api/roles/{role}
    public function update(Request $request, Role $role)
    {
        $data = $request->validate([
            'name' => ['sometimes','string','max:255','unique:roles,name,'.$role->id],
            'permissions'   => ['sometimes','array'],
            'permissions.*' => ['string'],
        ]);

        if (array_key_exists('name',$data)) $role->name = $data['name'];
        $role->save();

        if (array_key_exists('permissions',$data)) {
            $role->syncPermissions($data['permissions'] ?? []);
        }

        return response()->json($role->load('permissions'));
    }

    // DELETE /api/roles/{role}
    public function destroy(Role $role)
    {
        $role->delete();
        return response()->json(['message' => 'Deleted']);
    }

    // POST /api/roles/{role}/permissions
    public function attachPermissions(Request $request, Role $role)
    {
        $data = $request->validate([
            'permissions'   => ['required','array','min:1'],
            'permissions.*' => ['string'],
        ]);
        $role->givePermissionTo($data['permissions']);
        return response()->json($role->load('permissions'));
    }

    // DELETE /api/roles/{role}/permissions/{permission}
    public function detachPermission(Role $role, string $permission)
    {
        $role->revokePermissionTo($permission);
        return response()->json($role->load('permissions'));
    }
}
