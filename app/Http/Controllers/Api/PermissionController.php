<?php

// app/Http/Controllers/Api/PermissionController.php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Spatie\Permission\Models\Permission;

class PermissionController extends Controller
{
    // public function __construct()
    // {
    //     $this->middleware('auth:sanctum');

    //     $this->middleware('permission:view permissions')->only(['index', 'show']);
    //     $this->middleware('permission:create permissions')->only(['store']);
    //     $this->middleware('permission:update permissions')->only(['update']);
    //     $this->middleware('permission:delete permissions')->only(['destroy']);
    // }

    // GET /api/permissions
    public function index()
    {
        return response()->json(Permission::all());
    }

    // POST /api/permissions
    public function store(Request $request)
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255', 'unique:permissions,name'],
        ]);

        $perm = Permission::create(['name' => $data['name'], 'guard_name' => 'web']);

        return response()->json($perm, 201);
    }

    // GET /api/permissions/{permission}
    public function show(Permission $permission)
    {
        return response()->json($permission);
    }

    // PUT /api/permissions/{permission}
    public function update(Request $request, Permission $permission)
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255', 'unique:permissions,name,' . $permission->id],
        ]);

        $permission->name = $data['name'];
        $permission->save();

        return response()->json($permission);
    }

    // DELETE /api/permissions/{permission}
    public function destroy(Permission $permission)
    {
        $permission->delete();
        return response()->json(['message' => 'Deleted']);
    }
}
