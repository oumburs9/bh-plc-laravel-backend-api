<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Foundation\Configuration\Middleware;

class UserController extends Controller
{
    // public function __construct(Middleware $middleware)
    // {
    //     // Auth every action
    //     $this->middleware('auth:sanctum');

    //     // Guard per action using Spatie permission names from the seeder
    //     $this->middleware('permission:view users')->only(['index', 'show']);
    //     $this->middleware('permission:create users')->only(['store']);
    //     $this->middleware('permission:update users')->only([
    //         'update',
    //         'assignRoles',
    //         'revokeRole',
    //         'givePermission',
    //         'revokePermission'
    //     ]);
    //     $this->middleware('permission:delete users')->only(['destroy']);
    // }

    // GET /api/users
    public function index(Request $request)
    {
        $perPage = (int) ($request->query('per_page', 15));

        $users = User::query()
            ->when($q = $request->query('q'), function ($qq) use ($q) {
                $qq->where('name', 'like', "%{$q}%")
                    ->orWhere('email', 'like', "%{$q}%");
            })
            ->with(['roles', 'permissions'])
            ->paginate($perPage);

        return response()->json($users);
    }

    // POST /api/users
    public function store(Request $request)
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'string', 'min:8'],
            'roles' => ['sometimes', 'array'],
            'roles.*' => ['string'],
            'permissions' => ['sometimes', 'array'],
            'permissions.*' => ['string'],
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);

        if (!empty($data['roles']))
            $user->syncRoles($data['roles']);
        if (!empty($data['permissions']))
            $user->syncPermissions($data['permissions']);

        return response()->json($user->load(['roles', 'permissions']), 201);
    }

    // GET /api/users/{user}
    public function show(User $user)
    {
        return response()->json($user->load(['roles', 'permissions']));
    }

    // PUT /api/users/{user}
    public function update(Request $request, User $user)
    {
        $data = $request->validate([
            'name' => ['sometimes', 'string', 'max:255'],
            'email' => ['sometimes', 'email', 'max:255', 'unique:users,email,' . $user->id],
            'password' => ['sometimes', 'nullable', 'string', 'min:8'],
            'roles' => ['sometimes', 'array'],
            'roles.*' => ['string'],
            'permissions' => ['sometimes', 'array'],
            'permissions.*' => ['string'],
        ]);

        if (array_key_exists('name', $data))
            $user->name = $data['name'];
        if (array_key_exists('email', $data))
            $user->email = $data['email'];
        if (!empty($data['password']))
            $user->password = Hash::make($data['password']);
        $user->save();

        if (array_key_exists('roles', $data))
            $user->syncRoles($data['roles'] ?? []);
        if (array_key_exists('permissions', $data))
            $user->syncPermissions($data['permissions'] ?? []);

        return response()->json($user->load(['roles', 'permissions']));
    }

    // DELETE /api/users/{user}
    public function destroy(User $user)
    {
        $user->delete();
        return response()->json(['message' => 'Deleted']);
    }

    // POST /api/users/{user}/roles
    public function assignRoles(Request $request, User $user)
    {
        $data = $request->validate([
            'roles' => ['required', 'array', 'min:1'],
            'roles.*' => ['string']
        ]);
        $user->syncRoles($data['roles']); // replace all roles with provided list
        return response()->json($user->load('roles'));
    }

    // DELETE /api/users/{user}/roles/{role}
    public function revokeRole(User $user, string $role)
    {
        $user->removeRole($role);
        return response()->json($user->load('roles'));
    }

    // POST /api/users/{user}/permissions
    public function givePermission(Request $request, User $user)
    {
        $data = $request->validate([
            'permissions' => ['required', 'array', 'min:1'],
            'permissions.*' => ['string']
        ]);
        $user->givePermissionTo($data['permissions']);
        return response()->json($user->load('permissions'));
    }

    // DELETE /api/users/{user}/permissions/{permission}
    public function revokePermission(User $user, string $permission)
    {
        $user->revokePermissionTo($permission);
        return response()->json($user->load('permissions'));
    }
}

