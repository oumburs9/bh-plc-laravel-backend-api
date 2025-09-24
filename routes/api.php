<?php

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\Api\RoleController;
use App\Http\Controllers\Api\PermissionController;
use Illuminate\Support\Facades\Route;

Route::post('/login', [AuthController::class, 'login']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/me', [AuthController::class, 'me']);
    Route::post('/refresh', [AuthController::class, 'refresh']);

    /*
    |--------------------------------------------------------------------------
    | Users
    |--------------------------------------------------------------------------
    */
    Route::apiResource('users', UserController::class)
        ->middlewareFor(['index','show'], 'permission:view users')
        ->middlewareFor('store', 'permission:create users')
        ->middlewareFor('update', 'permission:update users')
        ->middlewareFor('destroy', 'permission:delete users');

    // Extra user role/permission routes
    Route::post('/users/{user}/roles', [UserController::class, 'assignRoles'])
        ->middleware('permission:update users');

    Route::delete('/users/{user}/roles/{role}', [UserController::class, 'revokeRole'])
        ->middleware('permission:update users');

    Route::post('/users/{user}/permissions', [UserController::class, 'givePermission'])
        ->middleware('permission:update users');

    Route::delete('/users/{user}/permissions/{permission}', [UserController::class, 'revokePermission'])
        ->middleware('permission:update users');

    /*
    |--------------------------------------------------------------------------
    | Roles
    |--------------------------------------------------------------------------
    */
    Route::apiResource('roles', RoleController::class)
        ->middlewareFor(['index','show'], 'permission:view roles')
        ->middlewareFor('store', 'permission:create roles')
        ->middlewareFor('update', 'permission:update roles')
        ->middlewareFor('destroy', 'permission:delete roles');

    Route::post('/roles/{role}/permissions', [RoleController::class, 'attachPermissions'])
        ->middleware('permission:update roles');

    Route::delete('/roles/{role}/permissions/{permission}', [RoleController::class, 'detachPermission'])
        ->middleware('permission:update roles');

    /*
    |--------------------------------------------------------------------------
    | Permissions
    |--------------------------------------------------------------------------
    */
    Route::apiResource('permissions', PermissionController::class)
        ->middlewareFor(['index','show'], 'permission:view permissions')
        ->middlewareFor('store', 'permission:create permissions')
        ->middlewareFor('update', 'permission:update permissions')
        ->middlewareFor('destroy', 'permission:delete permissions');
});
