<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Carbon\Carbon;
use Laravel\Sanctum\PersonalAccessToken;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $data = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);

        $user = User::where('email', $data['email'])->first();

        if (!$user || !Hash::check($data['password'], $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 422);
        }

        // Access token (short lived)
        $accessToken = $user->createToken('access-token', ['*'], now()->addMinutes(15))->plainTextToken;

        // Refresh token (long lived, 7 days)
        $refreshToken = $user->createToken('refresh-token', ['*'], now()->addDays(7))->plainTextToken;

        // Send refresh token in secure httpOnly cookie
        return response()->json([
            'access_token' => $accessToken,
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'roles' => $user->getRoleNames(),
                'permissions' => $user->getPermissionNames(),
            ]
        ])->cookie(
                'refresh_token',
                $refreshToken,
                60 * 24 * 7,   // 7 days
                '/',
                '.byo-technology.com', // 👈 explicit domain
                true,   // Secure = true
                true,   // HttpOnly
                false,  // Raw
                'None'  // 👈 SameSite=None (required for cross-site)
            );
    }

    public function refresh(Request $request)
    {
        $refreshToken = $request->cookie('refresh_token');
        if (!$refreshToken) {
            return response()->json(['message' => 'No refresh token'], 401);
        }

        // Decode the refresh token into ID + token
        $tokenModel = PersonalAccessToken::findToken($refreshToken);
        if (!$tokenModel) {
            return response()->json(['message' => 'Invalid refresh token'], 401);
        }

        $user = $tokenModel->tokenable; // the user who owns this token
        if (!$user) {
            return response()->json(['message' => 'Invalid refresh token user'], 401);
        }

        // Issue a new access token
        $accessToken = $user->createToken('access-token', ['*'], now()->addMinutes(15))->plainTextToken;

        return response()->json([
            'access_token' => $accessToken,
        ]);
    }

    public function logout(Request $request)
    {
        // Delete all user tokens
        $request->user()->tokens()->delete();

        return response()->json(['message' => 'Logged out'])
            ->withCookie(cookie()->forget('refresh_token'));
    }
}
