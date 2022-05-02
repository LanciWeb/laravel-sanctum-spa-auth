<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request): Response
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:5|confirmed' //password_confirmation
        ]);

        $data = $request->only('email', 'name');
        $data['password'] = bcrypt($request->password);

        $user = User::create($data);

        return response($user, 201);
    }

    public function login(Request $request): Response
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:5'
        ]);

        $credentials = $request->all();

        if (Auth::attempt($credentials)) {
            return response(Auth::user(), 200);
        }

        abort('401', 'login-failed');
    }

    public function logout(): Response
    {
        Auth::logout();
        return response(null, 204);
    }
}
