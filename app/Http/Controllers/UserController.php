<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use App\Models\User;
use Hash;

class UserController extends Controller
{
    public function register(Request $request)
    {
        $data = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password'])
        ]);

        //create token
        $token = $user->createToken('myAppToken')->plainTextToken;

        //response
        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, '201');
    }

    public function login(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        //check email
        $user = User::where('email', $data['email'])->first();

        //check password
        if (!$user || !Hash::check($data['password'], $user->password)) {
            return response([
                'messaage' => 'Invalid Details'
            ], 401);
        }

        //create token
        $token = $user->createToken('myAppToken')->plainTextToken;

        //response
        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, '201');
    }


    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();

        return [
            'messaage' => 'Logged Out'
        ];
    }
}
