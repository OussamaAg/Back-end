<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Facades\JWTFactory;


//import auth facades
use Illuminate\Support\Facades\Auth;
class AuthController extends Controller
{
    /**
     * Store a new user.
     *
     * @param  Request  $request
     * @return Response
     */
    public function register(Request $request)
    {
        //validate incoming request 
        $this->validate($request, [
            'email' => 'required|email',
            'password' => 'required',
        ]);
        
        try {

            $user = new User;
            $user->email = $request->input('email');
            $plainPassword = $request->input('password');
            $user->password = app('hash')->make($plainPassword);

            $user->save();


            //return successful response
            return response()->json(['user' => $user, 'message' => 'CREATED'], 201);

        } catch (\Exception $e) {
            dd($e);
            //return error message
            return response()->json(['message' => $e], 409);
        }

    }
    /**
     * Get a JWT via given credentials.
     *
     * @param  Request  $request
     * @return Response
     */
    public function login(Request $request)
    {
          //validate incoming request 
         
        $this->validate($request, [
            'email' => 'required|string',
            'password' => 'required|string',
        ]);
       
        $credentials = $request->only(['email', 'password']);

        if (! $token = Auth::attempt($credentials,true)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }


}
