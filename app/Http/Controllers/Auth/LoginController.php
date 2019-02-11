<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Socialite;
use Auth;
use App\User;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    /**
     * Redirect the user to the Socialite provider authentication page.
     *
     * @return \Illuminate\Http\Response
     */
    public function redirectToProvider($provider)
    {
        return Socialite::driver($provider)->redirect();
    }

    /**
     * Obtain the user information from Socialite provider.
     *
     * @return \Illuminate\Http\Response
     */
    public function handleProviderCallback($provider)
    {        
        if($provider == 'google')
        {
            $socialiteUser = Socialite::driver($provider)->stateless()->user();
        }
        else
        {
            $socialiteUser = Socialite::driver($provider)->user();
        }

        $user = User::where('email', $socialiteUser->getEmail())->first();
        
        if(!$user)
        {
            $user = User::createSocialiteUser($socialiteUser, $provider);
        }
        else 
        {
            $user = User::updateSocialiteUser($socialiteUser, $user);
        }
        
        Auth::login($user, true);

        return redirect($this->redirectTo);
    }
}
