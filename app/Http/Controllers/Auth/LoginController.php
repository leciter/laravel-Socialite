<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Carbon\Carbon;
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
     * Redirect the user to the GitHub authentication page.
     *
     * @return \Illuminate\Http\Response
     */
    public function redirectToProvider()
    {
        return Socialite::driver('github')->redirect();
    }

    /**
     * Obtain the user information from GitHub.
     *
     * @return \Illuminate\Http\Response
     */
    public function handleProviderCallback()
    {
        $githubUser = Socialite::driver('github')->user();

        $user = User::where('provider_id', $githubUser->getId())->first();

        if(!$user)
        {
            $user = User::create([
                'name'          => $githubUser->getName() ?? $githubUser->getNickname(),
                'nickname'      => $githubUser->getNickname() ?? null,
                'email'         => $githubUser->getEmail(),
                'password'      => $githubUser->token ?? bcrypt(Carbon::now()),
                'provider'      => 'github',
                'provider_id'   => $githubUser->getId(),          
                'avatar'        => $githubUser->getAvatar() ?? null,
                'expires_in'    => $githubUser->expiresIn ?? null,
                'token'         => $githubUser->token ?? null,
                'token_secret'  => $githubUser->tokenSecret ?? null,
            ]);
        }
        
        Auth::login($user, true);
        
        return redirect($this->redirectTo);
    }
}
