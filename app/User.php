<?php

namespace App;

use Illuminate\Notifications\Notifiable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Carbon\Carbon;

class User extends Authenticatable
{
    use Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name', 'nickname', 'email', 'password', 'provider', 'provider_id',
        'token', 'token_secret', 'expires_in', 'email_verified_at', 'locale', 'avatar', 
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token', 'token', 'token_secret',
    ];
    
    /**
     * Create user by socialite provider credentials.
     *
     * @return User
     */
    public static function createSocialiteUser($socialiteUser, $provider)
    {
        $verified_email = $socialiteUser->user['verified_email'] ?? false;
        $user = User::create([
                'name'              => $socialiteUser->getName() ?? $socialiteUser->getNickname(),
                'nickname'          => $socialiteUser->getNickname() ?? null,
                'email'             => $provider . '#' . $socialiteUser->getEmail(),
                'email_verified_at' => $verified_email ? Carbon::now() : null,
                'password'          => bcrypt(Carbon::now()),
                'provider_id'       => $socialiteUser->getId(),
                'avatar'            => $socialiteUser->getAvatar() ?? null,
                'expires_in'        => $socialiteUser->expiresIn ?? null,
                'token'             => $socialiteUser->token ?? null,
                'token_secret'      => $socialiteUser->tokenSecret ?? null,
                'locale'            => $socialiteUser->user['locale'] ?? $socialiteUser->user['location'] ?? null,
        ]);

        return $user;
    }

    /**
     * Update user by socialite provider credentials.
     *
     */
    public static function updateSocialiteUser($socialiteUser, $user)
    {
        $user->update([
                'name'              => $socialiteUser->getName() ?? $socialiteUser->getNickname(),
                'nickname'          => $socialiteUser->getNickname() ?? null,
                'avatar'            => $socialiteUser->getAvatar() ?? null,
                'expires_in'        => $socialiteUser->expiresIn ?? null,
                'token'             => $socialiteUser->token ?? null,
                'token_secret'      => $socialiteUser->tokenSecret ?? null,
        ]);
        
        return User::where('email', $socialiteUser->getEmail())->first();
    }
}
