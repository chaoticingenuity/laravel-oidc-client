<?php

namespace Maicol07\OIDCClient\Controllers;

use Exception;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Maicol07\OIDCClient\Auth\OIDCGuard;

class OIDCController extends Controller
{
    use ValidatesRequests;
    use AuthorizesRequests;
    use DispatchesJobs;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
    }

    /**
     * @throws Exception
     */
    final public function login(): RedirectResponse
    {
        return redirect()->away($this->guard()->getAuthorizationUrl());
    }

    /**
     * @throws Exception
     */
    final public function callback(Request $request): null|RedirectResponse
    {
        $user = $this->guard()->generateUser();

        if (($user->exists() === false) && (config('oidc.create_new_users') === true)) {
            if (config('oidc.users_key_field') !== null) {
                $existing_user = config('auth.providers.' . config('oidc.auth-provider') . '.model')::where(config('oidc.users_key_field'), $user->{config('oidc.users_key_field')})->first();
                if ($existing_user === null) {
                } else {
                    $existing_user->fill(json_decode(json_encode($user), true));
                    $existing_user->save();
                    $user = $existing_user;
                }
            }
        }

        $user->save();

        if ($this->guard()->login($user)) {
            $request->session()->regenerate();

            if (method_exists($user, config('oidc.system-user-relationship-method'))) {
                $system_user =
                    $user->{config('oidc.system-user-relationship-method')} ??
                    (
                        (
                            (config('oidc.system-user-relationship-creation-method') !== null)
                            && method_exists($user, config('oidc.system-user-relationship-creation-method'))
                        )
                        ? $user->{config('oidc.system-user-relationship-creation-method')}()
                        : null
                    )
                ;
                if ($system_user !== null) {
                    Auth::guard()->login($system_user);
                }
            }

            return redirect()->intended(config('oidc.redirect_path_after_login'));
        }

        throw ValidationException::withMessages([
            'user' => [trans('auth.failed')],
        ]);
    }

    final public function logout(Request $request): RedirectResponse
    {
        try {
            $this->guard()->logout();
        } catch (Exception $e) {

        }

        $request->session()->invalidate();

        return redirect()->intended(config('oidc.redirect_path_after_logout'));
    }

    private function guard(): StatefulGuard|OIDCGuard
    {
        return Auth::guard(config('oidc.auth-guard'));
    }
}
