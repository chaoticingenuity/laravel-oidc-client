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

        /** @var OIDCGuard $guard */
        $guard = $this->guard();

        $user = $guard->generateUser();

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

        // Get tokens from the OIDC client and store them
        $this->storeTokensFromClient($guard);

        if ($guard->login($user)) {
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

    /**
     * Extract and store tokens from the OIDC client after authentication
     */
    protected function storeTokensFromClient(OIDCGuard $guard): void
    {

        $client = $guard->getClient();

        // The Token trait stores these after authenticate() is called
        // Access them via the client's properties
        $tokens = [
            'access_token' => $client->getAccessToken() ?? null,
            'refresh_token' => $client->getRefreshToken() ?? null,
            'id_token' => $client->getIdToken() ?? null,
            'expires_in' => $this->getExpiresInFromClient($client),
        ];

        // Only store if we have an access token
        if (!empty($tokens['access_token'])) {
            $guard->storeTokens($tokens);
        }
    }

    /**
     * Get token expiration time from client
     */
    protected function getExpiresInFromClient($client): int
    {

        // Option 1: If your client has a direct method
        if (method_exists($client, 'getAccessTokenExpiresIn')) {
            return $client->getAccessTokenExpiresIn();
        }

        // Option 2: If your client exposes expires_in from the token response
        if (method_exists($client, 'getTokenResponse')) {
            $response = $client->getTokenResponse();
            if (isset($response['expires_in'])) {
                return (int) $response['expires_in'];
            }
        }

        // Option 3: Parse from ID token exp claim
        $idToken = $client->getIdToken() ?? null;
        if ($idToken) {
            $expiresIn = $this->parseExpiresInFromJwt($idToken);
            if ($expiresIn !== null) {
                return $expiresIn;
            }
        }

        // Default to 1 hour
        return 3600;
    }

    /**
     * Parse expires_in from JWT token
     */
    protected function parseExpiresInFromJwt(string $jwt): ?int
    {

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }

        try {
            $payload = json_decode(
                base64_decode(strtr($parts[1], '-_', '+/')),
                true
            );

            if (isset($payload['exp'])) {
                $expiresIn = $payload['exp'] - time();
                return max(0, $expiresIn);
            }
        } catch (\Exception $e) {
            // Ignore parse errors
        }

        return null;
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
