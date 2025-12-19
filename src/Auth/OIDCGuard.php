<?php

/** @noinspection InterfacesAsConstructorDependenciesInspection */
namespace Maicol07\OIDCClient\Auth;

use Exception;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use JetBrains\PhpStorm\Pure;
use Maicol07\OIDCClient\Models\User;
use Maicol07\OpenIDConnect\Client;
use Maicol07\OpenIDConnect\UserInfo;

class OIDCGuard extends SessionGuard
{

    private Client $oidc;

    // Session keys for OIDC tokens
    public const SESSION_ACCESS_TOKEN  = 'oidc_access_token';
    public const SESSION_REFRESH_TOKEN = 'oidc_refresh_token';
    public const SESSION_ID_TOKEN      = 'oidc_id_token';
    public const SESSION_EXPIRES_AT    = 'oidc_expires_at';

    #[Pure]

    public function __construct($name, Client $oidc, OIDCUserProvider $provider, Session $session, Request $request = null)
    {

        parent::__construct($name, $provider, $session, $request);
        $this->oidc = $oidc;
    }

    /**
     * @throws Exception
     */
    final public function getAuthorizationUrl(): string
    {

        return $this->oidc->getAuthorizationUrl(config('oidc.authorization_endpoint_query_params'), csrf_token());
    }

    /**
     * @throws Exception
     */
    final public function getUserInfo(): UserInfo
    {

        $this->oidc->authenticate();
        return $this->oidc->getUserInfo();
    }

    /**
     * @throws Exception
     */
    final public function generateUser(?UserInfo $user_info = null): User
    {

        if ($user_info === null) {
            $user_info = $this->getUserInfo();
        }
        return $this->provider->retrieveByInfo($user_info);
    }

    #[\Override]

    final public function login(User|Authenticatable $user, $remember = false): bool
    {

        $this->updateSession($user);

        if ($remember) {
            $this->ensureRememberTokenIsSet($user);
            $this->queueRecallerCookie($user);
        }
        $this->fireLoginEvent($user, $remember);

        /** @noinspection UnusedFunctionResultInspection */
        $this->setUser($user);
        return true;
    }

    #[\Override]

    final public function logout(): void
    {

        $id_token = $this->user()?->id_token;
        if ($id_token !== null) {
            $this->oidc->signOut(id_token: $id_token, back_channel_process: true);
        }

        // Clear OIDC tokens
        $this->clearTokens();

        parent::logout();
    }

    #[\Override]

    final public function user(): Authenticatable|User|null
    {

        if ($this->loggedOut) {
            return null;
        }

        if (!is_null($this->user)) {
            return $this->user;
        }

        $user = $this->session->get($this->getName());

        if (!is_null($user) && $this->user = $user) {
            $this->fireAuthenticatedEvent($this->user);
        }

        if (is_null($this->user) && !is_null($recaller = $this->recaller())) {
            $this->user = $this->userFromRecaller($recaller);

            if ($this->user) {
                $this->updateSession($this->user);

                $this->fireLoginEvent($this->user, true);
            }
        }

        return $this->user;
    }

    /** @param User $user
     * @noinspection PhpParameterNameChangedDuringInheritanceInspection
     */
    #[\Override]

    final protected function updateSession($user): void
    {

        $this->session->put($this->getName(), $user);
        $this->session->migrate(true);
    }

    // =========================================================================
    // Token Management Methods (for OIDC session/token refresh)
    // =========================================================================

    /**
     * Store OIDC tokens in session after successful authentication
     */
    public function storeTokens(array $tokens): void
    {

        $expiresIn = (int) ($tokens['expires_in'] ?? 3600);
        $expiresAt = now()->addSeconds($expiresIn)->timestamp;

        $this->session->put(self::SESSION_ACCESS_TOKEN, $tokens['access_token']);
        $this->session->put(self::SESSION_REFRESH_TOKEN, $tokens['refresh_token'] ?? null);
        $this->session->put(self::SESSION_ID_TOKEN, $tokens['id_token'] ?? null);
        $this->session->put(self::SESSION_EXPIRES_AT, $expiresAt);

        $this->session->save();
    }

    /**
     * Get all stored tokens
     */
    public function getTokens(): array
    {

        return [
            'access_token' => $this->session->get(self::SESSION_ACCESS_TOKEN),
            'refresh_token' => $this->session->get(self::SESSION_REFRESH_TOKEN),
            'id_token' => $this->session->get(self::SESSION_ID_TOKEN),
            'expires_at' => $this->session->get(self::SESSION_EXPIRES_AT),
        ];
    }

    /**
     * Get the current access token
     */
    public function getAccessToken(): ?string
    {

        return $this->session->get(self::SESSION_ACCESS_TOKEN);
    }

    /**
     * Get the current refresh token
     */
    public function getRefreshToken(): ?string
    {

        return $this->session->get(self::SESSION_REFRESH_TOKEN);
    }

    /**
     * Get the ID token
     */
    public function getIdToken(): ?string
    {

        return $this->session->get(self::SESSION_ID_TOKEN);
    }

    /**
     * Get token expiration timestamp
     */
    public function getExpiresAt(): ?int
    {

        return $this->session->get(self::SESSION_EXPIRES_AT);
    }

    /**
     * Clear all OIDC tokens from session
     */
    public function clearTokens(): void
    {

        $this->session->forget([
            self::SESSION_ACCESS_TOKEN,
            self::SESSION_REFRESH_TOKEN,
            self::SESSION_ID_TOKEN,
            self::SESSION_EXPIRES_AT,
        ]);
    }

    /**
     * Check if tokens need refresh (within threshold of expiry)
     */
    public function needsRefresh(?int $thresholdMinutes = null): bool
    {

        $expiresAt    = $this->getExpiresAt();
        $refreshToken = $this->getRefreshToken();

        if (!$expiresAt || !$refreshToken) {
            return false;
        }

        $threshold        = $thresholdMinutes ?? config('oidc.refresh_threshold', 30);
        $thresholdSeconds = $threshold * 60;
        $timeRemaining    = $expiresAt - now()->timestamp;

        return $timeRemaining <= $thresholdSeconds;
    }

    /**
     * Refresh the access token using the OIDC client
     *
     * @return bool True if refresh succeeded, false otherwise
     */
    public function refreshAccessToken(): bool
    {

        $refreshToken = $this->getRefreshToken();

        if (!$refreshToken) {
            return false;
        }

        try {
            // Token trait's refreshToken() returns a Collection
            $response = $this->oidc->refreshToken($refreshToken);

            // Convert Collection to array for storeTokens
            $tokens = $response->toArray();
            $this->storeTokens($tokens);

            Log::debug('OIDC token refreshed successfully', [
                'expires_in' => $tokens['expires_in'] ?? 'unknown',
            ]);

            return true;
        } catch (Exception $e) {
            Log::warning('OIDC token refresh failed', [
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Validate and refresh token if needed
     * Returns: 'valid', 'refreshed', or 'expired'
     */
    public function validateAndRefresh(): string
    {

        if (!$this->getRefreshToken()) {
            return 'expired';
        }

        if (!$this->needsRefresh()) {
            return 'valid';
        }

        if ($this->refreshAccessToken()) {
            return 'refreshed';
        }

        // Refresh failed - clear tokens
        $this->clearTokens();
        return 'expired';
    }

    /**
     * Get the underlying OIDC client
     */
    public function getClient(): Client
    {

        return $this->oidc;
    }

}
