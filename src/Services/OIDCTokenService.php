<?php
namespace Maicol07\OIDCClient\Services;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Maicol07\OIDCClient\Auth\OIDCGuard;

class OIDCTokenService
{

  public function check(): array
  {

    // Check if user is logged in via web guard
    if (!Auth::guard('web')->check()) {
      return [
        'status' => 'unauthenticated',
        'oidc' => false,
      ];
    }

    $expiresAt    = session()->get('oidc_expires_at');
    $refreshToken = session()->get('oidc_refresh_token');

    if (!$expiresAt || !$refreshToken) {
      return [
        'status' => 'authenticated',
        'oidc' => false,
      ];
    }

    $now              = now()->timestamp;
    $timeRemaining    = $expiresAt - $now;
    $refreshThreshold = config('oidc.refresh_threshold', 4) * 60;

    if ($timeRemaining <= $refreshThreshold) {
      return $this->refresh($refreshToken);
    }

    return [
      'status' => 'valid',
      'oidc' => true,
      'expires_in' => $timeRemaining,
    ];
  }

  public function refresh(string $refreshToken): array
  {

    try {
      $guardName = config('oidc.auth-guard', 'web');
      $guard     = Auth::guard($guardName);

      if (!$guard instanceof OIDCGuard) {
        return ['status' => 'error', 'oidc' => true, 'error' => 'Invalid guard'];
      }

      $client   = $guard->getClient();
      $response = $client->refreshToken($refreshToken);
      $tokens   = $response->toArray();

      if (isset($tokens['access_token'])) {
        $expiresIn = (int) ($tokens['expires_in'] ?? 3600);

        session()->put('oidc_access_token', $tokens['access_token']);
        session()->put('oidc_refresh_token', $tokens['refresh_token'] ?? $refreshToken);
        session()->put('oidc_id_token', $tokens['id_token'] ?? session()->get('oidc_id_token'));
        session()->put('oidc_expires_at', now()->addSeconds($expiresIn)->timestamp);
        session()->save();

        Log::info('OIDC token refreshed', ['expires_in' => $expiresIn]);

        return ['status' => 'refreshed', 'oidc' => true, 'expires_in' => $expiresIn];
      }

      return ['status' => 'expired', 'oidc' => true, 'action' => 'login'];

    } catch (\Exception $e) {
      Log::error('OIDC token refresh failed', ['error' => $e->getMessage()]);
      return ['status' => 'expired', 'oidc' => true, 'action' => 'login', 'error' => $e->getMessage()];
    }
  }

  public function clear(): void
  {

    session()->forget([
      'oidc_access_token',
      'oidc_refresh_token',
      'oidc_id_token',
      'oidc_expires_at',
    ]);
  }

}