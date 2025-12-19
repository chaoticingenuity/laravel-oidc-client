<?php
namespace Maicol07\OIDCClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Maicol07\OIDCClient\Services\OIDCTokenService;
use Symfony\Component\HttpFoundation\Response;

class OIDCTokenRefresh
{

  public function __construct(
    protected OIDCTokenService $tokenService
  )
  {

  }

  public function handle(Request $request, Closure $next): Response
  {

    $result = $this->tokenService->check();

    // If expired and refresh failed, clear session and let request continue
    // (user will be redirected to login by auth middleware)
    if ($result['status'] === 'expired') {
      $this->tokenService->clear();
      $request->session()->flush();
      $request->session()->invalidate();
      $request->session()->regenerateToken();
    }

    return $next($request);
  }

}