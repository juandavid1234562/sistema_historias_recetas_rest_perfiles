<?php

namespace PerfilesMiddlewaresAuth\RequerimientosEvaluacion\ValidacionTokenBearer;

use Closure;
use Illuminate\Http\Request;
use Laravel\Sanctum\PersonalAccessToken;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware de Validación de Token Bearer.
 *
 * Requerimiento 2 - Validación de Token:
 * "Todas las rutas (excepto login) deben exigir el token Bearer de autenticación.
 * Si no se envía un token válido, el sistema debe retornar el código HTTP 401 Unauthorized."
 *
 * Puede usarse como complemento explícito a `auth:sanctum` o para validar
 * manualmente la cabecera `Authorization: Bearer <token>` y garantizar siempre HTTP 401 JSON.
 */
class AuthenticateBearerMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $bearerToken = $request->bearerToken();

        if (!is_string($bearerToken) || trim($bearerToken) === '') {
            return $this->unauthorizedResponse('Token Bearer requerido en la cabecera Authorization.');
        }

        // Si auth:sanctum ya resolvió al usuario autenticado, continuamos
        if ($request->user() !== null) {
            return $next($request);
        }

        // Resolución manual contra Sanctum PersonalAccessToken
        $accessToken = PersonalAccessToken::findToken(trim($bearerToken));
        if (!$accessToken || !$accessToken->tokenable) {
            return $this->unauthorizedResponse('Token Bearer inválido o expirado.');
        }

        if ($accessToken->expires_at !== null && $accessToken->expires_at->isPast()) {
            return $this->unauthorizedResponse('El token Bearer ha expirado.');
        }

        // Inyectar el usuario resuelto en la petición para que $request->user()->role esté disponible
        $request->setUserResolver(fn () => $accessToken->tokenable);

        return $next($request);
    }

    private function unauthorizedResponse(string $mensaje): Response
    {
        return response()->json([
            'error'   => 'No autorizado',
            'mensaje' => $mensaje,
        ], 401);
    }
}
