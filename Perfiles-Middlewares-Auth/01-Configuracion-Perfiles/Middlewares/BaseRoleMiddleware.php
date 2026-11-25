<?php

namespace PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares;

use Closure;
use Illuminate\Http\Request;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\MatrizPerfilesPermisos;
use Symfony\Component\HttpFoundation\Response;

/**
 * Clase base compartida para los middlewares de verificación manual de rol.
 *
 * Cumple los requerimientos de evaluación:
 *  1. Verifica que exista usuario autenticado (token Bearer válido) -> 401 Unauthorized.
 *  2. Verifica manualmente $request->user()->role contra los roles permitidos y la matriz de métodos.
 *  3. Aborta ANTES de llegar al controlador o al servicio SOAP retornando HTTP 403 Forbidden
 *     con exactamente: { "error": "Permisos insuficientes para ejecutar este método" }.
 */
abstract class BaseRoleMiddleware
{
    /**
     * Lista de roles aceptados por este middleware concreto.
     *
     * @return string[]
     */
    abstract protected function allowedRoles(): array;

    /**
     * Maneja una petición entrante verificando manualmente rol y método permitido.
     */
    public function handle(Request $request, Closure $next, ?string $metodoRest = null): Response
    {
        $user = $request->user();

        if ($user === null) {
            return response()->json([
                'error' => 'No autenticado. Se requiere un token Bearer válido.',
            ], 401);
        }

        // Verificación manual estricta de $request->user()->role
        $role = $user->role ?? null;

        if (!is_string($role) || !in_array($role, $this->allowedRoles(), true)) {
            return $this->forbiddenResponse();
        }

        $metodo = $this->resolveMetodoRest($request, $metodoRest);
        if ($metodo !== null && !MatrizPerfilesPermisos::metodoRestPermitido($role, $metodo)) {
            return $this->forbiddenResponse();
        }

        return $next($request);
    }

    protected function resolveMetodoRest(Request $request, ?string $metodoRest): ?string
    {
        if ($metodoRest !== null && $metodoRest !== '') {
            return $metodoRest;
        }

        $route = $request->route();
        if ($route === null) {
            return null;
        }

        if (method_exists($route, 'getName') && $route->getName()) {
            return (string) $route->getName();
        }

        if (method_exists($route, 'getActionName')) {
            $action = class_basename((string) $route->getActionName());
            return MatrizPerfilesPermisos::resolverNombreMetodoRest($action);
        }

        return null;
    }

    protected function forbiddenResponse(): Response
    {
        return response()->json([
            'error' => 'Permisos insuficientes para ejecutar este método',
        ], 403);
    }
}
