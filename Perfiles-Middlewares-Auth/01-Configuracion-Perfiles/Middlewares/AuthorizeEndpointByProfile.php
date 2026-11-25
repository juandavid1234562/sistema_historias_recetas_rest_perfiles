<?php

namespace PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares;

use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\MatrizPerfilesPermisos;

/**
 * Middleware auxiliar para rutas de lectura compartidas entre múltiples perfiles
 * (por ejemplo: listarAtenciones, consultarAtencion, consultarRecetasAtencion).
 *
 * Evalúa manualmente $request->user()->role contra la matriz de permisos
 * del método REST solicitado antes de llegar al controlador.
 */
class AuthorizeEndpointByProfile extends BaseRoleMiddleware
{
    protected function allowedRoles(): array
    {
        return [
            MatrizPerfilesPermisos::ROLE_ADMINISTRADOR,
            MatrizPerfilesPermisos::ROLE_FARMACIA,
            MatrizPerfilesPermisos::ROLE_PACIENTE,
            MatrizPerfilesPermisos::ROLE_MEDICO,
        ];
    }
}
