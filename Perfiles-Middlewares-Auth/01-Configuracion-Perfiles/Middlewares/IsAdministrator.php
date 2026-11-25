<?php

namespace PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares;

use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\MatrizPerfilesPermisos;

/**
 * Middleware: IsAdministrator
 * Perfil: Administrador (usuario: administrador)
 *
 * Autoriza exclusivamente al rol 'administrador', el cual tiene acceso total
 * a todos los métodos REST y al método SOAP consultarCitas().
 */
class IsAdministrator extends BaseRoleMiddleware
{
    protected function allowedRoles(): array
    {
        return [
            MatrizPerfilesPermisos::ROLE_ADMINISTRADOR,
        ];
    }
}
