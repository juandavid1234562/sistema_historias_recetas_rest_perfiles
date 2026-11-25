<?php

namespace PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares;

use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\MatrizPerfilesPermisos;

/**
 * Middleware: CanManagePrescriptions
 * Perfil: Farmacia / Recetas (usuario: farmacia)
 *
 * Permite gestionar recetas médicas (registrarReceta) y consultar atenciones/recetas.
 * Bloquea el acceso a registrarAtencion y consultarCitasSoap (ningún acceso a SOAP).
 */
class CanManagePrescriptions extends BaseRoleMiddleware
{
    protected function allowedRoles(): array
    {
        return [
            MatrizPerfilesPermisos::ROLE_ADMINISTRADOR,
            MatrizPerfilesPermisos::ROLE_FARMACIA,
        ];
    }
}
