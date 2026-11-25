<?php

namespace PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares;

use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\MatrizPerfilesPermisos;

/**
 * Middleware: CanCreateAttentions
 * Perfil: Médico de Atenciones (usuario: medico)
 *
 * Permite registrar nuevas atenciones clínicas (autorizando consultarCitas() en SOAP
 * únicamente durante registrarAtencion) y consultar atenciones/recetas.
 * Bloquea el registro de recetas y la consulta directa de citas SOAP.
 */
class CanCreateAttentions extends BaseRoleMiddleware
{
    protected function allowedRoles(): array
    {
        return [
            MatrizPerfilesPermisos::ROLE_ADMINISTRADOR,
            MatrizPerfilesPermisos::ROLE_MEDICO,
        ];
    }
}
