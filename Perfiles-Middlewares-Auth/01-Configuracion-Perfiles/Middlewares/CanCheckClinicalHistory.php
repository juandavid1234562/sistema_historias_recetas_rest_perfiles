<?php

namespace PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares;

use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\MatrizPerfilesPermisos;

/**
 * Middleware: CanCheckClinicalHistory
 * Perfil: Paciente / Consulta (usuario: paciente)
 *
 * Permite consultar detalle de atenciones, recetas y verificar el estado de su cita
 * en SOAP mediante consultarCitasSoap (consumiendo consultarCitas()).
 * Bloquea cualquier registro de atenciones o recetas.
 */
class CanCheckClinicalHistory extends BaseRoleMiddleware
{
    protected function allowedRoles(): array
    {
        return [
            MatrizPerfilesPermisos::ROLE_ADMINISTRADOR,
            MatrizPerfilesPermisos::ROLE_PACIENTE,
        ];
    }
}
