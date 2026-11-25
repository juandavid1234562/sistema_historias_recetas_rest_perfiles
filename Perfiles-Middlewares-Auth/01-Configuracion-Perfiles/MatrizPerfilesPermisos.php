<?php

namespace PerfilesMiddlewaresAuth\ConfiguracionPerfiles;

/**
 * Matriz central de Perfiles, Usuarios, Middlewares, Métodos REST y Métodos SOAP
 * contextualizada para los dos proyectos locales:
 *  - REST (Laravel): sistema_historias_recetas_rest
 *  - SOAP (NuSOAP):  sistema_citas_soap (operación consultarCitas())
 */
final class MatrizPerfilesPermisos
{
    public const ROLE_ADMINISTRADOR = 'administrador';
    public const ROLE_FARMACIA      = 'farmacia';
    public const ROLE_PACIENTE      = 'paciente';
    public const ROLE_MEDICO        = 'medico';

    /**
     * Definición completa de los 4 perfiles y sus permisos REST/SOAP.
     */
    public static function perfiles(): array
    {
        return [
            self::ROLE_ADMINISTRADOR => [
                'perfil'     => 'Perfil Administrador',
                'usuario'    => 'administrador',
                'email'      => 'administrador@consultorio.com',
                'middleware' => 'IsAdministrator',
                'rest_permitidos' => [
                    'login',
                    'registrarAtencion',
                    'listarAtenciones',
                    'consultarAtencion',
                    'consultarRecetasAtencion',
                    'registrarReceta',
                    'consultarCitasSoap',
                    'generarTokenSoap',
                    'validarTokenSoap',
                ],
                'soap_permitidos' => [
                    'consultarCitas' => [
                        'autorizado' => true,
                        'cuando'     => ['registrarAtencion', 'consultarCitasSoap'],
                        'detalle'    => 'Autorizado al ejecutar registrarAtencion, consultarCitasSoap y operaciones de token SOAP.',
                    ],
                ],
            ],

            self::ROLE_FARMACIA => [
                'perfil'     => 'Perfil Farmacia / Recetas',
                'usuario'    => 'farmacia',
                'email'      => 'farmacia@consultorio.com',
                'middleware' => 'CanManagePrescriptions',
                'rest_permitidos' => [
                    'login',
                    'registrarReceta',
                    'consultarRecetasAtencion',
                    'consultarAtencion',
                    'listarAtenciones',
                ],
                'soap_permitidos' => [
                    'consultarCitas' => [
                        'autorizado' => false,
                        'cuando'     => [],
                        'detalle'    => 'Ninguno: bloquea el acceso a registrarAtencion y consultarCitasSoap, impidiendo cualquier consumo hacia consultarCitas().',
                    ],
                ],
            ],

            self::ROLE_PACIENTE => [
                'perfil'     => 'Perfil Paciente / Consulta',
                'usuario'    => 'paciente',
                'email'      => 'paciente@consultorio.com',
                'middleware' => 'CanCheckClinicalHistory',
                'rest_permitidos' => [
                    'login',
                    'consultarAtencion',
                    'consultarRecetasAtencion',
                    'consultarCitasSoap',
                ],
                'soap_permitidos' => [
                    'consultarCitas' => [
                        'autorizado' => true,
                        'cuando'     => ['consultarCitasSoap'],
                        'detalle'    => 'Autorizado únicamente cuando el paciente ejecuta el método consultarCitasSoap para verificar su cita.',
                    ],
                ],
            ],

            self::ROLE_MEDICO => [
                'perfil'     => 'Perfil Médico de Atenciones',
                'usuario'    => 'medico',
                'email'      => 'medico@consultorio.com',
                'middleware' => 'CanCreateAttentions',
                'rest_permitidos' => [
                    'login',
                    'registrarAtencion',
                    'listarAtenciones',
                    'consultarAtencion',
                    'consultarRecetasAtencion',
                ],
                'soap_permitidos' => [
                    'consultarCitas' => [
                        'autorizado' => true,
                        'cuando'     => ['registrarAtencion'],
                        'detalle'    => 'Autorizado únicamente cuando el médico ejecuta registrarAtencion para validar que la cita esté Programada en SOAP.',
                    ],
                ],
            ],
        ];
    }

    /**
     * Verifica si un rol tiene permiso para ejecutar un método REST dado.
     */
    public static function metodoRestPermitido(?string $role, string $metodoRest): bool
    {
        if ($role === null || $role === '') {
            return false;
        }

        $perfiles = self::perfiles();
        if (!isset($perfiles[$role])) {
            return false;
        }

        return in_array($metodoRest, $perfiles[$role]['rest_permitidos'], true);
    }

    /**
     * Verifica si un rol tiene permiso para consumir consultarCitas() en SOAP
     * desde un método REST específico.
     */
    public static function puedeConsumirSoap(?string $role, string $metodoRest, string $metodoSoap = 'consultarCitas'): bool
    {
        if (!self::metodoRestPermitido($role, $metodoRest)) {
            return false;
        }

        $perfiles = self::perfiles();
        $soapConfig = $perfiles[$role]['soap_permitidos'][$metodoSoap] ?? null;

        if (!$soapConfig || empty($soapConfig['autorizado'])) {
            return false;
        }

        return in_array($metodoRest, $soapConfig['cuando'], true);
    }

    /**
     * Mapea el método de controlador de Laravel al nombre lógico del método REST.
     */
    public static function resolverNombreMetodoRest(string $controllerAction): string
    {
        $mapa = [
            'AtencionController@store'                => 'registrarAtencion',
            'AtencionController@index'                => 'listarAtenciones',
            'AtencionController@show'                 => 'consultarAtencion',
            'AtencionController@recetas'              => 'consultarRecetasAtencion',
            'RecetaController@store'                  => 'registrarReceta',
            'SoapTokenController@consultarCitasConToken' => 'consultarCitasSoap',
            'SoapTokenController@generar'             => 'generarTokenSoap',
            'SoapTokenController@validar'             => 'validarTokenSoap',
            'AuthController@login'                    => 'login',
        ];

        return $mapa[$controllerAction] ?? $controllerAction;
    }
}
