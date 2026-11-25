<?php

namespace PerfilesMiddlewaresAuth\RequerimientosEvaluacion\ValidacionMiddlewareRoles;

use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\MatrizPerfilesPermisos;
use TokenttsConexionSoap\ClienteSoapToken;
use TokenttsConexionSoap\GeneradorTokenSecreto;

require_once __DIR__ . '/../../../Tokentts-conexion-soap/GeneradorTokenSecreto.php';
require_once __DIR__ . '/../../../Tokentts-conexion-soap/ClienteSoapToken.php';

/**
 * Puente de Autorización REST -> SOAP (sistema_historias_recetas_rest -> sistema_citas_soap).
 *
 * Complementa a los middlewares de ruta asegurando una segunda línea de defensa
 * antes de invocar la operación SOAP `consultarCitas()` en `sistema_citas_soap/legacy_soap/soap/server.php`:
 *  - `administrador`: autorizado en `registrarAtencion` y `consultarCitasSoap`.
 *  - `farmacia`:      NUNCA autorizado para consumir `consultarCitas()`.
 *  - `paciente`:      autorizado únicamente desde `consultarCitasSoap`.
 *  - `medico`:        autorizado únicamente desde `registrarAtencion`.
 *
 * Cuando está autorizado, emite el token HMAC-SHA256 incluyendo el rol en el payload
 * para trazabilidad en el servicio SOAP (`ValidadorTokenSecreto`).
 */
class SoapAutorizacionBridge
{
    private GeneradorTokenSecreto $generador;
    private ClienteSoapToken $clienteSoap;

    public function __construct(?GeneradorTokenSecreto $generador = null, ?ClienteSoapToken $clienteSoap = null)
    {
        $this->generador   = $generador ?? new GeneradorTokenSecreto();
        $this->clienteSoap = $clienteSoap ?? new ClienteSoapToken();
    }

    /**
     * Ejecuta `consultarCitas()` en SOAP solo si el rol del usuario está autorizado
     * para hacerlo dentro del método REST especificado.
     *
     * @return array{status:int, autorizado:bool, payload:array}
     */
    public function consultarCitasAutorizado(string $usuarioEmail, ?string $role, string $metodoRestOrigen, int $profesionalId = 0, string $fecha = ''): array
    {
        if (!MatrizPerfilesPermisos::puedeConsumirSoap($role, $metodoRestOrigen, 'consultarCitas')) {
            return [
                'status'     => 403,
                'autorizado' => false,
                'payload'    => [
                    'error' => 'Permisos insuficientes para ejecutar este método',
                ],
            ];
        }

        // Genera el token HMAC compartiendo la clave secreta con sistema_citas_soap
        $tokenSoap = $this->generador->generar($usuarioEmail, 30, [
            'role'          => $role,
            'metodo_rest'   => $metodoRestOrigen,
            'metodo_soap'   => 'consultarCitas',
        ]);

        $respuestaSoap = $this->clienteSoap->consultarCitasConToken($tokenSoap, $profesionalId, $fecha);

        return [
            'status'     => 200,
            'autorizado' => true,
            'payload'    => [
                'mensaje'       => 'Consumo SOAP consultarCitas() autorizado para el perfil',
                'role'          => $role,
                'metodo_rest'   => $metodoRestOrigen,
                'token_soap'    => $tokenSoap,
                'respuesta_soap'=> $respuestaSoap,
            ],
        ];
    }
}
