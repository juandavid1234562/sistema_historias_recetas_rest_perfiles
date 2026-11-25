<?php

use App\Http\Controllers\Api\AtencionController;
use App\Http\Controllers\Api\RecetaController;
use App\Http\Controllers\Api\SoapTokenController;
use Illuminate\Support\Facades\Route;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\AuthorizeEndpointByProfile;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\CanCheckClinicalHistory;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\CanCreateAttentions;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\CanManagePrescriptions;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\IsAdministrator;
use PerfilesMiddlewaresAuth\RequerimientosEvaluacion\ValidacionTokenBearer\AuthController;
use PerfilesMiddlewaresAuth\RequerimientosEvaluacion\ValidacionTokenBearer\AuthenticateBearerMiddleware;

/*
|--------------------------------------------------------------------------
| Especificación de Rutas Protegidas (Laravel API REST + Puente SOAP)
|--------------------------------------------------------------------------
|
| 1. Todas las rutas (excepto /api/login) exigen token Bearer válido
|    (auth:sanctum / AuthenticateBearerMiddleware -> HTTP 401 si falta o es inválido).
| 2. Cada ruta pasa por su middleware personalizado que verifica manualmente
|    $request->user()->role ANTES de llegar al controlador o al servicio SOAP
|    (HTTP 403 { "error": "Permisos insuficientes para ejecutar este método" }).
|
*/

// =========================================================================
// Ruta Pública: Login (emisión de Token Bearer con rol)
// =========================================================================
Route::post('/login', [AuthController::class, 'login'])->name('login');

// =========================================================================
// Rutas Protegidas con Token Bearer + Validación Manual de Rol por Middleware
// =========================================================================
Route::middleware(['auth:sanctum', AuthenticateBearerMiddleware::class])->group(function () {

    Route::get('/me', [AuthController::class, 'me'])->name('me');
    Route::post('/logout', [AuthController::class, 'logout'])->name('logout');

    // ---------------------------------------------------------------------
    // MÓDULO: Atenciones Clínicas (Historias)
    // ---------------------------------------------------------------------

    // Registrar atención clínica (requiere consultarCitas() en SOAP).
    // Permitido: administrador (IsAdministrator), medico (CanCreateAttentions).
    // Bloqueado: farmacia, paciente -> HTTP 403 antes de tocar el controlador o SOAP.
    Route::post('/atenciones', [AtencionController::class, 'store'])
        ->middleware(CanCreateAttentions::class . ':registrarAtencion')
        ->name('registrarAtencion');

    // Listar todas las atenciones clínicas (no consume SOAP).
    // Permitido: administrador, farmacia, medico. Bloqueado: paciente -> HTTP 403.
    Route::get('/atenciones', [AtencionController::class, 'index'])
        ->middleware(AuthorizeEndpointByProfile::class . ':listarAtenciones')
        ->name('listarAtenciones');

    // Consultar detalle de una atención clínica (no consume SOAP).
    // Permitido: administrador, farmacia, paciente, medico.
    Route::get('/atenciones/{id}', [AtencionController::class, 'show'])
        ->whereNumber('id')
        ->middleware(AuthorizeEndpointByProfile::class . ':consultarAtencion')
        ->name('consultarAtencion');

    // Consultar recetas de una atención clínica (no consume SOAP).
    // Permitido: administrador, farmacia, paciente, medico.
    Route::get('/atenciones/{id}/recetas', [AtencionController::class, 'recetas'])
        ->whereNumber('id')
        ->middleware(AuthorizeEndpointByProfile::class . ':consultarRecetasAtencion')
        ->name('consultarRecetasAtencion');

    // ---------------------------------------------------------------------
    // MÓDULO: Recetas Médicas
    // ---------------------------------------------------------------------

    // Crear y asociar una receta médica (no consume SOAP).
    // Permitido: administrador, farmacia (CanManagePrescriptions).
    // Bloqueado: paciente, medico -> HTTP 403.
    Route::post('/recetas', [RecetaController::class, 'store'])
        ->middleware(CanManagePrescriptions::class . ':registrarReceta')
        ->name('registrarReceta');

    // ---------------------------------------------------------------------
    // MÓDULO: Integración REST -> SOAP (sistema_citas_soap)
    // ---------------------------------------------------------------------

    // Consultar citas en el servidor SOAP (consume consultarCitas()).
    // Permitido: administrador, paciente (CanCheckClinicalHistory).
    // Bloqueado: farmacia (sin acceso SOAP), medico (solo puede usar SOAP al registrarAtencion) -> HTTP 403.
    Route::post('/soap/citas/consultar', [SoapTokenController::class, 'consultarCitasConToken'])
        ->middleware(CanCheckClinicalHistory::class . ':consultarCitasSoap')
        ->name('consultarCitasSoap');

    // Administración de tokens criptográficos SOAP (exclusivo Administrador).
    // Permitido: únicamente administrador (IsAdministrator).
    Route::post('/soap/token/generar', [SoapTokenController::class, 'generar'])
        ->middleware(IsAdministrator::class . ':generarTokenSoap')
        ->name('generarTokenSoap');

    Route::post('/soap/token/validar', [SoapTokenController::class, 'validar'])
        ->middleware(IsAdministrator::class . ':validarTokenSoap')
        ->name('validarTokenSoap');
});
