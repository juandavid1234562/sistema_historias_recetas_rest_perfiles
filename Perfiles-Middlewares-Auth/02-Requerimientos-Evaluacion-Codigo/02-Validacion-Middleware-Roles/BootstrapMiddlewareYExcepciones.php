<?php

use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\AuthorizeEndpointByProfile;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\CanCheckClinicalHistory;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\CanCreateAttentions;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\CanManagePrescriptions;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\IsAdministrator;
use PerfilesMiddlewaresAuth\RequerimientosEvaluacion\ValidacionTokenBearer\AuthenticateBearerMiddleware;

/**
 * Especificación de configuración para bootstrap/app.php en Laravel 13.
 * Registra los alias de middlewares personalizados y asegura respuesta HTTP 401 JSON
 * cuando no se envía un token Bearer válido en rutas protegidas.
 */
return Application::configure(basePath: dirname(__DIR__, 3))
    ->withRouting(
        api: __DIR__ . '/routes_api_protegidas.php',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'bearer.auth'              => AuthenticateBearerMiddleware::class,
            'is.administrator'         => IsAdministrator::class,
            'can.manage.prescriptions' => CanManagePrescriptions::class,
            'can.check.history'        => CanCheckClinicalHistory::class,
            'can.create.attentions'    => CanCreateAttentions::class,
            'profile.authorize'        => AuthorizeEndpointByProfile::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );

        // Garantiza HTTP 401 Unauthorized en formato JSON para cualquier fallo de token Bearer
        $exceptions->render(function (AuthenticationException $e, Request $request) {
            return response()->json([
                'error'   => 'No autorizado',
                'mensaje' => 'Token Bearer ausente, inválido o expirado.',
            ], 401);
        });
    });
