<?php
/**
 * Script ejecutable de verificación de Perfiles, Tokens Bearer y Middlewares.
 *
 * Verifica sin modificar archivos existentes del proyecto:
 *  1. Acceso público a `login` y emisión de token Bearer por perfil.
 *  2. Rechazo HTTP 401 Unauthorized cuando falta el token Bearer o es inválido.
 *  3. Verificación manual de `$request->user()->role` en los 4 middlewares:
 *     - IsAdministrator         (usuario: administrador)
 *     - CanManagePrescriptions  (usuario: farmacia)
 *     - CanCheckClinicalHistory (usuario: paciente)
 *     - CanCreateAttentions     (usuario: medico)
 *     + AuthorizeEndpointByProfile (rutas de lectura compartidas)
 *  4. Aborto ANTES de llegar al controlador o al servicio SOAP retornando HTTP 403
 *     con exactamente: { "error": "Permisos insuficientes para ejecutar este método" }.
 *  5. Autorización/bloqueo del método SOAP `consultarCitas()` y validación del token
 *     HMAC en `sistema_citas_soap/Tokenst-conexion-REST/ValidadorTokenSecreto.php`.
 *
 * Uso:
 *   php Perfiles-Middlewares-Auth/03-Pruebas-Verificacion/probar_perfiles_middlewares.php
 */

// -----------------------------------------------------------------------------
// 1. Bootstrap mínimo para ejecutar las clases Laravel con o sin vendor/
// -----------------------------------------------------------------------------
$autoloadPath = __DIR__ . '/../../vendor/autoload.php';
if (file_exists($autoloadPath)) {
    require_once $autoloadPath;
}

if (!class_exists('Symfony\\Component\\HttpFoundation\\Response')) {
    eval('
        namespace Symfony\Component\HttpFoundation;
        class Response {
            public function __construct(
                protected string $content = "",
                protected int $status = 200,
                protected array $headers = []
            ) {}
            public function getStatusCode(): int { return $this->status; }
            public function getContent(): string { return $this->content; }
        }
    ');
}

if (!class_exists('Illuminate\\Http\\JsonResponse')) {
    eval('
        namespace Illuminate\Http;
        class JsonResponse extends \Symfony\Component\HttpFoundation\Response {
            private array $data;
            public function __construct(mixed $data = [], int $status = 200, array $headers = []) {
                $this->data = is_array($data) ? $data : (array) $data;
                parent::__construct(json_encode($this->data, JSON_UNESCAPED_UNICODE), $status, $headers);
            }
            public function getData(bool $assoc = false): mixed {
                return $assoc ? $this->data : (object) $this->data;
            }
        }
    ');
}

if (!class_exists('Illuminate\\Http\\Request')) {
    eval('
        namespace Illuminate\Http;
        class Request {
            private ?string $bearer = null;
            private mixed $userResolver = null;
            private ?object $routeObj = null;
            public function __construct(private string $uri = "/", private string $method = "GET") {}
            public function setBearerToken(?string $token): self { $this->bearer = $token; return $this; }
            public function bearerToken(): ?string { return $this->bearer; }
            public function setUserResolver(callable $resolver): self { $this->userResolver = $resolver; return $this; }
            public function user(): ?object { return $this->userResolver ? ($this->userResolver)() : null; }
            public function setRoute(?object $route): self { $this->routeObj = $route; return $this; }
            public function route(): ?object { return $this->routeObj; }
        }
    ');
}

if (!class_exists('Laravel\\Sanctum\\PersonalAccessToken')) {
    eval('
        namespace Laravel\Sanctum;
        class PersonalAccessToken {
            public static array $store = [];
            public ?object $tokenable = null;
            public ?object $expires_at = null;
            public static function findToken(string $token): ?self {
                return self::$store[$token] ?? null;
            }
        }
    ');
}

if (!function_exists('response')) {
    function response(): object
    {
        return new class {
            public function json(mixed $data = [], int $status = 200, array $headers = []): \Illuminate\Http\JsonResponse
            {
                return new \Illuminate\Http\JsonResponse($data, $status, $headers);
            }
        };
    }
}

if (!function_exists('class_basename')) {
    function class_basename(string|object $class): string
    {
        $class = is_object($class) ? get_class($class) : $class;
        return basename(str_replace('\\', '/', $class));
    }
}

// -----------------------------------------------------------------------------
// 2. Carga de clases reales del módulo Perfiles-Middlewares-Auth
// -----------------------------------------------------------------------------
$baseDir = __DIR__ . '/..';
require_once $baseDir . '/01-Configuracion-Perfiles/MatrizPerfilesPermisos.php';
require_once $baseDir . '/01-Configuracion-Perfiles/Middlewares/BaseRoleMiddleware.php';
require_once $baseDir . '/01-Configuracion-Perfiles/Middlewares/IsAdministrator.php';
require_once $baseDir . '/01-Configuracion-Perfiles/Middlewares/CanManagePrescriptions.php';
require_once $baseDir . '/01-Configuracion-Perfiles/Middlewares/CanCheckClinicalHistory.php';
require_once $baseDir . '/01-Configuracion-Perfiles/Middlewares/CanCreateAttentions.php';
require_once $baseDir . '/01-Configuracion-Perfiles/Middlewares/AuthorizeEndpointByProfile.php';
require_once $baseDir . '/02-Requerimientos-Evaluacion-Codigo/01-Validacion-Token-Bearer/AuthenticateBearerMiddleware.php';
require_once $baseDir . '/02-Requerimientos-Evaluacion-Codigo/02-Validacion-Middleware-Roles/SoapAutorizacionBridge.php';

use Illuminate\Http\Request;
use Laravel\Sanctum\PersonalAccessToken;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\MatrizPerfilesPermisos;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\AuthorizeEndpointByProfile;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\CanCheckClinicalHistory;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\CanCreateAttentions;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\CanManagePrescriptions;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\Middlewares\IsAdministrator;
use PerfilesMiddlewaresAuth\RequerimientosEvaluacion\ValidacionMiddlewareRoles\SoapAutorizacionBridge;
use PerfilesMiddlewaresAuth\RequerimientosEvaluacion\ValidacionTokenBearer\AuthenticateBearerMiddleware;
use TokenttsConexionSoap\GeneradorTokenSecreto;

// -----------------------------------------------------------------------------
// 3. Helpers de aserción y simulación de tokens Bearer emitidos por /api/login
// -----------------------------------------------------------------------------
$totalTests = 0;
$passedTests = 0;
$failedTests = [];

$assert = function (bool $condition, string $label) use (&$totalTests, &$passedTests, &$failedTests): void {
    $totalTests++;
    if ($condition) {
        $passedTests++;
        echo "  [OK] {$label}\n";
    } else {
        $failedTests[] = $label;
        echo "  [FAIL] {$label}\n";
    }
};

$tokensPorRol = [];
foreach (MatrizPerfilesPermisos::perfiles() as $role => $info) {
    $tokenPlano = "bearer_token_{$role}_2026";
    $pat = new PersonalAccessToken();
    $pat->tokenable = (object) [
        'id'    => count($tokensPorRol) + 1,
        'name'  => $info['perfil'],
        'email' => $info['email'],
        'role'  => $role,
    ];
    PersonalAccessToken::$store[$tokenPlano] = $pat;
    $tokensPorRol[$role] = $tokenPlano;
}

$ejecutarPipeline = function (
    ?string $bearerToken,
    string $middlewareClass,
    string $metodoRest
): array {
    $request = new Request("/api/{$metodoRest}", 'POST');
    if ($bearerToken !== null) {
        $request->setBearerToken($bearerToken);
    }
    $request->setRoute(new class($metodoRest) {
        public function __construct(private string $name) {}
        public function getName(): string { return $this->name; }
        public function getActionName(): string { return $this->name; }
    });

    $controllerReached = false;
    $bearerMw = new AuthenticateBearerMiddleware();
    $roleMw   = new $middlewareClass();

    $response = $bearerMw->handle($request, function ($req) use ($roleMw, $metodoRest, &$controllerReached) {
        return $roleMw->handle($req, function () use (&$controllerReached) {
            $controllerReached = true;
            return response()->json(['mensaje' => 'Ejecutado en controlador'], 200);
        }, $metodoRest);
    });

    return [
        'status'            => $response->getStatusCode(),
        'body'              => json_decode($response->getContent(), true),
        'controllerReached' => $controllerReached,
    ];
};

// Catálogo de rutas protegidas (todas excepto login)
$rutasProtegidas = [
    'registrarAtencion'        => CanCreateAttentions::class,
    'listarAtenciones'         => AuthorizeEndpointByProfile::class,
    'consultarAtencion'        => AuthorizeEndpointByProfile::class,
    'consultarRecetasAtencion' => AuthorizeEndpointByProfile::class,
    'registrarReceta'          => CanManagePrescriptions::class,
    'consultarCitasSoap'       => CanCheckClinicalHistory::class,
    'generarTokenSoap'         => IsAdministrator::class,
    'validarTokenSoap'         => IsAdministrator::class,
];

echo "========================================================================\n";
echo "  VERIFICACION: PERFILES, TOKEN BEARER (401) Y MIDDLEWARES DE ROL (403) \n";
echo "========================================================================\n\n";

// -----------------------------------------------------------------------------
// BLOQUE A: Validación de Token Bearer (HTTP 401 Unauthorized)
// -----------------------------------------------------------------------------
echo ">>> [A] Validacion de Token Bearer en todas las rutas protegidas (HTTP 401)...\n";
foreach ($rutasProtegidas as $metodo => $mwClass) {
    $sinToken = $ejecutarPipeline(null, $mwClass, $metodo);
    $assert(
        $sinToken['status'] === 401 && $sinToken['controllerReached'] === false,
        "Sin token en '{$metodo}' retorna 401 y no llega al controlador"
    );

    $tokenInvalido = $ejecutarPipeline('token_falso_inexistente', $mwClass, $metodo);
    $assert(
        $tokenInvalido['status'] === 401 && $tokenInvalido['controllerReached'] === false,
        "Token inválido en '{$metodo}' retorna 401 y no llega al controlador"
    );
}
echo "\n";

// -----------------------------------------------------------------------------
// BLOQUE B: Validación Manual de $request->user()->role por cada Perfil y Ruta
// -----------------------------------------------------------------------------
echo ">>> [B] Validacion por Middleware de los 4 Perfiles en cada metodo REST...\n";
$expectedError = ['error' => 'Permisos insuficientes para ejecutar este método'];

foreach ($tokensPorRol as $role => $token) {
    echo "  -- Perfil: {$role} --\n";
    foreach ($rutasProtegidas as $metodo => $mwClass) {
        $res = $ejecutarPipeline($token, $mwClass, $metodo);
        $debePermitir = MatrizPerfilesPermisos::metodoRestPermitido($role, $metodo);

        if ($debePermitir) {
            $assert(
                $res['status'] === 200 && $res['controllerReached'] === true,
                "[{$role}] '{$metodo}' PERMITIDO -> HTTP 200 y alcanza controlador"
            );
        } else {
            $assert(
                $res['status'] === 403
                && $res['body'] === $expectedError
                && $res['controllerReached'] === false,
                "[{$role}] '{$metodo}' DENEGADO -> HTTP 403 exacto antes de controlador/SOAP"
            );
        }
    }
}
echo "\n";

// -----------------------------------------------------------------------------
// BLOQUE C: Verificación explícita de cada Middleware aislado
// -----------------------------------------------------------------------------
echo ">>> [C] Verificacion individual de los 4 middlewares por rol...\n";
$casosAislados = [
    [IsAdministrator::class,         'administrador', 'generarTokenSoap',  true],
    [IsAdministrator::class,         'medico',        'generarTokenSoap',  false],
    [CanManagePrescriptions::class,  'farmacia',      'registrarReceta',   true],
    [CanManagePrescriptions::class,  'medico',        'registrarReceta',   false],
    [CanCheckClinicalHistory::class, 'paciente',      'consultarCitasSoap', true],
    [CanCheckClinicalHistory::class, 'farmacia',      'consultarCitasSoap', false],
    [CanCreateAttentions::class,     'medico',        'registrarAtencion', true],
    [CanCreateAttentions::class,     'paciente',      'registrarAtencion', false],
];

foreach ($casosAislados as [$mwClass, $role, $metodo, $esperado]) {
    $res = $ejecutarPipeline($tokensPorRol[$role], $mwClass, $metodo);
    $nombreMw = class_basename($mwClass);
    if ($esperado) {
        $assert($res['status'] === 200, "{$nombreMw} autoriza a '{$role}' en '{$metodo}'");
    } else {
        $assert(
            $res['status'] === 403 && $res['body'] === $expectedError,
            "{$nombreMw} rechaza a '{$role}' en '{$metodo}' con 403 JSON exacto"
        );
    }
}
echo "\n";

// -----------------------------------------------------------------------------
// BLOQUE D: Autorización SOAP consultarCitas() + validación en proyecto SOAP
// -----------------------------------------------------------------------------
echo ">>> [D] Validacion de acceso SOAP consultarCitas() y firma hacia sistema_citas_soap...\n";
$assert(
    MatrizPerfilesPermisos::puedeConsumirSoap('administrador', 'registrarAtencion') === true
    && MatrizPerfilesPermisos::puedeConsumirSoap('administrador', 'consultarCitasSoap') === true,
    "Administrador autorizado para consultarCitas() desde registrarAtencion y consultarCitasSoap"
);
$assert(
    MatrizPerfilesPermisos::puedeConsumirSoap('farmacia', 'registrarAtencion') === false
    && MatrizPerfilesPermisos::puedeConsumirSoap('farmacia', 'consultarCitasSoap') === false,
    "Farmacia bloqueada completamente de consultarCitas() en SOAP"
);
$assert(
    MatrizPerfilesPermisos::puedeConsumirSoap('paciente', 'consultarCitasSoap') === true
    && MatrizPerfilesPermisos::puedeConsumirSoap('paciente', 'registrarAtencion') === false,
    "Paciente autorizado para consultarCitas() UNICAMENTE desde consultarCitasSoap"
);
$assert(
    MatrizPerfilesPermisos::puedeConsumirSoap('medico', 'registrarAtencion') === true
    && MatrizPerfilesPermisos::puedeConsumirSoap('medico', 'consultarCitasSoap') === false,
    "Medico autorizado para consultarCitas() UNICAMENTE desde registrarAtencion"
);

// Verificar SoapAutorizacionBridge bloqueando a farmacia antes de tocar SOAP
$bridge = new SoapAutorizacionBridge();
$bloqueoFarmacia = $bridge->consultarCitasAutorizado('farmacia@consultorio.com', 'farmacia', 'registrarAtencion');
$assert(
    $bloqueoFarmacia['status'] === 403
    && $bloqueoFarmacia['autorizado'] === false
    && $bloqueoFarmacia['payload'] === $expectedError,
    "SoapAutorizacionBridge aborta farmacia antes de SOAP con HTTP 403 exacto"
);

// Verificar que un token HMAC generado con el rol médico es validado por sistema_citas_soap
$soapValidadorPath = 'C:/laragon/www/sistema_citas_soap/Tokenst-conexion-REST/ValidadorTokenSecreto.php';
if (file_exists($soapValidadorPath)) {
    require_once $soapValidadorPath;
    $generador = new GeneradorTokenSecreto();
    $tokenMedico = $generador->generar('medico@consultorio.com', 30, [
        'role'        => 'medico',
        'metodo_rest' => 'registrarAtencion',
        'metodo_soap' => 'consultarCitas',
    ]);
    $validadorSoap = new \ValidadorTokenSecreto();
    $resSoap = $validadorSoap->validar($tokenMedico);

    $assert(
        $resSoap['valido'] === true
        && $resSoap['codigo'] === 200
        && ($resSoap['detalles']['role'] ?? null) === 'medico',
        "Token REST->SOAP con rol 'medico' validado exitosamente por ValidadorTokenSecreto de sistema_citas_soap"
    );
}

echo "\n========================================================================\n";
echo "  RESUMEN: {$passedTests}/{$totalTests} pruebas aprobadas";
if (!empty($failedTests)) {
    echo " (" . count($failedTests) . " fallidas)";
}
echo "\n========================================================================\n";

exit(empty($failedTests) ? 0 : 1);
