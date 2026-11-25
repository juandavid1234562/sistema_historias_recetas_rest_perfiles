<?php

namespace PerfilesMiddlewaresAuth\RequerimientosEvaluacion\ValidacionTokenBearer;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\MatrizPerfilesPermisos;

/**
 * Controlador de Autenticación API REST (Laravel Sanctum - Token Bearer).
 *
 * Única ruta pública: POST /api/login.
 * Emite un Personal Access Token (Bearer) asociado al usuario y su rol manual
 * ('administrador', 'farmacia', 'paciente', 'medico').
 */
class AuthController extends Controller
{
    /**
     * POST /api/login (Pública)
     * Autentica al usuario y retorna el token Bearer junto con su perfil y permisos.
     */
    public function login(Request $request): JsonResponse
    {
        $credenciales = $request->validate([
            'email'    => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ]);

        $user = User::where('email', $credenciales['email'])->first();

        if (!$user || !Hash::check($credenciales['password'], $user->password)) {
            return response()->json([
                'error' => 'Credenciales inválidas. Verifique email y contraseña.',
            ], 401);
        }

        // Revoca tokens previos opcionalmente o genera un nuevo token Sanctum con habilidad del rol
        $token = $user->createToken('api-rest-consultorio', ["role:{$user->role}"])->plainTextToken;

        $perfilInfo = MatrizPerfilesPermisos::perfiles()[$user->role] ?? null;

        return response()->json([
            'mensaje'      => 'Autenticación exitosa',
            'token_type'   => 'Bearer',
            'access_token' => $token,
            'usuario'      => [
                'id'    => $user->id,
                'name'  => $user->name,
                'email' => $user->email,
                'role'  => $user->role,
            ],
            'permisos' => $perfilInfo ? [
                'middleware'      => $perfilInfo['middleware'],
                'rest_permitidos' => $perfilInfo['rest_permitidos'],
                'soap_permitidos' => $perfilInfo['soap_permitidos'],
            ] : null,
        ], 200);
    }

    /**
     * GET /api/me (Protegida por Bearer Token)
     * Retorna el perfil del usuario autenticado mediante $request->user().
     */
    public function me(Request $request): JsonResponse
    {
        $user = $request->user();

        return response()->json([
            'id'    => $user->id,
            'name'  => $user->name,
            'email' => $user->email,
            'role'  => $user->role,
        ], 200);
    }

    /**
     * POST /api/logout (Protegida por Bearer Token)
     * Revoca el token Bearer actual.
     */
    public function logout(Request $request): JsonResponse
    {
        $request->user()->currentAccessToken()?->delete();

        return response()->json([
            'mensaje' => 'Sesión cerrada y token Bearer revocado exitosamente.',
        ], 200);
    }
}
