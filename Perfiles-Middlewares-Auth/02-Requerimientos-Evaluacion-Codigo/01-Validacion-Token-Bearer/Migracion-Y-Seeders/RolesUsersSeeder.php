<?php

namespace PerfilesMiddlewaresAuth\RequerimientosEvaluacion\ValidacionTokenBearer\MigracionYSeeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use PerfilesMiddlewaresAuth\ConfiguracionPerfiles\MatrizPerfilesPermisos;

/**
 * Seeder para poblar los 4 perfiles de usuario requeridos en el Consultorio Médico.
 */
class RolesUsersSeeder extends Seeder
{
    public function run(): void
    {
        $usuarios = [
            [
                'name'     => 'Administrador Consultorio',
                'email'    => 'administrador@consultorio.com',
                'password' => Hash::make('Admin2026*'),
                'role'     => MatrizPerfilesPermisos::ROLE_ADMINISTRADOR,
            ],
            [
                'name'     => 'Farmacia y Recetas',
                'email'    => 'farmacia@consultorio.com',
                'password' => Hash::make('Farmacia2026*'),
                'role'     => MatrizPerfilesPermisos::ROLE_FARMACIA,
            ],
            [
                'name'     => 'Paciente Consulta',
                'email'    => 'paciente@consultorio.com',
                'password' => Hash::make('Paciente2026*'),
                'role'     => MatrizPerfilesPermisos::ROLE_PACIENTE,
            ],
            [
                'name'     => 'Médico de Atenciones',
                'email'    => 'medico@consultorio.com',
                'password' => Hash::make('Medico2026*'),
                'role'     => MatrizPerfilesPermisos::ROLE_MEDICO,
            ],
        ];

        foreach ($usuarios as $datos) {
            User::updateOrCreate(
                ['email' => $datos['email']],
                $datos
            );
        }
    }
}
