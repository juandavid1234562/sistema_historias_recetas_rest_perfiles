<?php

namespace PerfilesMiddlewaresAuth\RequerimientosEvaluacion\ValidacionTokenBearer\MigracionYSeeders;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

/**
 * Modelo de referencia User con soporte de Laravel Sanctum (HasApiTokens)
 * y el atributo manual `role` para verificación directa en middlewares ($request->user()->role).
 */
class UserWithRole extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $table = 'users';

    protected $fillable = [
        'name',
        'email',
        'password',
        'role',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password'          => 'hashed',
        ];
    }

    public function hasRole(string $role): bool
    {
        return $this->role === $role;
    }
}
