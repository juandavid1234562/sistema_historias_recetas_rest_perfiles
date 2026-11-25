# README2 - Implementación de Perfiles, Autenticación Bearer y Middlewares Personalizados (REST + SOAP)

Este documento describe la implementación ordenada de **autenticación por Token Bearer, gestión manual de roles y middlewares personalizados** aplicada al contexto real de los dos proyectos locales:

1. **API REST Laravel (`sistema_historias_recetas_rest`)**: Gestión de Historias Clínicas (`Atenciones`) y `Recetas Médicas`.
2. **Servicio Web SOAP (`C:\laragon\www\sistema_citas_soap`)**: Servicio legado de citas médicas en NuSOAP/MySQL, cuya operación protegida principal consumida desde REST es **`consultarCitas()`**.

> **Nota de integridad:** Ningún archivo existente de `sistema_historias_recetas_rest` ni de `sistema_citas_soap` fue modificado. Toda la implementación, configuración y pruebas se organizaron en la carpeta nueva [`Perfiles-Middlewares-Auth/`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth).

---

## 1. Configuración de Perfiles y Middlewares (Adaptado al Contexto Médico REST + SOAP)

En el proyecto de ejemplo (Biblioteca) los métodos giraban en torno a multas, pagos y `consultarPrestamos()`. Aplicado exactamente a nuestros dos proyectos locales del Consultorio Médico, las operaciones equivalentes son:

- **Métodos REST (`sistema_historias_recetas_rest`)**:
  - `login` (`POST /api/login`)
  - `registrarAtencion` (`POST /api/atenciones` — valida la cita en SOAP)
  - `listarAtenciones` (`GET /api/atenciones`)
  - `consultarAtencion` (`GET /api/atenciones/{id}`)
  - `consultarRecetasAtencion` (`GET /api/atenciones/{id}/recetas`)
  - `registrarReceta` (`POST /api/recetas`)
  - `consultarCitasSoap` (`POST /api/soap/citas/consultar` — consulta citas en SOAP)
  - `generarTokenSoap` (`POST /api/soap/token/generar`) / `validarTokenSoap` (`POST /api/soap/token/validar`)
- **Método SOAP (`sistema_citas_soap`)**:
  - `consultarCitas()` (expuesto en `legacy_soap/soap/server.php` y consumido vía `CitaSoapAdapter` y `ClienteSoapToken`).

### Matriz de los 4 Perfiles

| Perfil | Usuario (`role`) | Middleware | Métodos REST permitidos | Método SOAP permitido (`consultarCitas()`) |
|---|---|---|---|---|
| **Perfil Administrador** | `administrador` | `IsAdministrator` | **Todos** (`login`, `registrarAtencion`, `listarAtenciones`, `consultarAtencion`, `consultarRecetasAtencion`, `registrarReceta`, `consultarCitasSoap`, `generarTokenSoap`, `validarTokenSoap`) | **`consultarCitas()`** (autorizado al ejecutar `registrarAtencion`, `consultarCitasSoap` y operaciones de token SOAP) |
| **Perfil Farmacia / Recetas** *(equiv. Tesorería)* | `farmacia` | `CanManagePrescriptions` | `login`, `registrarReceta`, `consultarRecetasAtencion`, `consultarAtencion`, `listarAtenciones` | **Ninguno** (bloquea `registrarAtencion` y `consultarCitasSoap`, impidiendo cualquier consumo hacia `consultarCitas()`) |
| **Perfil Paciente / Consulta** *(equiv. Estudiante)* | `paciente` | `CanCheckClinicalHistory` | `login`, `consultarAtencion`, `consultarRecetasAtencion`, `consultarCitasSoap` | **`consultarCitas()`** (autorizado **únicamente** cuando el paciente ejecuta `consultarCitasSoap` para verificar su cita) |
| **Perfil Médico de Atenciones** *(equiv. Sancionador)* | `medico` | `CanCreateAttentions` | `login`, `registrarAtencion`, `listarAtenciones`, `consultarAtencion`, `consultarRecetasAtencion` | **`consultarCitas()`** (autorizado **únicamente** cuando el médico ejecuta `registrarAtencion` para validar que la cita esté `Programada`) |

---

## 2. Requerimientos de Evaluación en el Código

### 2.1 Validación de Token Bearer (`HTTP 401 Unauthorized`)
- La única ruta pública es **`POST /api/login`**.
- Todas las demás rutas exigen un **token Bearer válido** (`Authorization: Bearer <token>`) emitido por Laravel Sanctum y validado por `AuthenticateBearerMiddleware` / `auth:sanctum`.
- Si el token no se envía, está malformado, no existe o expiró, el sistema retorna **`HTTP 401 Unauthorized`** en JSON antes de llegar al controlador.

### 2.2 Validación Manual por Middleware (`$request->user()->role` -> `HTTP 403 Forbidden`)
- Todos los middlewares personalizados (`IsAdministrator`, `CanManagePrescriptions`, `CanCheckClinicalHistory`, `CanCreateAttentions`, `AuthorizeEndpointByProfile`) heredan de `BaseRoleMiddleware` y verifican manualmente la propiedad **`$request->user()->role`**.
- Además de validar el rol del middleware, se verifica contra `MatrizPerfilesPermisos` que el método REST solicitado forme parte de los permisos del perfil.
- Si un usuario intenta ejecutar un método no listado en sus permisos, el middleware **aborta la petición antes de llegar al controlador o al servicio SOAP**, retornando **`HTTP 403 Forbidden`** con la estructura JSON exacta requerida:

```json
{ "error": "Permisos insuficientes para ejecutar este método" }
```

---

## 3. Estructura de Carpetas Creada

```text
Perfiles-Middlewares-Auth/
├── 01-Configuracion-Perfiles/
│   ├── MatrizPerfilesPermisos.php
│   └── Middlewares/
│       ├── BaseRoleMiddleware.php
│       ├── IsAdministrator.php
│       ├── CanManagePrescriptions.php
│       ├── CanCheckClinicalHistory.php
│       ├── CanCreateAttentions.php
│       └── AuthorizeEndpointByProfile.php
├── 02-Requerimientos-Evaluacion-Codigo/
│   ├── 01-Validacion-Token-Bearer/
│   │   ├── AuthController.php
│   │   ├── AuthenticateBearerMiddleware.php
│   │   └── Migracion-Y-Seeders/
│   │       ├── 2026_11_24_000001_add_role_to_users_table.php
│   │       ├── UserWithRole.php
│   │       └── RolesUsersSeeder.php
│   └── 02-Validacion-Middleware-Roles/
│       ├── routes_api_protegidas.php
│       ├── BootstrapMiddlewareYExcepciones.php
│       └── SoapAutorizacionBridge.php
└── 03-Pruebas-Verificacion/
    └── probar_perfiles_middlewares.php
```

### Descripción por Subcarpeta
1. **`01-Configuracion-Perfiles/`**:
   - [`MatrizPerfilesPermisos.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/01-Configuracion-Perfiles/MatrizPerfilesPermisos.php): Define de forma centralizada los 4 perfiles (`administrador`, `farmacia`, `paciente`, `medico`), sus métodos REST permitidos y las reglas de consumo de `consultarCitas()` en SOAP.
   - `Middlewares/`: Contiene [`BaseRoleMiddleware.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/01-Configuracion-Perfiles/Middlewares/BaseRoleMiddleware.php) y los middlewares [`IsAdministrator.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/01-Configuracion-Perfiles/Middlewares/IsAdministrator.php), [`CanManagePrescriptions.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/01-Configuracion-Perfiles/Middlewares/CanManagePrescriptions.php), [`CanCheckClinicalHistory.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/01-Configuracion-Perfiles/Middlewares/CanCheckClinicalHistory.php), [`CanCreateAttentions.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/01-Configuracion-Perfiles/Middlewares/CanCreateAttentions.php) y [`AuthorizeEndpointByProfile.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/01-Configuracion-Perfiles/Middlewares/AuthorizeEndpointByProfile.php).

2. **`02-Requerimientos-Evaluacion-Codigo/`**:
   - **`01-Validacion-Token-Bearer/`**:
     - [`AuthController.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/02-Requerimientos-Evaluacion-Codigo/01-Validacion-Token-Bearer/AuthController.php): Implementa `login`, `me` y `logout` con Laravel Sanctum (`Bearer`).
     - [`AuthenticateBearerMiddleware.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/02-Requerimientos-Evaluacion-Codigo/01-Validacion-Token-Bearer/AuthenticateBearerMiddleware.php): Exige el token Bearer y responde HTTP `401 Unauthorized` si falta o es inválido.
     - `Migracion-Y-Seeders/`: Migración de columna `role` en `users`, modelo `UserWithRole` (`HasApiTokens` + `role`) y `RolesUsersSeeder` con los 4 usuarios de prueba.
   - **`02-Validacion-Middleware-Roles/`**:
     - [`routes_api_protegidas.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/02-Requerimientos-Evaluacion-Codigo/02-Validacion-Middleware-Roles/routes_api_protegidas.php): Definición completa de rutas `/api/*` con `login` público y protección por Bearer + Middleware en el resto.
     - [`BootstrapMiddlewareYExcepciones.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/02-Requerimientos-Evaluacion-Codigo/02-Validacion-Middleware-Roles/BootstrapMiddlewareYExcepciones.php): Registro de alias de middlewares y manejo global de `AuthenticationException -> 401 JSON` para Laravel 13.
     - [`SoapAutorizacionBridge.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/02-Requerimientos-Evaluacion-Codigo/02-Validacion-Middleware-Roles/SoapAutorizacionBridge.php): Guardia de autorización previa al consumo de `consultarCitas()` en `sistema_citas_soap`, adjuntando el `role` en el token HMAC-SHA256.

3. **`03-Pruebas-Verificacion/`**:
   - [`probar_perfiles_middlewares.php`](file:///c:/laragon/www/soap/sistema_historias_recetas_rest/Perfiles-Middlewares-Auth/03-Pruebas-Verificacion/probar_perfiles_middlewares.php): Script automatizado que prueba todos los escenarios de autenticación (`401`), permisos por rol (`403` con el JSON exacto y `200` cuando aplica), bloqueo previo a controlador/SOAP y validación del token con `ValidadorTokenSecreto` de `sistema_citas_soap`.

---

## 4. Cómo Ejecutar la Verificación

Desde la raíz del proyecto Laravel:

```bash
php Perfiles-Middlewares-Auth/03-Pruebas-Verificacion/probar_perfiles_middlewares.php
```

También se puede verificar la sintaxis PHP de todos los archivos del módulo con `php -l`.
