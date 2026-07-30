# 5. Análisis de cobertura de pruebas

Estado del repositorio al momento del análisis: el único artefacto de pruebas es
`db/tests/security_invariants.sql`. No hay código de aplicación todavía, de modo
que este documento evalúa lo que **sí** es verificable hoy: el esquema, el
contrato de API y la ausencia de automatización.

Todo lo que sigue se verificó ejecutando el esquema y la suite contra
PostgreSQL 16.13 real. La suite aplica sin errores y pasa 25/25, y es
re-ejecutable como declara el README.

## 5.1 Qué cubre hoy la suite

| Área | Aserciones | Comentario |
|---|---|---|
| Aislamiento multi-tenant (RLS) | 5 | Sólo sobre `units` y `condominiums` |
| FK compuestas entre tenants | 2 | `packages→units`, `unit_residents→memberships` |
| Auditoría inmutable y encadenada | 11 | El área mejor cubierta con diferencia |
| Invariantes de negocio (CHECK) | 6 | Pases, encomiendas, llamadas |
| Higiene de credenciales | 1 | Barrido de nombres de columna |

El módulo de auditoría está genuinamente bien probado: el encadenamiento, el
`INSERT` multi-fila, la detección de manipulación por la puerta trasera y la
inaccesibilidad de `audit_chain_heads` están todos cubiertos. El resto del
esquema no.

## 5.2 Cobertura medida

| Superficie | Total | Ejercitado | |
|---|---|---|---|
| Restricciones `CHECK` con nombre | 16 | 3 | 19 % |
| Tablas con RLS activa | 18 | 2 | 11 % |
| Definiciones de política RLS distintas | 6 | 2 | 33 % |
| Roles de base de datos | 2 | 1 | 50 % |
| Pruebas de concurrencia | — | 0 | — |
| Endpoints documentados con contrato OpenAPI | 33 | 21 | 64 % |
| Puertas en CI | — | 0 | — |

Los `CHECK` ejercitados son `passes_max_ttl`, `packages_delivery_complete` y
`calls_time_order`. Los trece restantes —incluidos
`access_requests_response_consistent`, `calls_answered_consistent`,
`visits_qr_needs_pass`, `devices_ios_needs_voip_token`, `passes_uses` y
`users_phone_e164_format`— nunca se ejecutan.

Las cuatro políticas RLS con lógica no trivial —`user_self_or_cotenant`,
`device_owner`, `refresh_token_owner` y `membership_roles_tenant`— tienen
cobertura cero. Son precisamente las que más pueden equivocarse: la política de
`users` es la única del esquema con una subconsulta `EXISTS`, y
`membership_roles_tenant` omite `WITH CHECK` y depende de que PostgreSQL
reutilice la expresión `USING` para las escrituras. Ese comportamiento es
correcto, pero nada en el repositorio lo fija frente a una regresión.

## 5.3 Tres defectos reales que las pruebas ausentes habrían detectado

Los tres se reprodujeron contra el esquema aplicado.

### 1. El rol `citofonia_auditor` no puede leer absolutamente nada

```
SET ROLE citofonia_auditor;
SELECT count(*) FROM app.units;       -- 0
SELECT count(*) FROM app.audit_logs;  -- 0
```

El rol recibe `GRANT SELECT` sobre todo el esquema (`schema.sql:665`), pero cada
tabla tiene `FORCE ROW LEVEL SECURITY` y el auditor no fija
`app.condominium_id` ni tiene `BYPASSRLS`. El rol existe, tiene permisos y es
funcionalmente inerte. La suite sólo prueba `citofonia_app`, así que nadie lo
notó.

### 2. Los eventos de plataforma no se pueden escribir

`schema.sql:489` documenta `condominium_id` NULL como «evento de plataforma»,
pero la política de inserción exige `condominium_id = app.current_condominium_id()`,
que es falso para NULL:

```
new row violates row-level security policy for table "audit_logs"
```

La cuenta de la aplicación no puede registrar ningún evento a nivel de
plataforma. La capacidad está documentada en el esquema y no funciona.

### 3. `CODIGO_RETIRO` acepta una entrega sin prueba alguna

`docs/03-api.md:179` afirma que «la base de datos rechaza cualquier transición a
`ENTREGADA` sin la prueba correspondiente». Es cierto para dos de los tres
métodos. `packages_delivery_complete` (`schema.sql:428`) exige `signature_key`
para `FIRMA_DIGITAL` y `delivered_to_name` para `AUTORIZADO_TERCERO`, pero no
pide nada para `CODIGO_RETIRO`: ni `pickup_code_hash`, ni `delivered_to`, ni
`pickup_code_expires_at`. Un `UPDATE` a `ENTREGADA` con
`delivery_method = 'CODIGO_RETIRO'` y ningún otro dato se acepta.

Es exactamente el escenario del modelo de amenazas de la fase 0 —«un conserje
que quiere quedarse un paquete»— y es el único de los tres métodos de entrega
sin respaldo en la base de datos. La suite prueba las dos ramas que sí
funcionan y omite la que no.

## 5.4 Áreas de mejora, por prioridad

### Prioridad 1 — Poner la suite en CI

No hay `.github/` en el repositorio. El plan de implementación lo exige en la
fase 0 y su propio texto explica por qué: «una garantía que no está en CI es
una garantía que se pierde en tres meses». Hoy las 25 pruebas sólo corren si
alguien se acuerda de correrlas.

Un workflow con un PostgreSQL 16 efímero que aplique `db/schema.sql`, ejecute la
suite y pase `npx @redocly/cli lint api/openapi.yaml` es media hora de trabajo y
es el prerrequisito de todo lo demás en esta lista.

### Prioridad 2 — Cerrar la matriz de aislamiento por tabla

Trece tablas llevan `tenant_isolation` y sólo `units` está probada. La prueba
debería generarse recorriendo `pg_policies`, no escribirse a mano, para que
cubra automáticamente las tablas que se agreguen después —el mismo criterio que
la fase 1 aplica a los endpoints.

Por cada tabla con RLS, cuatro aserciones: `SELECT` cruzado devuelve cero,
`INSERT` cruzado se rechaza, `UPDATE` cruzado afecta cero filas, `DELETE`
cruzado afecta cero filas. Hoy sólo se prueba `INSERT`, y sólo en una tabla;
`UPDATE` y `DELETE` cruzados no se prueban en ninguna.

Añadir además las cuatro políticas específicas: que un usuario vea a sus
co-inquilinos activos pero no a los de otro condominio ni a los revocados, que
`devices` y `refresh_tokens` sean estrictamente del dueño, y que
`membership_roles` no admita escrituras hacia membresías ajenas.

### Prioridad 3 — Concurrencia

No hay ninguna prueba concurrente, y el plan cierra dos fases con requisitos que
lo son. Verifiqué a mano que ambos caminos críticos aguantan —10 escaneos
simultáneos del mismo pase producen exactamente un canje; 200 inserciones de
auditoría desde 8 sesiones no producen `seq` duplicados ni roturas de cadena—
pero nada en el repositorio impide que una refactorización lo rompa en
silencio. Son las dos propiedades más caras de depurar en producción y las más
baratas de fijar ahora.

La prueba de canje debe ejecutar la consulta atómica tal como aparece en
`docs/03-api.md:78`, para que el día que alguien la reescriba como
lectura-y-luego-escritura la suite lo detecte.

### Prioridad 4 — Completar los `CHECK` y las reglas de borrado

Trece restricciones sin ejercitar, cada una expresando una regla de negocio que
alguien podría relajar al editar el esquema. Las de mayor valor:
`visits_qr_needs_pass`, `access_requests_response_consistent`,
`devices_ios_needs_voip_token` (de la que depende la citofonía en iOS) y
`passes_uses`.

En el mismo bloque conviene fijar las reglas de borrado, que hoy no se prueban:
`ON DELETE RESTRICT` sobre `packages.received_by` y `visits.registered_by`
protege la trazabilidad —una membresía que registró una encomienda no debe poder
desaparecer— y `ON DELETE CASCADE` desde `condominiums` determina qué ocurre al
dar de baja un tenant.

### Prioridad 5 — Alinear y probar el contrato de API

Doce de los treinta y tres endpoints de `docs/03-api.md` no existen en
`api/openapi.yaml`: `/auth/mfa/verify`, `/auth/password/forgot`,
`/auth/password/reset`, el JWKS, `DELETE /me/devices/{id}`,
`/calls/{id}/reject`, `/calls/{id}/quality`, `GET /packages/{id}`,
`/packages/{id}/photo`, `/packages/inventory` y ambos endpoints de
`/reports`. En sentido inverso, `/uploads` está en el contrato y no en el
documento.

Esto importa más de lo que parece: la fase 1 exige que la suite de tenancy sea
**generada a partir de la especificación**. Una suite generada saltaría en
silencio los doce endpoints ausentes, incluidos los de recuperación de
contraseña y MFA, que están entre los más atacados del sistema. Alinear el
contrato es un prerrequisito de esa prueba generada, no una tarea cosmética.

## 5.5 Notas sobre la suite existente

Dos observaciones que no son huecos de cobertura pero afectan su operación:

**Es fail-fast.** `app.t_report` lanza una excepción al primer fallo y
`ON_ERROR_STOP` aborta el archivo, de modo que una regresión oculta el
resultado de todo lo que venía después. Acumular los fallos y reportarlos al
final daría un diagnóstico mucho más útil en CI.

**Requiere una base desechable.** La suite escribe filas permanentes en
`audit_logs` —que es append-only y no se puede limpiar—, necesita privilegios de
dueño de tabla y toma un `ACCESS EXCLUSIVE` sobre `audit_logs` al desactivar el
trigger para el simulacro de manipulación. Es correcto para CI contra un
PostgreSQL efímero, y es exactamente lo que hay que dejar claro antes de que
alguien la apunte a un entorno compartido. El bloque `DO` que desactiva el
trigger sí es seguro: al ser una única transacción, un fallo intermedio revierte
también el `ALTER TABLE`.
