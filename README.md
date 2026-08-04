# Citofonía Comunidad

Diseño de arquitectura para una aplicación móvil y web de **citofonía online y gestión de condominios**: comunicación en tiempo real entre conserjería y departamentos, control de acceso de visitas por QR, gestión de encomiendas y auditoría trazable.

Este repositorio contiene el **diseño técnico y los artefactos ejecutables que lo respaldan**. No es todavía una aplicación en funcionamiento; el plan para construirla está en el documento 4.

## Documentos

| # | Documento | Contenido |
|---|---|---|
| 1 | [Arquitectura del sistema](docs/01-arquitectura.md) | Componentes, infraestructura, alcance real del cifrado E2EE, notificaciones de llamada crítica |
| 2 | [Modelo de datos](docs/02-modelo-datos.md) | Entidades, aislamiento multi-tenant, auditoría inmutable, matriz RBAC |
| 3 | [Especificación de API](docs/03-api.md) | REST, WebSocket, señalización WebRTC, formato del token QR, defensas OWASP |
| 4 | [Plan de implementación del MVP](docs/04-plan-mvp.md) | Seis fases con puertas de seguridad, cronograma y riesgos |
| 5 | [Análisis de cobertura de pruebas](docs/05-cobertura-pruebas.md) | Qué está probado, qué no, y tres defectos que las pruebas ausentes no detectan |

## Artefactos ejecutables

| Ruta | Qué es | Estado |
|---|---|---|
| [`db/schema.sql`](db/schema.sql) | Esquema PostgreSQL 16 completo: tablas, RLS, RBAC, auditoría encadenada | Aplica sin errores en PostgreSQL 16.13 |
| [`db/tests/security_invariants.sql`](db/tests/security_invariants.sql) | 25 pruebas de invariantes de seguridad | 25/25 en verde, re-ejecutable |
| [`api/openapi.yaml`](api/openapi.yaml) | Contrato OpenAPI 3.1 — 21 rutas, 25 operaciones | Válido, sin advertencias (Redocly) |

```bash
# Esquema y pruebas
createdb citofonia
psql -d citofonia -v ON_ERROR_STOP=1 -f db/schema.sql
psql -d citofonia -v ON_ERROR_STOP=1 -f db/tests/security_invariants.sql

# Contrato de API
npx @redocly/cli lint api/openapi.yaml
```

## Las cinco decisiones que definen el diseño

1. **El aislamiento entre condominios se implementa dos veces.** Row Level Security filtra las lecturas y las claves foráneas compuestas impiden enlazar entidades de tenants distintos. Un bug en la aplicación no basta para filtrar datos de un condominio a otro, y hay pruebas que lo verifican contra el motor.

2. **El audio no pasa por el backend.** Las llamadas son WebRTC punto a punto con DTLS-SRTP; el servidor sólo transporta señalización. No se usa SFU precisamente porque obligaría a terminar el cifrado en el servidor.

3. **La auditoría es append-only y encadenada por hash**, con la cabeza de cadena fuera del alcance de la cuenta de la aplicación. El verificador recalcula los hashes, de modo que detecta tanto entradas eliminadas como campos alterados.

4. **Los pases QR se firman con Ed25519, no con RS256.** Una firma RSA de 256 bytes produce un QR demasiado denso para escanear con fiabilidad desde una tablet de portería. Los JWT de la API sí usan RS256, donde el tamaño no importa.

5. **El servidor nunca acepta el destino de una acción sensible desde el cliente.** Iniciar una llamada recibe `unit_id`, jamás un número de teléfono; el tenant sale del token, nunca de la petición.

## Dos limitaciones que conviene leer antes de firmar nada

**El fallback a red telefónica no es, ni puede ser, cifrado de extremo a extremo.** La llamada se termina en el gateway del operador y viaja por la PSTN: el proveedor tiene acceso al audio por diseño y ninguna configuración lo evita. Por eso el fallback es desactivable por condominio, se muestra un aviso visible de línea no cifrada en ambos extremos y el hecho queda registrado. Detalle en [§1.4](docs/01-arquitectura.md#14-cifrado-de-audio-alcance-real-del-e2ee).

**"Cero hackeos" no es una propiedad alcanzable** y no debe prometerse por contrato. Lo que este diseño persigue —y sí es verificable— es defensa en profundidad, radio de explosión acotado y trazabilidad no repudiable. La discusión completa abre el documento de arquitectura.

## Estado

Diseño completo con esquema y contrato de API verificados. El siguiente paso es la Fase 0 del [plan de implementación](docs/04-plan-mvp.md): fundaciones de infraestructura y CI, antes de escribir código de negocio.
