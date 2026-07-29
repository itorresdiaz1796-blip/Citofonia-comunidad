-- =====================================================================
--  Citofonía Comunidad — Esquema relacional (PostgreSQL 16)
--  ---------------------------------------------------------------
--  Principios aplicados:
--   1. Multi-tenancy por RLS: TODA tabla de negocio lleva condominium_id
--      y una política que la filtra por app.current_condominium_id().
--   2. Integridad de tenant por FK compuesta: las referencias entre
--      entidades incluyen condominium_id, de modo que la base de datos
--      hace imposible enlazar una unidad del condominio A con una
--      encomienda del condominio B (defensa estructural contra IDOR).
--   3. Identificadores UUIDv4 no adivinables en todo recurso expuesto.
--   4. Secretos (códigos de retiro, tokens QR, refresh tokens) se
--      almacenan SOLO como hash; nunca en claro.
--   5. audit_logs es append-only con encadenamiento de hash.
-- =====================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS citext   WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS app;

-- ---------------------------------------------------------------------
-- 0. Contexto de tenant y helpers
-- ---------------------------------------------------------------------

-- El backend ejecuta SET LOCAL app.condominium_id = '<uuid>' al inicio de
-- cada transacción, derivándolo del JWT verificado (nunca de un parámetro
-- de la petición). Si no está definido, las políticas RLS no dejan pasar
-- ninguna fila.
CREATE OR REPLACE FUNCTION app.current_condominium_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.condominium_id', true), '')::uuid;
$$;

CREATE OR REPLACE FUNCTION app.current_user_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid;
$$;

CREATE OR REPLACE FUNCTION app.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------
-- 1. Enumeraciones
-- ---------------------------------------------------------------------

CREATE TYPE app.membership_role       AS ENUM ('ADMIN', 'CONSERJE', 'RESIDENTE', 'VISITA');
CREATE TYPE app.entity_status         AS ENUM ('ACTIVE', 'SUSPENDED', 'DISABLED');
CREATE TYPE app.user_status           AS ENUM ('PENDING', 'ACTIVE', 'LOCKED', 'DISABLED');
CREATE TYPE app.resident_relation     AS ENUM ('PROPIETARIO', 'ARRENDATARIO', 'FAMILIAR', 'AUTORIZADO');
CREATE TYPE app.device_platform       AS ENUM ('IOS', 'ANDROID', 'WEB');
CREATE TYPE app.pass_status           AS ENUM ('ACTIVE', 'USED', 'EXPIRED', 'REVOKED');
CREATE TYPE app.visit_method          AS ENUM ('QR', 'APROBACION_REMOTA', 'MANUAL', 'LISTA_FRECUENTE');
CREATE TYPE app.visit_status          AS ENUM ('EN_CURSO', 'FINALIZADA', 'RECHAZADA');
CREATE TYPE app.access_request_status AS ENUM ('PENDIENTE', 'APROBADA', 'RECHAZADA', 'EXPIRADA', 'CANCELADA');
CREATE TYPE app.call_channel          AS ENUM ('WEBRTC_P2P', 'WEBRTC_TURN', 'PSTN');
CREATE TYPE app.call_direction        AS ENUM ('CONSERJERIA_A_UNIDAD', 'UNIDAD_A_CONSERJERIA');
CREATE TYPE app.call_status           AS ENUM ('INITIATED', 'RINGING', 'ANSWERED', 'REJECTED', 'MISSED', 'FAILED', 'ENDED');
CREATE TYPE app.package_status        AS ENUM ('RECIBIDA', 'NOTIFICADA', 'ENTREGADA', 'DEVUELTA', 'EXTRAVIADA');
CREATE TYPE app.delivery_method       AS ENUM ('FIRMA_DIGITAL', 'CODIGO_RETIRO', 'AUTORIZADO_TERCERO');
CREATE TYPE app.notification_channel  AS ENUM ('PUSH', 'VOIP_PUSH', 'SMS', 'EMAIL', 'CALL_PSTN');
CREATE TYPE app.notification_status   AS ENUM ('QUEUED', 'SENT', 'DELIVERED', 'FAILED');

-- ---------------------------------------------------------------------
-- 2. Tenants: condominios, edificios, unidades
-- ---------------------------------------------------------------------

CREATE TABLE app.condominiums (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name           text        NOT NULL,
  tax_id         citext      UNIQUE,                 -- RUT / NIT
  country_code   char(2)     NOT NULL DEFAULT 'CL',
  timezone       text        NOT NULL DEFAULT 'America/Santiago',
  address        text,
  status         app.entity_status NOT NULL DEFAULT 'ACTIVE',
  -- Parámetros operativos: TTL de pases, política de fallback PSTN, etc.
  settings       jsonb       NOT NULL DEFAULT '{}'::jsonb,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT condominiums_name_not_blank CHECK (length(btrim(name)) > 0)
);

CREATE TABLE app.buildings (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  condominium_id  uuid NOT NULL REFERENCES app.condominiums(id) ON DELETE CASCADE,
  name            text NOT NULL,
  floors          smallint,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (condominium_id, name),
  -- Clave candidata compuesta: habilita FK que arrastran el tenant.
  UNIQUE (condominium_id, id)
);

CREATE TABLE app.units (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  condominium_id  uuid NOT NULL REFERENCES app.condominiums(id) ON DELETE CASCADE,
  building_id     uuid,
  label           text NOT NULL,               -- "A-1203"
  intercom_alias  text,                        -- marcación en conserjería: "1203"
  floor           smallint,
  status          app.entity_status NOT NULL DEFAULT 'ACTIVE',
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (condominium_id, label),
  UNIQUE (condominium_id, intercom_alias),
  UNIQUE (condominium_id, id),
  FOREIGN KEY (condominium_id, building_id)
    REFERENCES app.buildings (condominium_id, id) ON DELETE SET NULL
);
CREATE INDEX units_condominium_idx ON app.units (condominium_id) WHERE status = 'ACTIVE';

-- ---------------------------------------------------------------------
-- 3. Identidad, membresías y RBAC
-- ---------------------------------------------------------------------

-- users es GLOBAL (una persona puede ser residente en dos condominios).
-- No lleva RLS por tenant: se accede sólo vía memberships.
CREATE TABLE app.users (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email              citext UNIQUE,
  phone_e164         text   UNIQUE,
  password_hash      text,                       -- argon2id; NULL si sólo OIDC
  full_name          text NOT NULL,
  -- Dato sensible: se guarda cifrado por la aplicación (envelope encryption
  -- con KMS). La BD nunca ve el RUT en claro; national_id_hash permite
  -- búsqueda por igualdad sin descifrar.
  national_id_enc    bytea,
  national_id_hash   bytea,
  status             app.user_status NOT NULL DEFAULT 'PENDING',
  mfa_enabled        boolean NOT NULL DEFAULT false,
  mfa_secret_enc     bytea,
  failed_login_count smallint NOT NULL DEFAULT 0,
  locked_until       timestamptz,
  last_login_at      timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_needs_identifier CHECK (email IS NOT NULL OR phone_e164 IS NOT NULL),
  CONSTRAINT users_phone_e164_format CHECK (phone_e164 IS NULL OR phone_e164 ~ '^\+[1-9][0-9]{7,14}$')
);
CREATE INDEX users_national_id_hash_idx ON app.users (national_id_hash) WHERE national_id_hash IS NOT NULL;

-- Una membresía por (condominio, usuario). Los roles se adjuntan aparte
-- porque una misma persona puede ser, p.ej., ADMIN del comité y RESIDENTE.
CREATE TABLE app.memberships (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  condominium_id  uuid NOT NULL REFERENCES app.condominiums(id) ON DELETE CASCADE,
  user_id         uuid NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
  status          app.entity_status NOT NULL DEFAULT 'ACTIVE',
  invited_by      uuid REFERENCES app.memberships(id) ON DELETE SET NULL,
  joined_at       timestamptz,
  revoked_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (condominium_id, user_id),
  UNIQUE (condominium_id, id)
);
CREATE INDEX memberships_user_idx ON app.memberships (user_id);

CREATE TABLE app.membership_roles (
  membership_id  uuid NOT NULL REFERENCES app.memberships(id) ON DELETE CASCADE,
  role           app.membership_role NOT NULL,
  granted_by     uuid REFERENCES app.memberships(id) ON DELETE SET NULL,
  granted_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (membership_id, role)
);

CREATE TABLE app.permissions (
  code        text PRIMARY KEY,
  description text NOT NULL
);

CREATE TABLE app.role_permissions (
  role            app.membership_role NOT NULL,
  permission_code text NOT NULL REFERENCES app.permissions(code) ON DELETE CASCADE,
  PRIMARY KEY (role, permission_code)
);

-- Residentes asignados a una unidad. La FK compuesta contra memberships
-- garantiza que sólo un miembro del MISMO condominio puede vivir en la unidad.
CREATE TABLE app.unit_residents (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  condominium_id    uuid NOT NULL,
  unit_id           uuid NOT NULL,
  membership_id     uuid NOT NULL,
  relation          app.resident_relation NOT NULL DEFAULT 'PROPIETARIO',
  is_primary        boolean NOT NULL DEFAULT false,
  receives_calls    boolean NOT NULL DEFAULT true,
  receives_packages boolean NOT NULL DEFAULT true,
  valid_from        date NOT NULL DEFAULT current_date,
  valid_until       date,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (unit_id, membership_id),
  FOREIGN KEY (condominium_id, unit_id)       REFERENCES app.units (condominium_id, id)       ON DELETE CASCADE,
  FOREIGN KEY (condominium_id, membership_id) REFERENCES app.memberships (condominium_id, id) ON DELETE CASCADE,
  CONSTRAINT unit_residents_valid_range CHECK (valid_until IS NULL OR valid_until >= valid_from)
);
CREATE INDEX unit_residents_unit_idx ON app.unit_residents (condominium_id, unit_id);
-- Un solo residente principal por unidad.
CREATE UNIQUE INDEX unit_residents_one_primary ON app.unit_residents (unit_id) WHERE is_primary;

-- ---------------------------------------------------------------------
-- 4. Dispositivos y sesiones
-- ---------------------------------------------------------------------

CREATE TABLE app.devices (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
  platform         app.device_platform NOT NULL,
  push_token       text,          -- FCM (Android/Web) o APNs alert token
  voip_push_token  text,          -- APNs PushKit: obligatorio en iOS para citofonía
  app_version      text,
  device_model     text,
  last_seen_at     timestamptz,
  revoked_at       timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT devices_ios_needs_voip_token
    CHECK (platform <> 'IOS' OR voip_push_token IS NOT NULL OR revoked_at IS NOT NULL)
);
CREATE UNIQUE INDEX devices_push_token_idx ON app.devices (platform, push_token) WHERE push_token IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX devices_user_active_idx ON app.devices (user_id) WHERE revoked_at IS NULL;

-- Rotación estricta con detección de reuso: si llega un refresh token cuyo
-- rotated_to ya está poblado, se revoca la familia completa.
CREATE TABLE app.refresh_tokens (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),   -- jti
  user_id        uuid NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
  family_id      uuid NOT NULL,
  token_hash     bytea NOT NULL UNIQUE,        -- sha256(token); jamás el token
  device_id      uuid REFERENCES app.devices(id) ON DELETE SET NULL,
  issued_at      timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  rotated_to     uuid REFERENCES app.refresh_tokens(id) ON DELETE SET NULL,
  revoked_at     timestamptz,
  revoked_reason text,
  ip             inet,
  user_agent     text,
  CONSTRAINT refresh_tokens_ttl CHECK (expires_at > issued_at)
);
CREATE INDEX refresh_tokens_family_idx ON app.refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_active_idx ON app.refresh_tokens (user_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------
-- 5. Control de acceso: pases QR, solicitudes y bitácora de visitas
-- ---------------------------------------------------------------------

CREATE TABLE app.visitor_passes (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),  -- jti embebido en el QR
  condominium_id     uuid NOT NULL,
  unit_id            uuid NOT NULL,
  issued_by          uuid NOT NULL,                    -- membership del residente
  visitor_name       text NOT NULL,
  visitor_national_id text,
  visitor_phone      text,
  vehicle_plate      text,
  purpose            text,
  max_uses           smallint NOT NULL DEFAULT 1,
  used_count         smallint NOT NULL DEFAULT 0,
  valid_from         timestamptz NOT NULL DEFAULT now(),
  valid_until        timestamptz NOT NULL,
  status             app.pass_status NOT NULL DEFAULT 'ACTIVE',
  key_id             text NOT NULL,                    -- kid de la clave Ed25519 firmante
  token_hash         bytea NOT NULL,                   -- sha256 del token completo
  revoked_at         timestamptz,
  revoked_by         uuid,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (condominium_id, unit_id)   REFERENCES app.units (condominium_id, id)       ON DELETE CASCADE,
  FOREIGN KEY (condominium_id, issued_by) REFERENCES app.memberships (condominium_id, id) ON DELETE RESTRICT,
  CONSTRAINT passes_window     CHECK (valid_until > valid_from),
  -- Ventana máxima de 7 días: un QR no puede ser un pase permanente.
  CONSTRAINT passes_max_ttl    CHECK (valid_until <= valid_from + interval '7 days'),
  CONSTRAINT passes_uses       CHECK (used_count >= 0 AND used_count <= max_uses AND max_uses BETWEEN 1 AND 50),
  UNIQUE (condominium_id, id)
);
CREATE INDEX passes_lookup_idx ON app.visitor_passes (condominium_id, status, valid_until);
CREATE INDEX passes_unit_idx   ON app.visitor_passes (condominium_id, unit_id, created_at DESC);

CREATE TABLE app.access_requests (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  condominium_id      uuid NOT NULL,
  unit_id             uuid NOT NULL,
  requested_by        uuid NOT NULL,                  -- membership del conserje
  visitor_name        text NOT NULL,
  visitor_national_id text,
  visitor_photo_key   text,                           -- objeto en storage cifrado
  status              app.access_request_status NOT NULL DEFAULT 'PENDIENTE',
  responded_by        uuid,
  responded_at        timestamptz,
  response_note       text,
  expires_at          timestamptz NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (condominium_id, unit_id)      REFERENCES app.units (condominium_id, id)       ON DELETE CASCADE,
  FOREIGN KEY (condominium_id, requested_by) REFERENCES app.memberships (condominium_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (condominium_id, responded_by) REFERENCES app.memberships (condominium_id, id) ON DELETE SET NULL,
  CONSTRAINT access_requests_response_consistent
    CHECK ((status IN ('APROBADA','RECHAZADA')) = (responded_by IS NOT NULL AND responded_at IS NOT NULL)),
  UNIQUE (condominium_id, id)
);
CREATE INDEX access_requests_pending_idx ON app.access_requests (condominium_id, unit_id, status) WHERE status = 'PENDIENTE';

CREATE TABLE app.visits (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  condominium_id      uuid NOT NULL,
  unit_id             uuid NOT NULL,
  pass_id             uuid,
  access_request_id   uuid,
  method              app.visit_method NOT NULL,
  visitor_name        text NOT NULL,
  visitor_national_id text,
  vehicle_plate       text,
  entry_at            timestamptz NOT NULL DEFAULT now(),
  exit_at             timestamptz,
  authorized_by       uuid,          -- residente que autorizó (QR o aprobación remota)
  registered_by       uuid NOT NULL, -- conserje que ejecutó el registro
  entry_photo_key     text,
  notes               text,
  status              app.visit_status NOT NULL DEFAULT 'EN_CURSO',
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (condominium_id, unit_id)           REFERENCES app.units (condominium_id, id)           ON DELETE CASCADE,
  FOREIGN KEY (condominium_id, pass_id)           REFERENCES app.visitor_passes (condominium_id, id)  ON DELETE SET NULL,
  FOREIGN KEY (condominium_id, access_request_id) REFERENCES app.access_requests (condominium_id, id) ON DELETE SET NULL,
  FOREIGN KEY (condominium_id, authorized_by)     REFERENCES app.memberships (condominium_id, id)     ON DELETE SET NULL,
  FOREIGN KEY (condominium_id, registered_by)     REFERENCES app.memberships (condominium_id, id)     ON DELETE RESTRICT,
  CONSTRAINT visits_exit_after_entry CHECK (exit_at IS NULL OR exit_at >= entry_at),
  CONSTRAINT visits_qr_needs_pass    CHECK (method <> 'QR' OR pass_id IS NOT NULL)
);
CREATE INDEX visits_log_idx  ON app.visits (condominium_id, entry_at DESC);
CREATE INDEX visits_unit_idx ON app.visits (condominium_id, unit_id, entry_at DESC);
CREATE INDEX visits_open_idx ON app.visits (condominium_id) WHERE exit_at IS NULL AND status = 'EN_CURSO';

-- ---------------------------------------------------------------------
-- 6. Citofonía
-- ---------------------------------------------------------------------

CREATE TABLE app.calls (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  condominium_id       uuid NOT NULL,
  unit_id              uuid,
  direction            app.call_direction NOT NULL,
  channel              app.call_channel NOT NULL DEFAULT 'WEBRTC_P2P',
  status               app.call_status NOT NULL DEFAULT 'INITIATED',
  initiated_by         uuid,          -- membership; NULL si origen es panel de calle
  answered_by          uuid,
  started_at           timestamptz NOT NULL DEFAULT now(),
  answered_at          timestamptz,
  ended_at             timestamptz,
  duration_seconds     integer GENERATED ALWAYS AS (
                         GREATEST(0, EXTRACT(EPOCH FROM (ended_at - answered_at))::int)
                       ) STORED,
  end_reason           text,
  turn_relayed         boolean NOT NULL DEFAULT false,
  fell_back_to_pstn    boolean NOT NULL DEFAULT false,
  pstn_provider_sid    text,
  pstn_cost_micros     bigint,
  quality              jsonb,        -- MOS, jitter, packet loss reportados por el cliente
  created_at           timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (condominium_id, unit_id)      REFERENCES app.units (condominium_id, id)       ON DELETE SET NULL,
  FOREIGN KEY (condominium_id, initiated_by) REFERENCES app.memberships (condominium_id, id) ON DELETE SET NULL,
  FOREIGN KEY (condominium_id, answered_by)  REFERENCES app.memberships (condominium_id, id) ON DELETE SET NULL,
  CONSTRAINT calls_time_order CHECK (
    (answered_at IS NULL OR answered_at >= started_at) AND
    (ended_at    IS NULL OR ended_at    >= started_at) AND
    (ended_at    IS NULL OR answered_at IS NULL OR ended_at >= answered_at)
  ),
  CONSTRAINT calls_answered_consistent CHECK (status <> 'ANSWERED' OR answered_at IS NOT NULL)
);
CREATE INDEX calls_log_idx  ON app.calls (condominium_id, started_at DESC);
CREATE INDEX calls_unit_idx ON app.calls (condominium_id, unit_id, started_at DESC);

-- Traza de señalización para diagnóstico (NO contiene media ni SDP completo).
CREATE TABLE app.call_events (
  id         bigserial PRIMARY KEY,
  call_id    uuid NOT NULL REFERENCES app.calls(id) ON DELETE CASCADE,
  condominium_id uuid NOT NULL,
  at         timestamptz NOT NULL DEFAULT now(),
  event      text NOT NULL,        -- OFFER_SENT, ANSWER_RECEIVED, ICE_CONNECTED, PSTN_DIALED...
  payload    jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX call_events_call_idx ON app.call_events (call_id, at);

-- ---------------------------------------------------------------------
-- 7. Encomiendas
-- ---------------------------------------------------------------------

CREATE TABLE app.packages (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  condominium_id        uuid NOT NULL,
  unit_id               uuid NOT NULL,
  recipient_membership_id uuid,             -- destinatario identificado (opcional)
  recipient_name_raw    text,               -- nombre tal como viene rotulado
  carrier               text NOT NULL,      -- empresa de transporte
  tracking_code         text,
  description           text,
  photo_key             text,               -- objeto cifrado en storage
  status                app.package_status NOT NULL DEFAULT 'RECIBIDA',
  received_by           uuid NOT NULL,      -- conserje
  received_at           timestamptz NOT NULL DEFAULT now(),
  -- Código de retiro: se entrega al residente por push y sólo se guarda su HMAC.
  pickup_code_hash      bytea,
  pickup_code_expires_at timestamptz,
  delivered_at          timestamptz,
  delivered_by          uuid,               -- conserje que entrega
  delivered_to          uuid,               -- membership que retira
  delivered_to_name     text,               -- si retira un tercero autorizado
  delivery_method       app.delivery_method,
  signature_key         text,               -- imagen de firma digital en storage
  notes                 text,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (condominium_id, unit_id)     REFERENCES app.units (condominium_id, id)       ON DELETE CASCADE,
  FOREIGN KEY (condominium_id, received_by) REFERENCES app.memberships (condominium_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (condominium_id, delivered_by) REFERENCES app.memberships (condominium_id, id) ON DELETE SET NULL,
  FOREIGN KEY (condominium_id, delivered_to) REFERENCES app.memberships (condominium_id, id) ON DELETE SET NULL,
  FOREIGN KEY (condominium_id, recipient_membership_id) REFERENCES app.memberships (condominium_id, id) ON DELETE SET NULL,
  -- Una encomienda ENTREGADA exige prueba de entrega completa.
  CONSTRAINT packages_delivery_complete CHECK (
    status <> 'ENTREGADA' OR (
      delivered_at IS NOT NULL AND delivered_by IS NOT NULL AND delivery_method IS NOT NULL
      AND (delivery_method <> 'FIRMA_DIGITAL' OR signature_key IS NOT NULL)
      AND (delivery_method <> 'AUTORIZADO_TERCERO' OR delivered_to_name IS NOT NULL)
    )
  ),
  CONSTRAINT packages_delivery_after_receipt CHECK (delivered_at IS NULL OR delivered_at >= received_at)
);
-- Inventario en tiempo real: índice parcial sobre lo pendiente de retiro.
CREATE INDEX packages_pending_idx ON app.packages (condominium_id, unit_id, received_at DESC)
  WHERE status IN ('RECIBIDA', 'NOTIFICADA');
CREATE INDEX packages_inventory_idx ON app.packages (condominium_id, status, received_at DESC);
CREATE INDEX packages_tracking_idx  ON app.packages (condominium_id, tracking_code) WHERE tracking_code IS NOT NULL;

CREATE TABLE app.package_events (
  id             bigserial PRIMARY KEY,
  package_id     uuid NOT NULL REFERENCES app.packages(id) ON DELETE CASCADE,
  condominium_id uuid NOT NULL,
  from_status    app.package_status,
  to_status      app.package_status NOT NULL,
  actor_membership_id uuid,
  at             timestamptz NOT NULL DEFAULT now(),
  metadata       jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX package_events_pkg_idx ON app.package_events (package_id, at);

-- ---------------------------------------------------------------------
-- 8. Notificaciones
-- ---------------------------------------------------------------------

CREATE TABLE app.notifications (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  condominium_id      uuid NOT NULL REFERENCES app.condominiums(id) ON DELETE CASCADE,
  user_id             uuid NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
  device_id           uuid REFERENCES app.devices(id) ON DELETE SET NULL,
  kind                text NOT NULL,       -- CALL_INCOMING, PACKAGE_RECEIVED, ACCESS_REQUEST...
  channel             app.notification_channel NOT NULL,
  -- Sin PII en el payload push: sólo identificadores para que la app
  -- consulte el detalle autenticada (evita filtrar datos en la pantalla
  -- de bloqueo y en los servidores de APNs/FCM).
  payload             jsonb NOT NULL DEFAULT '{}'::jsonb,
  status              app.notification_status NOT NULL DEFAULT 'QUEUED',
  provider_message_id text,
  error               text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  sent_at             timestamptz
);
CREATE INDEX notifications_user_idx ON app.notifications (user_id, created_at DESC);
CREATE INDEX notifications_retry_idx ON app.notifications (status, created_at) WHERE status IN ('QUEUED', 'FAILED');

-- ---------------------------------------------------------------------
-- 9. Auditoría inmutable (particionada + encadenamiento de hash)
-- ---------------------------------------------------------------------

CREATE TABLE app.audit_logs (
  id             uuid NOT NULL DEFAULT gen_random_uuid(),
  -- Correlativo estricto por tenant. No se puede confiar en created_at para
  -- ordenar la cadena: now() es constante dentro de una transacción, de modo
  -- que varias entradas emitidas en la misma operación comparten timestamp.
  seq            bigint NOT NULL,
  condominium_id uuid,                       -- NULL = evento de plataforma
  actor_user_id  uuid,
  actor_membership_id uuid,
  actor_role     app.membership_role,
  actor_ip       inet,
  user_agent     text,
  action         text NOT NULL,              -- 'VISITOR_PASS.CREATE', 'PACKAGE.DELIVER'...
  entity_type    text,
  entity_id      uuid,
  before         jsonb,
  after          jsonb,
  request_id     text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  prev_hash      bytea,
  entry_hash     bytea NOT NULL,
  PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE INDEX audit_logs_tenant_idx ON app.audit_logs (condominium_id, created_at DESC);
CREATE INDEX audit_logs_seq_idx    ON app.audit_logs (condominium_id, seq);
CREATE INDEX audit_logs_entity_idx ON app.audit_logs (entity_type, entity_id, created_at DESC);
CREATE INDEX audit_logs_actor_idx  ON app.audit_logs (actor_user_id, created_at DESC);

-- Particiones mensuales (crear por adelantado con pg_partman o un cron job).
CREATE TABLE app.audit_logs_2026_07 PARTITION OF app.audit_logs
  FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE app.audit_logs_2026_08 PARTITION OF app.audit_logs
  FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE app.audit_logs_default PARTITION OF app.audit_logs DEFAULT;

-- Cabeza de cadena por tenant. Existe porque un trigger BEFORE INSERT no
-- puede leer las filas insertadas antes por su MISMA sentencia (usa el
-- snapshot del comando): consultar audit_logs para obtener el hash previo
-- produciría prev_hash duplicados en un INSERT multi-fila. Leer y bloquear
-- esta fila con FOR UPDATE da orden total y exclusión mutua por tenant.
CREATE TABLE app.audit_chain_heads (
  tenant_key uuid PRIMARY KEY,   -- condominium_id, o UUID cero para plataforma
  last_seq   bigint NOT NULL DEFAULT 0,
  last_hash  bytea,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Función canónica de hash: la usan por igual el trigger que escribe y el
-- verificador que audita, de modo que no puedan divergir.
CREATE OR REPLACE FUNCTION app.audit_entry_hash(
  p_prev bytea, p_seq bigint, p_condominium_id uuid, p_actor_user_id uuid,
  p_action text, p_entity_type text, p_entity_id uuid,
  p_before jsonb, p_after jsonb, p_created_at timestamptz)
RETURNS bytea
LANGUAGE sql IMMUTABLE AS $$
  SELECT public.digest(
    COALESCE(p_prev, '\x00'::bytea) ||
    convert_to(
      p_seq::text                        || '|' ||
      COALESCE(p_condominium_id::text,'') || '|' ||
      COALESCE(p_actor_user_id::text, '') || '|' ||
      p_action                            || '|' ||
      COALESCE(p_entity_type, '')         || '|' ||
      COALESCE(p_entity_id::text, '')     || '|' ||
      COALESCE(p_before::text, '')        || '|' ||
      COALESCE(p_after::text, '')         || '|' ||
      p_created_at::text,
      'UTF8'),
    'sha256');
$$;

-- SECURITY DEFINER: la cuenta de la aplicación no tiene permisos sobre
-- audit_chain_heads, así que ni siquiera con ejecución SQL arbitraria puede
-- reescribir la cabeza de la cadena para fabricar un histórico coherente.
CREATE OR REPLACE FUNCTION app.audit_chain() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = app, public, pg_catalog AS $$
DECLARE
  v_key  uuid := COALESCE(NEW.condominium_id, '00000000-0000-0000-0000-000000000000'::uuid);
  v_prev bytea;
  v_seq  bigint;
BEGIN
  INSERT INTO app.audit_chain_heads AS h (tenant_key)
  VALUES (v_key)
  ON CONFLICT (tenant_key) DO UPDATE SET updated_at = now()   -- toma el row lock
  RETURNING h.last_seq, h.last_hash INTO v_seq, v_prev;

  NEW.seq        := v_seq + 1;
  NEW.prev_hash  := v_prev;
  NEW.entry_hash := app.audit_entry_hash(
      v_prev, NEW.seq, NEW.condominium_id, NEW.actor_user_id, NEW.action,
      NEW.entity_type, NEW.entity_id, NEW.before, NEW.after, NEW.created_at);

  UPDATE app.audit_chain_heads
     SET last_seq = NEW.seq, last_hash = NEW.entry_hash, updated_at = now()
   WHERE tenant_key = v_key;

  RETURN NEW;
END;
$$;

CREATE TRIGGER audit_logs_chain
  BEFORE INSERT ON app.audit_logs
  FOR EACH ROW EXECUTE FUNCTION app.audit_chain();

-- Append-only: ni siquiera el dueño de la tabla puede alterar el histórico.
CREATE OR REPLACE FUNCTION app.deny_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs es append-only: % denegado', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_logs_no_update
  BEFORE UPDATE OR DELETE ON app.audit_logs
  FOR EACH ROW EXECUTE FUNCTION app.deny_mutation();

-- Verificador de integridad (job diario). Recalcula cada entry_hash además
-- de comprobar el enlace: así detecta no sólo la eliminación de una entrada,
-- sino también la alteración de cualquier campo de una entrada existente.
CREATE OR REPLACE FUNCTION app.verify_audit_chain(
  p_condominium_id uuid, p_since timestamptz DEFAULT '-infinity')
RETURNS TABLE (entry_id uuid, entry_seq bigint, broken_at timestamptz, reason text)
LANGUAGE sql STABLE AS $$
  WITH ordered AS (
    SELECT a.id, a.seq, a.created_at, a.prev_hash, a.entry_hash,
           app.audit_entry_hash(a.prev_hash, a.seq, a.condominium_id, a.actor_user_id,
                                a.action, a.entity_type, a.entity_id, a.before,
                                a.after, a.created_at) AS recomputed,
           LAG(a.entry_hash) OVER (ORDER BY a.seq) AS expected_prev,
           LAG(a.seq)        OVER (ORDER BY a.seq) AS prior_seq
    FROM app.audit_logs a
    WHERE a.condominium_id IS NOT DISTINCT FROM p_condominium_id
      AND a.created_at >= p_since
  )
  SELECT id, seq, created_at,
         CASE
           WHEN entry_hash IS DISTINCT FROM recomputed          THEN 'entrada alterada'
           WHEN prior_seq IS NOT NULL AND seq <> prior_seq + 1  THEN 'correlativo faltante'
           ELSE 'enlace roto con la entrada previa'
         END
  FROM ordered
  WHERE entry_hash IS DISTINCT FROM recomputed
     OR (prior_seq IS NOT NULL AND seq <> prior_seq + 1)
     OR (expected_prev IS NOT NULL AND prev_hash IS DISTINCT FROM expected_prev);
$$;

-- ---------------------------------------------------------------------
-- 10. Triggers updated_at
-- ---------------------------------------------------------------------

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'condominiums','buildings','units','users','memberships','unit_residents',
    'devices','visitor_passes','access_requests','visits','packages'
  ] LOOP
    EXECUTE format(
      'CREATE TRIGGER %I_touch BEFORE UPDATE ON app.%I
         FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at()', t, t);
  END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- 11. Roles de base de datos y Row Level Security
-- ---------------------------------------------------------------------

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'citofonia_app') THEN
    CREATE ROLE citofonia_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'citofonia_auditor') THEN
    CREATE ROLE citofonia_auditor NOLOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA app TO citofonia_app, citofonia_auditor;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO citofonia_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO citofonia_app;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO citofonia_auditor;

-- La aplicación NUNCA puede modificar la auditoría, sólo agregar.
REVOKE UPDATE, DELETE, TRUNCATE ON app.audit_logs FROM citofonia_app;
REVOKE UPDATE, DELETE, TRUNCATE ON app.audit_logs_2026_07, app.audit_logs_2026_08, app.audit_logs_default FROM citofonia_app;
-- La cabeza de cadena sólo la manipula el trigger (SECURITY DEFINER).
REVOKE ALL ON app.audit_chain_heads FROM citofonia_app, citofonia_auditor;

-- RLS en toda tabla con condominium_id. FORCE se aplica para que ni el
-- dueño de la tabla eluda la política si alguna vez se conecta con él.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'buildings','units','memberships','unit_residents','visitor_passes',
    'access_requests','visits','calls','call_events','packages',
    'package_events','notifications','audit_logs'
  ] LOOP
    EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON app.%I
         USING (condominium_id = app.current_condominium_id())
         WITH CHECK (condominium_id = app.current_condominium_id())', t);
  END LOOP;
END $$;

-- condominiums: cada tenant sólo se ve a sí mismo.
ALTER TABLE app.condominiums ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.condominiums FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app.condominiums
  USING (id = app.current_condominium_id())
  WITH CHECK (id = app.current_condominium_id());

-- users es global: un usuario sólo se ve a sí mismo o a quienes comparten
-- condominio activo con él.
ALTER TABLE app.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.users FORCE ROW LEVEL SECURITY;
CREATE POLICY user_self_or_cotenant ON app.users
  USING (
    id = app.current_user_id()
    OR EXISTS (
      SELECT 1 FROM app.memberships m
      WHERE m.user_id = app.users.id
        AND m.condominium_id = app.current_condominium_id()
        AND m.status = 'ACTIVE'
    )
  )
  WITH CHECK (id = app.current_user_id());

-- devices y refresh_tokens: estrictamente del propio usuario.
ALTER TABLE app.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.devices FORCE ROW LEVEL SECURITY;
CREATE POLICY device_owner ON app.devices
  USING (user_id = app.current_user_id())
  WITH CHECK (user_id = app.current_user_id());

ALTER TABLE app.refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY refresh_token_owner ON app.refresh_tokens
  USING (user_id = app.current_user_id())
  WITH CHECK (user_id = app.current_user_id());

-- membership_roles no tiene condominium_id propio: se filtra vía membresía.
ALTER TABLE app.membership_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.membership_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY membership_roles_tenant ON app.membership_roles
  USING (EXISTS (
    SELECT 1 FROM app.memberships m
    WHERE m.id = membership_roles.membership_id
      AND m.condominium_id = app.current_condominium_id()));

-- La auditoría es sólo-lectura filtrada e insertable por la app.
CREATE POLICY audit_insert ON app.audit_logs FOR INSERT
  WITH CHECK (condominium_id = app.current_condominium_id());

COMMIT;

-- =====================================================================
--  Matriz RBAC — mínimo privilegio
--  ADMIN     = gestión y lectura del condominio; NO opera la conserjería.
--  CONSERJE  = operación diaria; NO lee auditoría ni gestiona miembros.
--  RESIDENTE = alcance limitado a SU unidad.
--  VISITA    = sólo consulta su propio pase mediante token firmado.
-- =====================================================================

BEGIN;

INSERT INTO app.permissions (code, description) VALUES
  ('condominium.read',              'Ver datos del condominio'),
  ('condominium.update',            'Editar configuración del condominio'),
  ('unit.read',                     'Listar unidades'),
  ('unit.manage',                   'Crear/editar/desactivar unidades'),
  ('member.read',                   'Listar miembros del condominio'),
  ('member.invite',                 'Invitar residentes y conserjes'),
  ('member.revoke',                 'Revocar membresías y roles'),
  ('pass.create.own_unit',          'Emitir pases QR para la propia unidad'),
  ('pass.read.own_unit',            'Ver pases emitidos por la propia unidad'),
  ('pass.revoke.own_unit',          'Revocar pases de la propia unidad'),
  ('pass.read.condominium',         'Ver todos los pases del condominio'),
  ('pass.validate',                 'Escanear y canjear pases QR en portería'),
  ('visit.create',                  'Registrar ingreso de visita'),
  ('visit.close',                   'Registrar salida de visita'),
  ('visit.read.own_unit',           'Ver bitácora de visitas de la propia unidad'),
  ('visit.read.condominium',        'Ver bitácora completa de visitas'),
  ('access_request.create',         'Solicitar autorización de ingreso al residente'),
  ('access_request.respond.own_unit','Aprobar o rechazar ingresos a la propia unidad'),
  ('access_request.read.condominium','Ver solicitudes de ingreso del condominio'),
  ('call.initiate.concierge',       'Llamar desde conserjería a una unidad'),
  ('call.initiate.resident',        'Llamar desde la unidad a conserjería'),
  ('call.answer.own_unit',          'Contestar llamadas dirigidas a la propia unidad'),
  ('call.read.own',                 'Ver historial de llamadas propias'),
  ('call.read.condominium',         'Ver historial completo de llamadas'),
  ('package.create',                'Registrar recepción de encomienda'),
  ('package.deliver',               'Registrar entrega de encomienda'),
  ('package.update',                'Corregir datos de una encomienda'),
  ('package.read.own_unit',         'Ver encomiendas de la propia unidad'),
  ('package.read.condominium',      'Ver inventario completo de encomiendas'),
  ('audit.read.condominium',        'Consultar logs de auditoría del condominio'),
  ('report.export.condominium',     'Exportar reportes e inventarios');

INSERT INTO app.role_permissions (role, permission_code) VALUES
  -- ADMIN
  ('ADMIN','condominium.read'), ('ADMIN','condominium.update'),
  ('ADMIN','unit.read'), ('ADMIN','unit.manage'),
  ('ADMIN','member.read'), ('ADMIN','member.invite'), ('ADMIN','member.revoke'),
  ('ADMIN','pass.read.condominium'),
  ('ADMIN','visit.read.condominium'),
  ('ADMIN','access_request.read.condominium'),
  ('ADMIN','call.read.condominium'),
  ('ADMIN','package.read.condominium'), ('ADMIN','package.update'),
  ('ADMIN','audit.read.condominium'), ('ADMIN','report.export.condominium'),
  -- CONSERJE
  ('CONSERJE','condominium.read'), ('CONSERJE','unit.read'), ('CONSERJE','member.read'),
  ('CONSERJE','pass.validate'), ('CONSERJE','pass.read.condominium'),
  ('CONSERJE','visit.create'), ('CONSERJE','visit.close'), ('CONSERJE','visit.read.condominium'),
  ('CONSERJE','access_request.create'), ('CONSERJE','access_request.read.condominium'),
  ('CONSERJE','call.initiate.concierge'), ('CONSERJE','call.read.own'),
  ('CONSERJE','package.create'), ('CONSERJE','package.deliver'), ('CONSERJE','package.read.condominium'),
  -- RESIDENTE
  ('RESIDENTE','condominium.read'),
  ('RESIDENTE','pass.create.own_unit'), ('RESIDENTE','pass.read.own_unit'), ('RESIDENTE','pass.revoke.own_unit'),
  ('RESIDENTE','visit.read.own_unit'),
  ('RESIDENTE','access_request.respond.own_unit'),
  ('RESIDENTE','call.initiate.resident'), ('RESIDENTE','call.answer.own_unit'), ('RESIDENTE','call.read.own'),
  ('RESIDENTE','package.read.own_unit'),
  -- VISITA (cuenta efímera, sin acceso a datos del condominio)
  ('VISITA','pass.read.own_unit');

COMMIT;
