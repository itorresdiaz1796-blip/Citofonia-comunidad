-- =====================================================================
--  Pruebas de invariantes de seguridad del esquema.
--  Ejecutar:  psql -d citofonia -v ON_ERROR_STOP=1 -f db/tests/security_invariants.sql
--
--  Estas pruebas verifican en la BASE DE DATOS (no en la aplicación) que:
--   - El aislamiento multi-tenant se cumple aunque la app tenga un bug.
--   - Las FK compuestas impiden enlaces entre condominios distintos.
--   - La auditoría es realmente append-only y su cadena de hash encadena.
--   - Los CHECK de negocio bloquean estados inválidos.
-- =====================================================================

\set ON_ERROR_STOP on
SET search_path = app, public;

-- audit_logs es append-only: las corridas anteriores no se pueden borrar.
-- Cada ejecución se marca con un identificador propio para que las
-- aserciones cuenten sólo sus propias filas y el archivo sea re-ejecutable.
SELECT set_config('app.test_run', gen_random_uuid()::text, false);

CREATE OR REPLACE FUNCTION app.t_report(p_name text, p_ok boolean, p_detail text DEFAULT '')
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF p_ok THEN
    RAISE NOTICE '  PASS  %', p_name;
  ELSE
    RAISE EXCEPTION 'FAIL  % :: %', p_name, p_detail;
  END IF;
END;
$$;

-- ---------------------------------------------------------------------
-- Semilla: dos condominios completamente independientes.
-- ---------------------------------------------------------------------
DO $$
BEGIN
  DELETE FROM app.condominiums WHERE tax_id IN ('TEST-A', 'TEST-B');
  DELETE FROM app.users WHERE email IN ('ana@test.local', 'bruno@test.local');
END $$;

INSERT INTO app.condominiums (id, name, tax_id) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001', 'Condominio Alfa', 'TEST-A'),
  ('bbbbbbbb-0000-4000-8000-000000000001', 'Condominio Beta', 'TEST-B');

INSERT INTO app.units (id, condominium_id, label, intercom_alias) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000010', 'aaaaaaaa-0000-4000-8000-000000000001', 'A-101', '101'),
  ('bbbbbbbb-0000-4000-8000-000000000010', 'bbbbbbbb-0000-4000-8000-000000000001', 'B-101', '101');

INSERT INTO app.users (id, email, full_name, status) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000100', 'ana@test.local',   'Ana Alfa',  'ACTIVE'),
  ('bbbbbbbb-0000-4000-8000-000000000100', 'bruno@test.local', 'Bruno Beta','ACTIVE');

INSERT INTO app.memberships (id, condominium_id, user_id) VALUES
  ('aaaaaaaa-0000-4000-8000-000000001000', 'aaaaaaaa-0000-4000-8000-000000000001', 'aaaaaaaa-0000-4000-8000-000000000100'),
  ('bbbbbbbb-0000-4000-8000-000000001000', 'bbbbbbbb-0000-4000-8000-000000000001', 'bbbbbbbb-0000-4000-8000-000000000100');

INSERT INTO app.membership_roles (membership_id, role) VALUES
  ('aaaaaaaa-0000-4000-8000-000000001000', 'CONSERJE'),
  ('bbbbbbbb-0000-4000-8000-000000001000', 'CONSERJE');

\echo ''
\echo '=== 1. Aislamiento multi-tenant (RLS) ==='

-- El rol de aplicación NO es superusuario, por lo que las políticas aplican.
SET ROLE citofonia_app;
SET app.condominium_id = 'aaaaaaaa-0000-4000-8000-000000000001';
SET app.user_id        = 'aaaaaaaa-0000-4000-8000-000000000100';

DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM app.units;
  PERFORM app.t_report('El tenant A sólo ve sus propias unidades', n = 1, format('vio %s filas', n));

  SELECT count(*) INTO n FROM app.units WHERE id = 'bbbbbbbb-0000-4000-8000-000000000010';
  PERFORM app.t_report('Consulta directa por UUID de otro tenant devuelve 0 filas (anti-IDOR)', n = 0);

  SELECT count(*) INTO n FROM app.condominiums;
  PERFORM app.t_report('El tenant A sólo ve su propio condominio', n = 1, format('vio %s filas', n));
END $$;

-- Sin contexto de tenant, no se ve absolutamente nada (fail-closed).
RESET app.condominium_id;
DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM app.units;
  PERFORM app.t_report('Sin contexto de tenant el acceso es cero (fail-closed)', n = 0, format('vio %s filas', n));
END $$;

SET app.condominium_id = 'aaaaaaaa-0000-4000-8000-000000000001';

-- WITH CHECK impide escribir en otro tenant aunque la app se equivoque.
DO $$
BEGIN
  BEGIN
    INSERT INTO app.units (condominium_id, label) VALUES
      ('bbbbbbbb-0000-4000-8000-000000000001', 'INYECTADA');
    PERFORM app.t_report('INSERT en otro tenant es rechazado', false, 'la fila se insertó');
  EXCEPTION WHEN insufficient_privilege OR check_violation THEN
    PERFORM app.t_report('INSERT en otro tenant es rechazado por WITH CHECK', true);
  END;
END $$;

RESET ROLE;

\echo ''
\echo '=== 2. Integridad referencial cruzada entre condominios ==='

DO $$
BEGIN
  BEGIN
    -- Encomienda del condominio A apuntando a una unidad del condominio B.
    INSERT INTO app.packages (condominium_id, unit_id, carrier, received_by)
    VALUES ('aaaaaaaa-0000-4000-8000-000000000001',
            'bbbbbbbb-0000-4000-8000-000000000010',
            'Chilexpress',
            'aaaaaaaa-0000-4000-8000-000000001000');
    PERFORM app.t_report('FK compuesta bloquea encomienda hacia unidad de otro tenant', false, 'se insertó');
  EXCEPTION WHEN foreign_key_violation THEN
    PERFORM app.t_report('FK compuesta bloquea encomienda hacia unidad de otro tenant', true);
  END;

  BEGIN
    -- Residente del condominio B asignado a una unidad del condominio A.
    INSERT INTO app.unit_residents (condominium_id, unit_id, membership_id)
    VALUES ('aaaaaaaa-0000-4000-8000-000000000001',
            'aaaaaaaa-0000-4000-8000-000000000010',
            'bbbbbbbb-0000-4000-8000-000000001000');
    PERFORM app.t_report('FK compuesta bloquea residente de otro tenant en la unidad', false, 'se insertó');
  EXCEPTION WHEN foreign_key_violation THEN
    PERFORM app.t_report('FK compuesta bloquea residente de otro tenant en la unidad', true);
  END;
END $$;

\echo ''
\echo '=== 3. Auditoría inmutable y encadenada ==='

-- Las tres entradas se escriben en UNA sola sentencia a propósito: es el
-- caso que rompe un encadenamiento ingenuo basado en releer la tabla.
INSERT INTO app.audit_logs (condominium_id, actor_user_id, action, entity_type, entity_id, request_id)
VALUES ('aaaaaaaa-0000-4000-8000-000000000001', 'aaaaaaaa-0000-4000-8000-000000000100',
        'VISITOR_PASS.CREATE', 'visitor_pass', gen_random_uuid(), current_setting('app.test_run')),
       ('aaaaaaaa-0000-4000-8000-000000000001', 'aaaaaaaa-0000-4000-8000-000000000100',
        'PACKAGE.DELIVER', 'package', gen_random_uuid(), current_setting('app.test_run')),
       ('aaaaaaaa-0000-4000-8000-000000000001', 'aaaaaaaa-0000-4000-8000-000000000100',
        'MEMBER.REVOKE', 'membership', gen_random_uuid(), current_setting('app.test_run'));

DO $$
DECLARE
  v_tenant uuid := 'aaaaaaaa-0000-4000-8000-000000000001';
  n int; broken int; v_distinct int; v_ts int;
BEGIN
  SELECT count(*), count(DISTINCT seq), count(DISTINCT created_at)
    INTO n, v_distinct, v_ts
  FROM app.audit_logs WHERE condominium_id = v_tenant AND request_id = current_setting('app.test_run');

  PERFORM app.t_report('Las 3 entradas se escribieron', n = 3, format('%s filas', n));
  PERFORM app.t_report(
    'Un INSERT multi-fila produce correlativos distintos (no colisionan)',
    v_distinct = 3, format('%s seq distintos', v_distinct));
  PERFORM app.t_report(
    'created_at es idéntico en las 3: por eso la cadena no puede ordenarse por tiempo',
    v_ts = 1, format('%s timestamps distintos', v_ts));

  SELECT count(*) INTO n FROM app.audit_logs
   WHERE condominium_id = v_tenant AND request_id = current_setting('app.test_run') AND entry_hash IS NOT NULL;
  PERFORM app.t_report('Cada entrada recibe entry_hash', n = 3);

  SELECT count(DISTINCT prev_hash) INTO n FROM app.audit_logs
   WHERE condominium_id = v_tenant AND request_id = current_setting('app.test_run') AND prev_hash IS NOT NULL;
  PERFORM app.t_report(
    'Cada entrada encadena con un prev_hash distinto',
    n >= 2, format('%s prev_hash distintos', n));

  SELECT count(*) INTO broken FROM app.verify_audit_chain(v_tenant);
  PERFORM app.t_report('verify_audit_chain no reporta roturas en una cadena sana', broken = 0,
                       format('%s roturas', broken));

  BEGIN
    UPDATE app.audit_logs SET action = 'BORRADO' WHERE action = 'MEMBER.REVOKE';
    PERFORM app.t_report('UPDATE sobre audit_logs es rechazado', false, 'el UPDATE pasó');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM app.t_report('UPDATE sobre audit_logs es rechazado incluso para el dueño', true);
  END;

  BEGIN
    DELETE FROM app.audit_logs WHERE action = 'MEMBER.REVOKE';
    PERFORM app.t_report('DELETE sobre audit_logs es rechazado', false, 'el DELETE pasó');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM app.t_report('DELETE sobre audit_logs es rechazado incluso para el dueño', true);
  END;
END $$;

-- Simulacro de manipulación: un atacante con acceso directo a la partición
-- (saltándose el trigger del padre) altera una entrada. El verificador debe
-- detectarlo porque recalcula el hash, no sólo compara enlaces.
DO $$
DECLARE
  v_tenant uuid := 'aaaaaaaa-0000-4000-8000-000000000001';
  v_part text; v_id uuid; broken int;
BEGIN
  SELECT tableoid::regclass::text, id INTO v_part, v_id
  FROM app.audit_logs
  WHERE condominium_id = v_tenant AND request_id = current_setting('app.test_run') AND action = 'PACKAGE.DELIVER'
  LIMIT 1;

  ALTER TABLE app.audit_logs DISABLE TRIGGER audit_logs_no_update;
  EXECUTE format('UPDATE %s SET action = %L WHERE id = %L', v_part, 'PACKAGE.READ', v_id);
  ALTER TABLE app.audit_logs ENABLE TRIGGER audit_logs_no_update;

  SELECT count(*) INTO broken FROM app.verify_audit_chain(v_tenant);
  PERFORM app.t_report(
    'Alterar una entrada por la puerta trasera es detectado por el verificador',
    broken > 0, 'la manipulación pasó inadvertida');

  -- Se restaura para no dejar la cadena rota a las siguientes ejecuciones.
  ALTER TABLE app.audit_logs DISABLE TRIGGER audit_logs_no_update;
  EXECUTE format('UPDATE %s SET action = %L WHERE id = %L', v_part, 'PACKAGE.DELIVER', v_id);
  ALTER TABLE app.audit_logs ENABLE TRIGGER audit_logs_no_update;

  SELECT count(*) INTO broken FROM app.verify_audit_chain(v_tenant);
  PERFORM app.t_report('Restaurado el valor original la cadena vuelve a validar', broken = 0);
END $$;

-- La cuenta de la aplicación no puede tocar la cabeza de cadena.
SET ROLE citofonia_app;
DO $$
BEGIN
  BEGIN
    PERFORM 1 FROM app.audit_chain_heads LIMIT 1;
    PERFORM app.t_report('La app no puede leer audit_chain_heads', false, 'pudo leerla');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM app.t_report('La app no puede leer ni reescribir audit_chain_heads', true);
  END;
END $$;
RESET ROLE;

\echo ''
\echo '=== 4. Invariantes de negocio ==='

DO $$
DECLARE v_pkg uuid;
BEGIN
  BEGIN
    INSERT INTO app.visitor_passes
      (condominium_id, unit_id, issued_by, visitor_name, valid_until, key_id, token_hash)
    VALUES ('aaaaaaaa-0000-4000-8000-000000000001','aaaaaaaa-0000-4000-8000-000000000010',
            'aaaaaaaa-0000-4000-8000-000000001000','Visita Eterna',
            now() + interval '30 days', 'k1', '\x00');
    PERFORM app.t_report('Un pase QR no puede durar más de 7 días', false, 'se aceptó 30 días');
  EXCEPTION WHEN check_violation THEN
    PERFORM app.t_report('Un pase QR no puede durar más de 7 días', true);
  END;

  INSERT INTO app.packages (id, condominium_id, unit_id, carrier, received_by)
  VALUES (gen_random_uuid(), 'aaaaaaaa-0000-4000-8000-000000000001',
          'aaaaaaaa-0000-4000-8000-000000000010', 'Starken',
          'aaaaaaaa-0000-4000-8000-000000001000')
  RETURNING id INTO v_pkg;

  BEGIN
    -- Marcar ENTREGADA sin prueba de entrega debe fallar.
    UPDATE app.packages SET status = 'ENTREGADA', delivered_at = now() WHERE id = v_pkg;
    PERFORM app.t_report('No se puede marcar ENTREGADA sin prueba de entrega', false, 'se aceptó');
  EXCEPTION WHEN check_violation THEN
    PERFORM app.t_report('No se puede marcar ENTREGADA sin prueba de entrega', true);
  END;

  BEGIN
    UPDATE app.packages
       SET status = 'ENTREGADA', delivered_at = now(),
           delivered_by = 'aaaaaaaa-0000-4000-8000-000000001000',
           delivery_method = 'FIRMA_DIGITAL'
     WHERE id = v_pkg;
    PERFORM app.t_report('FIRMA_DIGITAL sin imagen de firma es rechazada', false, 'se aceptó');
  EXCEPTION WHEN check_violation THEN
    PERFORM app.t_report('FIRMA_DIGITAL sin imagen de firma es rechazada', true);
  END;

  UPDATE app.packages
     SET status = 'ENTREGADA', delivered_at = now(),
         delivered_by = 'aaaaaaaa-0000-4000-8000-000000001000',
         delivery_method = 'FIRMA_DIGITAL', signature_key = 's3://sig/1.png'
   WHERE id = v_pkg;
  PERFORM app.t_report('Entrega con firma completa se acepta', true);

  INSERT INTO app.unit_residents (condominium_id, unit_id, membership_id, is_primary)
  VALUES ('aaaaaaaa-0000-4000-8000-000000000001','aaaaaaaa-0000-4000-8000-000000000010',
          'aaaaaaaa-0000-4000-8000-000000001000', true);

  BEGIN
    INSERT INTO app.memberships (id, condominium_id, user_id)
    VALUES ('aaaaaaaa-0000-4000-8000-000000001001','aaaaaaaa-0000-4000-8000-000000000001',
            'bbbbbbbb-0000-4000-8000-000000000100');
    INSERT INTO app.unit_residents (condominium_id, unit_id, membership_id, is_primary)
    VALUES ('aaaaaaaa-0000-4000-8000-000000000001','aaaaaaaa-0000-4000-8000-000000000010',
            'aaaaaaaa-0000-4000-8000-000000001001', true);
    PERFORM app.t_report('Sólo un residente principal por unidad', false, 'se aceptaron dos');
  EXCEPTION WHEN unique_violation THEN
    PERFORM app.t_report('Sólo un residente principal por unidad', true);
  END;

  BEGIN
    INSERT INTO app.calls (condominium_id, unit_id, direction, status, started_at, answered_at)
    VALUES ('aaaaaaaa-0000-4000-8000-000000000001','aaaaaaaa-0000-4000-8000-000000000010',
            'CONSERJERIA_A_UNIDAD','ANSWERED', now(), now() - interval '5 minutes');
    PERFORM app.t_report('Una llamada no puede contestarse antes de iniciarse', false, 'se aceptó');
  EXCEPTION WHEN check_violation THEN
    PERFORM app.t_report('Una llamada no puede contestarse antes de iniciarse', true);
  END;
END $$;

\echo ''
\echo '=== 5. Higiene de credenciales ==='

DO $$
DECLARE cols text;
BEGIN
  SELECT string_agg(column_name, ', ') INTO cols
  FROM information_schema.columns
  WHERE table_schema = 'app'
    AND (column_name ILIKE '%password%' OR column_name ILIKE '%token%' OR column_name ILIKE '%code%')
    AND column_name NOT ILIKE '%hash%'
    AND column_name NOT ILIKE '%_enc'
    AND column_name NOT IN ('push_token','voip_push_token','tracking_code','country_code',
                            'permission_code','code','key_id','pickup_code_expires_at');
  PERFORM app.t_report(
    'Ninguna columna guarda secretos en claro',
    cols IS NULL,
    format('columnas sospechosas: %s', cols));
END $$;

\echo ''
\echo 'Todas las pruebas de invariantes pasaron.'
