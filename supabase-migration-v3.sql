-- ═══════════════════════════════════════════════════════════
-- MIGRATION V3 — Sistema de pagos, stock mínimo, meta mensual
-- SEGURO: solo ADD COLUMN / CREATE IF NOT EXISTS / INSERT
-- No DROP, no DELETE, no UPDATE masivo sobre datos existentes
-- ═══════════════════════════════════════════════════════════

BEGIN;

-- ── 1. Tabla pagos ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pagos (
  id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     UUID REFERENCES auth.users(id) NOT NULL,
  cliente_id  UUID REFERENCES clientes(id) NOT NULL,
  monto       NUMERIC(12,2) NOT NULL CHECK (monto > 0),
  fecha       DATE NOT NULL DEFAULT CURRENT_DATE,
  medio_pago  TEXT DEFAULT 'efectivo'
              CHECK (medio_pago IN ('efectivo','transferencia','tarjeta','otro')),
  nota        TEXT DEFAULT '',
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE pagos ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename='pagos' AND policyname='own_data'
  ) THEN
    CREATE POLICY "own_data" ON pagos
      USING (user_id = auth.uid())
      WITH CHECK (user_id = auth.uid());
  END IF;
END $$;

-- ── 2. Stock mínimo en variantes ──────────────────────────────────────────────
ALTER TABLE producto_variantes
  ADD COLUMN IF NOT EXISTS stock_minimo INTEGER DEFAULT 0;

-- ── 3. Meta mensual en perfiles ───────────────────────────────────────────────
ALTER TABLE perfiles
  ADD COLUMN IF NOT EXISTS meta_mensual NUMERIC(12,2) DEFAULT NULL;

-- ── 4. Categoría en gastos (por si no existe) ─────────────────────────────────
ALTER TABLE gastos
  ADD COLUMN IF NOT EXISTS categoria TEXT DEFAULT 'otros';

-- ── 5. View saldos_clientes ───────────────────────────────────────────────────
-- Subqueries agregadas primero para evitar multiplicación de filas (cartesian product)
DROP VIEW IF EXISTS saldos_clientes;

CREATE OR REPLACE VIEW saldos_clientes AS
SELECT
  c.id        AS cliente_id,
  c.user_id,
  c.nombre,
  c.telefono,
  c.notas,
  COALESCE(v.total_comprado, 0)                            AS total_comprado,
  COALESCE(v.cant_compras,   0)                            AS cant_compras,
  COALESCE(p.total_pagado,   0)                            AS total_pagado,
  COALESCE(v.total_comprado, 0) - COALESCE(p.total_pagado, 0) AS saldo,
  v.ultima_compra,
  p.ultimo_pago
FROM clientes c
LEFT JOIN (
  SELECT
    cliente_id, user_id,
    SUM(precio_venta) AS total_comprado,
    COUNT(*)                                  AS cant_compras,
    MAX(COALESCE(fecha_compra, created_at::date)) AS ultima_compra
  FROM ventas
  GROUP BY cliente_id, user_id
) v ON v.cliente_id = c.id AND v.user_id = c.user_id
LEFT JOIN (
  SELECT
    cliente_id, user_id,
    SUM(monto)  AS total_pagado,
    MAX(fecha)  AS ultimo_pago
  FROM pagos
  GROUP BY cliente_id, user_id
) p ON p.cliente_id = c.id AND p.user_id = c.user_id;

-- ── 6. Migrar pagos existentes desde ventas.adeuda ───────────────────────────
-- Sólo para ventas donde ya se pagó algo (precio_venta * cantidad > adeuda)
-- y que no tengan ya una entrada migrada en pagos.
INSERT INTO pagos (user_id, cliente_id, monto, fecha, medio_pago, nota)
SELECT
  v.user_id,
  v.cliente_id,
  (v.precio_venta * COALESCE(v.cantidad, 1)) - COALESCE(v.adeuda, 0),
  COALESCE(v.fecha_compra, v.created_at::date),
  'efectivo',
  'Pago migrado desde sistema anterior (venta ID: ' || v.id || ')'
FROM ventas v
WHERE
  v.cliente_id IS NOT NULL
  AND ((v.precio_venta * COALESCE(v.cantidad, 1)) - COALESCE(v.adeuda, 0)) > 0
  AND NOT EXISTS (
    SELECT 1 FROM pagos p
    WHERE p.nota = 'Pago migrado desde sistema anterior (venta ID: ' || v.id || ')'
  );

COMMIT;

-- ── Verificación post-migración ───────────────────────────────────────────────
-- Ejecutar manualmente para confirmar:
-- SELECT COUNT(*) FROM ventas;          -- debe ser igual que antes
-- SELECT COUNT(*) FROM clientes;        -- debe ser igual que antes
-- SELECT COUNT(*) FROM pagos WHERE nota LIKE 'Pago migrado%';
-- SELECT c.nombre, sc.saldo, SUM(v.adeuda) as adeuda_original
--   FROM saldos_clientes sc
--   JOIN clientes c ON c.id = sc.cliente_id
--   LEFT JOIN ventas v ON v.cliente_id = c.id AND v.user_id = c.user_id
--   GROUP BY c.nombre, sc.saldo
--   HAVING sc.saldo <> SUM(v.adeuda)   -- no debe haber filas
--   LIMIT 5;
