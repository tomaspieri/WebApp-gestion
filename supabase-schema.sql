-- =============================================================================
-- CHANA Gestión — Schema Supabase
-- Ejecutar en: Supabase Dashboard → SQL Editor → New query
-- Si ya existían tablas de una versión anterior, este script las recrea desde cero.
-- =============================================================================

-- DROP en orden correcto (foreign keys)
DROP TABLE IF EXISTS contadores          CASCADE;
DROP TABLE IF EXISTS ventas_online       CASCADE;
DROP TABLE IF EXISTS producto_variantes  CASCADE;
DROP TABLE IF EXISTS productos           CASCADE;
DROP TABLE IF EXISTS ventas              CASCADE;
DROP TABLE IF EXISTS gastos              CASCADE;
DROP TABLE IF EXISTS clientes            CASCADE;
DROP TABLE IF EXISTS mp_conexiones       CASCADE;
DROP TABLE IF EXISTS perfiles            CASCADE;
DROP TABLE IF EXISTS rate_limits         CASCADE;

-- PERFILES
CREATE TABLE perfiles (
  id         UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  nombre     TEXT DEFAULT '',
  rol        TEXT DEFAULT 'usuario' CHECK (rol IN ('admin', 'usuario')),
  activo     BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- CONEXIÓN MERCADOPAGO por usuario (tokens encriptados AES-256-GCM)
CREATE TABLE mp_conexiones (
  id                      UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id                 UUID REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE,
  mp_user_id              TEXT,
  access_token_encrypted  TEXT,
  refresh_token_encrypted TEXT,
  expires_at              TIMESTAMPTZ,
  conectado               BOOLEAN DEFAULT false,
  tienda_url              TEXT DEFAULT '',
  tienda_nombre           TEXT DEFAULT '',
  vercel_deploy_hook      TEXT DEFAULT '',
  mp_last_sync            TIMESTAMPTZ,
  updated_at              TIMESTAMPTZ DEFAULT NOW()
);

-- CLIENTES
CREATE TABLE clientes (
  id         UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id    UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  nombre     TEXT NOT NULL,
  telefono   TEXT DEFAULT '',
  notas      TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- VENTAS
CREATE TABLE ventas (
  id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id         UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  cliente_id      UUID REFERENCES clientes(id),
  prenda          TEXT NOT NULL,
  precio_venta    DECIMAL(12,2) DEFAULT 0,
  costo           DECIMAL(12,2) DEFAULT 0,
  pagado          DECIMAL(12,2) DEFAULT 0,
  adeuda          DECIMAL(12,2) DEFAULT 0,
  cantidad        INTEGER DEFAULT 1,
  precio_unitario DECIMAL(12,2) DEFAULT 0,
  costo_unitario  DECIMAL(12,2) DEFAULT 0,
  fecha_compra    DATE,
  prox_cuota      DATE,
  notas           TEXT DEFAULT '',
  numero_venta    INTEGER,
  notificado_at   DATE,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- GASTOS
CREATE TABLE gastos (
  id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id         UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  descripcion     TEXT NOT NULL,
  monto           DECIMAL(12,2) DEFAULT 0,
  fecha           DATE,
  categoria       TEXT DEFAULT '',
  notas           TEXT DEFAULT '',
  cantidad        INTEGER DEFAULT 1,
  precio_unitario DECIMAL(12,2) DEFAULT 0,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- PRODUCTOS
CREATE TABLE productos (
  id             UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id        UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  nombre         TEXT NOT NULL,
  categoria      TEXT DEFAULT '',
  precio         DECIMAL(12,2) DEFAULT 0,
  costo          DECIMAL(12,2) DEFAULT 0,
  imagen_url     TEXT DEFAULT '',
  imagenes       JSONB DEFAULT '[]',
  descripcion    TEXT DEFAULT '',
  guia_de_talles TEXT DEFAULT '',
  peso           INTEGER DEFAULT 0,
  dimensiones    TEXT DEFAULT '',
  nuevo          BOOLEAN DEFAULT false,
  activo         BOOLEAN DEFAULT true,
  created_at     TIMESTAMPTZ DEFAULT NOW(),
  updated_at     TIMESTAMPTZ DEFAULT NOW()
);

-- VARIANTES
CREATE TABLE producto_variantes (
  id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  producto_id UUID REFERENCES productos(id) ON DELETE CASCADE NOT NULL,
  tipo        TEXT NOT NULL CHECK (tipo IN ('color', 'talle')),
  nombre      TEXT NOT NULL,
  cantidad    INTEGER DEFAULT 0,
  imagen      TEXT DEFAULT '',
  color_id    UUID REFERENCES producto_variantes(id)
);

-- VENTAS ONLINE
CREATE TABLE ventas_online (
  id           UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id      UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  external_ref TEXT,
  payment_id   TEXT UNIQUE,
  items        JSONB DEFAULT '[]',
  estado       TEXT DEFAULT 'procesado',
  fecha_venta  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- CONTADORES DE VENTA POR USUARIO
CREATE TABLE contadores (
  user_id       UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  venta_counter INTEGER DEFAULT 0
);

-- RATE LIMITING (para login)
CREATE TABLE rate_limits (
  key      TEXT PRIMARY KEY,
  count    INTEGER DEFAULT 0,
  reset_at TIMESTAMPTZ
);

-- ÍNDICES
CREATE INDEX idx_clientes_user    ON clientes(user_id);
CREATE INDEX idx_ventas_user      ON ventas(user_id);
CREATE INDEX idx_ventas_cliente   ON ventas(cliente_id);
CREATE INDEX idx_gastos_user      ON gastos(user_id);
CREATE INDEX idx_productos_user   ON productos(user_id);
CREATE INDEX idx_variantes_prod   ON producto_variantes(producto_id);

-- ROW LEVEL SECURITY
ALTER TABLE perfiles          ENABLE ROW LEVEL SECURITY;
ALTER TABLE mp_conexiones     ENABLE ROW LEVEL SECURITY;
ALTER TABLE clientes          ENABLE ROW LEVEL SECURITY;
ALTER TABLE ventas            ENABLE ROW LEVEL SECURITY;
ALTER TABLE gastos            ENABLE ROW LEVEL SECURITY;
ALTER TABLE productos         ENABLE ROW LEVEL SECURITY;
ALTER TABLE producto_variantes ENABLE ROW LEVEL SECURITY;
ALTER TABLE ventas_online     ENABLE ROW LEVEL SECURITY;
ALTER TABLE contadores        ENABLE ROW LEVEL SECURITY;

CREATE POLICY "own_data"      ON clientes         FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "own_data"      ON ventas           FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "own_data"      ON gastos           FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "own_data"      ON productos        FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "own_data"      ON ventas_online    FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "own_data"      ON contadores       FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "own_profile"   ON perfiles         FOR ALL USING (auth.uid() = id);
CREATE POLICY "own_mp"        ON mp_conexiones    FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "own_variantes" ON producto_variantes FOR ALL
  USING (EXISTS (
    SELECT 1 FROM productos WHERE id = producto_variantes.producto_id AND user_id = auth.uid()
  ));

-- INSERTAR PERFILES (ajustar UUIDs reales de Authentication → Users)
-- UUIDs actuales:
--   tomaspieri@outlook.com → 9f14c82c-82b0-4bb2-a341-30b8e0d7c1de  (admin)
--   sanlatorre@hotmail.com → 920a408f-79b7-4fb1-945f-c99eb301b257  (usuario)

INSERT INTO perfiles (id, nombre, rol) VALUES
  ('9f14c82c-82b0-4bb2-a341-30b8e0d7c1de', 'Tomas', 'admin'),
  ('920a408f-79b7-4fb1-945f-c99eb301b257', 'Chana', 'usuario')
ON CONFLICT (id) DO NOTHING;

INSERT INTO contadores (user_id, venta_counter) VALUES
  ('920a408f-79b7-4fb1-945f-c99eb301b257', 0)
ON CONFLICT (user_id) DO NOTHING;
