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
  id                  UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  nombre              TEXT DEFAULT '',
  rol                 TEXT DEFAULT 'usuario' CHECK (rol IN ('admin', 'usuario')),
  activo              BOOLEAN DEFAULT true,
  tipo_cuenta         TEXT DEFAULT 'gestion' CHECK (tipo_cuenta IN ('gestion', 'gestion_tienda')),
  tienda_configurada  BOOLEAN DEFAULT false,
  created_at          TIMESTAMPTZ DEFAULT NOW()
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
  tipo        TEXT NOT NULL CHECK (tipo IN ('color', 'talle', 'unico')),
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

-- TIENDA CONFIG (una fila por usuario con cuenta gestion_tienda)
CREATE TABLE IF NOT EXISTS tienda_config (
  id                  UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id             UUID REFERENCES auth.users(id) NOT NULL UNIQUE,
  nombre_tienda       TEXT DEFAULT '',
  descripcion         TEXT DEFAULT '',
  logo_url            TEXT DEFAULT NULL,
  color_primario      TEXT DEFAULT '#A88671',
  banner_imagen_url   TEXT DEFAULT NULL,
  banner_titulo       TEXT DEFAULT '',
  banner_subtitulo    TEXT DEFAULT '',
  banner_boton_texto  TEXT DEFAULT 'Ver colección',
  banner_boton_url    TEXT DEFAULT '/productos',
  secciones           JSONB DEFAULT '[]',
  franja_texto        TEXT DEFAULT '',
  franja_activa       BOOLEAN DEFAULT false,
  instagram_url       TEXT DEFAULT '',
  whatsapp_numero     TEXT DEFAULT '',
  envio_gratis_desde  NUMERIC(12,2) DEFAULT NULL,
  marquee_items       JSONB DEFAULT '[]',
  updated_at          TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE tienda_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY "usuario gestiona su config" ON tienda_config FOR ALL USING (auth.uid() = user_id);
ALTER PUBLICATION supabase_realtime ADD TABLE tienda_config;

-- PROMOCIONES (códigos de descuento)
CREATE TABLE IF NOT EXISTS promociones (
  id               UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id          UUID REFERENCES auth.users(id) NOT NULL,
  nombre           TEXT NOT NULL,
  tipo             TEXT NOT NULL DEFAULT 'codigo'
                     CHECK (tipo IN ('codigo','descuento_automatico','envio_gratis')),
  codigo           TEXT DEFAULT NULL,
  descuento_tipo   TEXT DEFAULT 'porcentaje'
                     CHECK (descuento_tipo IN ('porcentaje','fijo')),
  descuento_valor  NUMERIC(10,2) DEFAULT 0,
  monto_minimo     NUMERIC(12,2) DEFAULT NULL,
  aplica_a         TEXT DEFAULT 'todo'
                     CHECK (aplica_a IN ('todo','categoria','producto')),
  aplica_a_valor   TEXT DEFAULT NULL,
  usos_max         INTEGER DEFAULT NULL,
  usos_actuales    INTEGER DEFAULT 0,
  activa           BOOLEAN DEFAULT true,
  fecha_inicio     DATE DEFAULT NULL,
  fecha_fin        DATE DEFAULT NULL,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE promociones ENABLE ROW LEVEL SECURITY;
CREATE POLICY "usuario gestiona sus promos" ON promociones FOR ALL USING (auth.uid() = user_id);
CREATE UNIQUE INDEX IF NOT EXISTS promociones_codigo_unique
  ON promociones (user_id, codigo)
  WHERE codigo IS NOT NULL AND activa = true;

-- RATE LIMITING (para login y registro)
CREATE TABLE rate_limits (
  key      TEXT PRIMARY KEY,
  count    INTEGER DEFAULT 0,
  reset_at TIMESTAMPTZ
);

-- LOGS DE ACTIVIDAD (sin RLS — solo service key)
CREATE TABLE logs_actividad (
  id         UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id    UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  accion     TEXT NOT NULL,
  detalle    TEXT DEFAULT '',
  ip         TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- CONFIGURACIÓN DEL SISTEMA (sin RLS — solo service key)
CREATE TABLE config_sistema (
  clave      TEXT PRIMARY KEY,
  valor      TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Valores por defecto de config_sistema
INSERT INTO config_sistema (clave, valor) VALUES
  ('registros_habilitados', 'true'),
  ('email_soporte', ''),
  ('mensaje_bienvenida', '')
ON CONFLICT (clave) DO NOTHING;

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

INSERT INTO perfiles (id, nombre, rol, tipo_cuenta) VALUES
  ('9f14c82c-82b0-4bb2-a341-30b8e0d7c1de', 'Tomas', 'admin',   'gestion'),
  ('920a408f-79b7-4fb1-945f-c99eb301b257', 'Chana', 'usuario', 'gestion_tienda')
ON CONFLICT (id) DO NOTHING;

-- Para DBs ya existentes: agregar columnas si no existen
ALTER TABLE perfiles ADD COLUMN IF NOT EXISTS tipo_cuenta TEXT DEFAULT 'gestion' CHECK (tipo_cuenta IN ('gestion', 'gestion_tienda'));
ALTER TABLE perfiles ADD COLUMN IF NOT EXISTS tienda_configurada BOOLEAN DEFAULT false;

INSERT INTO contadores (user_id, venta_counter) VALUES
  ('920a408f-79b7-4fb1-945f-c99eb301b257', 0)
ON CONFLICT (user_id) DO NOTHING;

-- =============================================================================
-- CMS TIENDA — tablas para configuración y promociones (FASE 2)
-- =============================================================================

CREATE TABLE IF NOT EXISTS tienda_config (
  id                  UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id             UUID REFERENCES auth.users(id) NOT NULL UNIQUE,
  nombre_tienda       TEXT DEFAULT '',
  descripcion         TEXT DEFAULT '',
  logo_url            TEXT DEFAULT NULL,
  color_primario      TEXT DEFAULT '#A88671',
  banner_imagen_url   TEXT DEFAULT NULL,
  banner_titulo       TEXT DEFAULT '',
  banner_subtitulo    TEXT DEFAULT '',
  banner_boton_texto  TEXT DEFAULT 'Ver colección',
  banner_boton_url    TEXT DEFAULT '/productos.html',
  secciones           JSONB DEFAULT '[]'::jsonb,
  franja_texto        TEXT DEFAULT '',
  franja_activa       BOOLEAN DEFAULT false,
  instagram_url       TEXT DEFAULT '',
  whatsapp_numero     TEXT DEFAULT '',
  envio_gratis_desde  NUMERIC(12,2) DEFAULT NULL,
  marquee_items       JSONB DEFAULT '[]'::jsonb,
  updated_at          TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE tienda_config ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies
    WHERE tablename='tienda_config'
    AND policyname='usuario gestiona su config') THEN
    CREATE POLICY "usuario gestiona su config"
      ON tienda_config FOR ALL USING (auth.uid()=user_id);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS promociones (
  id               UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id          UUID REFERENCES auth.users(id) NOT NULL,
  nombre           TEXT NOT NULL DEFAULT '',
  tipo             TEXT NOT NULL DEFAULT 'codigo'
                     CHECK (tipo IN ('codigo','descuento_automatico','envio_gratis')),
  codigo           TEXT DEFAULT NULL,
  descuento_tipo   TEXT DEFAULT 'porcentaje'
                     CHECK (descuento_tipo IN ('porcentaje','fijo')),
  descuento_valor  NUMERIC(10,2) DEFAULT 0,
  monto_minimo     NUMERIC(12,2) DEFAULT NULL,
  aplica_a         TEXT DEFAULT 'todo'
                     CHECK (aplica_a IN ('todo','categoria','producto')),
  aplica_a_valor   TEXT DEFAULT NULL,
  usos_max         INTEGER DEFAULT NULL,
  usos_actuales    INTEGER DEFAULT 0,
  activa           BOOLEAN DEFAULT true,
  fecha_inicio     DATE DEFAULT NULL,
  fecha_fin        DATE DEFAULT NULL,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE promociones ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies
    WHERE tablename='promociones'
    AND policyname='usuario gestiona sus promos') THEN
    CREATE POLICY "usuario gestiona sus promos"
      ON promociones FOR ALL USING (auth.uid()=user_id);
  END IF;
END $$;
