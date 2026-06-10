'use strict';
/**
 * migrate-cms.js — Crea tablas tienda_config y promociones en Supabase
 * Uso: node scripts/migrate-cms.js
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('ERROR: Faltan variables SUPABASE_URL y/o SUPABASE_SERVICE_KEY en .env.local');
  process.exit(1);
}

const adminSupabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false }
});

const SQL_TIENDA_CONFIG = `
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
`;

const SQL_PROMOCIONES = `
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
`;

async function runMigration(label, sql) {
  console.log(`\n▶ Ejecutando: ${label}`);

  // Intentar via rpc exec_sql
  const { error } = await adminSupabase.rpc('exec_sql', { sql });

  if (error) {
    if (error.message && error.message.includes('function') && error.message.includes('exec_sql')) {
      console.warn(`  ⚠ RPC exec_sql no disponible. Imprimiendo SQL para ejecución manual:`);
      console.log('\n--- COPIAR Y PEGAR EN SUPABASE SQL EDITOR ---');
      console.log(sql);
      console.log('--- FIN SQL ---\n');
    } else {
      console.error(`  ✗ Error: ${error.message}`);
    }
    return false;
  }

  console.log(`  ✓ OK`);
  return true;
}

async function verificarTablas() {
  console.log('\n▶ Verificando tablas...');
  const { data, error } = await adminSupabase
    .from('information_schema.tables')
    .select('table_name')
    .in('table_name', ['tienda_config', 'promociones'])
    .eq('table_schema', 'public');

  if (error) {
    // information_schema no siempre es accesible via API REST, intentar insert vacío
    const { error: e1 } = await adminSupabase.from('tienda_config').select('id').limit(1);
    const { error: e2 } = await adminSupabase.from('promociones').select('id').limit(1);

    const tc = !e1 || e1.code !== 'PGRST116' && e1.code !== '42P01';
    const pr = !e2 || e2.code !== 'PGRST116' && e2.code !== '42P01';

    console.log(`  tienda_config : ${tc ? '✓ existe' : '✗ no existe'}`);
    console.log(`  promociones   : ${pr ? '✓ existe' : '✗ no existe'}`);
    return;
  }

  const names = (data || []).map(r => r.table_name);
  console.log(`  tienda_config : ${names.includes('tienda_config') ? '✓ existe' : '✗ no existe'}`);
  console.log(`  promociones   : ${names.includes('promociones')   ? '✓ existe' : '✗ no existe'}`);
}

(async () => {
  console.log('═══════════════════════════════════════');
  console.log('  migrate-cms.js — CHANA CMS tables');
  console.log('═══════════════════════════════════════');

  await runMigration('tienda_config', SQL_TIENDA_CONFIG);
  await runMigration('promociones',   SQL_PROMOCIONES);
  await verificarTablas();

  console.log('\n✓ Script terminado.\n');
})();
