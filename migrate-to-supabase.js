/**
 * migrate-to-supabase.js
 * Lee ventas.db en modo READ-ONLY y migra todos los datos a Supabase.
 * NUNCA modifica ventas.db.
 *
 * Uso:
 *   CHANA_USER_ID=920a408f-79b7-4fb1-945f-c99eb301b257 node migrate-to-supabase.js
 */

'use strict';

const path   = require('path');
const crypto = require('crypto');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const { createClient } = require('@supabase/supabase-js');

// ── Validar env ────────────────────────────────────────────────────────────────
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const CHANA_USER_ID        = process.env.CHANA_USER_ID;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('ERROR: Falta SUPABASE_URL o SUPABASE_SERVICE_KEY en .env');
  process.exit(1);
}
if (!CHANA_USER_ID) {
  console.error('ERROR: Falta CHANA_USER_ID');
  process.exit(1);
}

const DB_PATH = path.join(__dirname, 'ventas.db');

// ── Abrir DB en modo READ-ONLY ─────────────────────────────────────────────────
let db;
try {
  db = require('better-sqlite3')(DB_PATH, { readonly: true, fileMustExist: true });
  console.log(`✓ ventas.db abierta READ-ONLY (better-sqlite3): ${DB_PATH}`);
} catch (_) {
  const { DatabaseSync } = require('node:sqlite');
  db = new DatabaseSync(DB_PATH, { readOnly: true });
  console.log(`✓ ventas.db abierta READ-ONLY (node:sqlite): ${DB_PATH}`);
}

// ── Cliente Supabase con service_role ─────────────────────────────────────────
const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
let okCount = 0, errCount = 0;
const uuid = () => crypto.randomUUID();

function parseDecimal(val) {
  if (val == null) return 0;
  const n = parseFloat(val);
  return isNaN(n) ? 0 : n;
}

function parseDate(val) {
  if (!val) return null;
  if (/^\d{4}-\d{2}-\d{2}$/.test(val)) return val;
  const d = new Date(val);
  return isNaN(d.getTime()) ? null : d.toISOString().split('T')[0];
}

function parseTimestamp(val) {
  if (!val) return null;
  const d = new Date(val);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

function col(row, ...names) {
  for (const n of names) if (row[n] !== undefined) return row[n];
  return null;
}

async function upsert(table, rows, onConflict = 'id') {
  if (!rows.length) { console.log(`  (sin filas)`); return; }
  let inserted = 0;
  const CHUNK = 50;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const chunk = rows.slice(i, i + CHUNK);
    const { error } = await sb.from(table).upsert(chunk, { onConflict });
    if (error) {
      console.error(`  ERROR en ${table} (chunk ${i}):`, error.message);
      errCount += chunk.length;
    } else {
      inserted += chunk.length;
      okCount += chunk.length;
    }
    process.stdout.write(`  ${Math.min(i + CHUNK, rows.length)}/${rows.length}\r`);
  }
  console.log(`  ${inserted} filas OK en ${table}              `);
}

// ── MIGRACIÓN ─────────────────────────────────────────────────────────────────
async function migrate() {
  console.log(`\nUsuario destino: ${CHANA_USER_ID}\n`);

  const clienteMap  = new Map(); // oldId → newUUID
  const productoMap = new Map(); // oldId → newUUID

  // 1. CLIENTES
  console.log('→ Migrando clientes...');
  {
    const rows = db.prepare('SELECT * FROM clientes').all();
    console.log(`  ${rows.length} encontradas`);
    const mapped = rows.map(r => {
      const oldId = col(r, 'id');
      const newId = uuid();
      clienteMap.set(String(oldId), newId);
      return {
        id:         newId,
        user_id:    CHANA_USER_ID,
        nombre:     col(r, 'nombre') || '',
        telefono:   col(r, 'telefono') || '',
        notas:      col(r, 'notas') || '',
        created_at: parseTimestamp(col(r, 'created_at', 'createdAt')) || new Date().toISOString()
      };
    });
    await upsert('clientes', mapped);
  }

  // 2. VENTAS
  console.log('→ Migrando ventas...');
  {
    const rows = db.prepare('SELECT * FROM ventas').all();
    console.log(`  ${rows.length} encontradas`);
    let maxNum = 0;
    const mapped = rows.map(r => {
      const oldClienteId = col(r, 'cliente_id', 'clienteId');
      const numVenta = col(r, 'numero_venta', 'numeroVenta');
      if (numVenta > maxNum) maxNum = numVenta;
      return {
        id:              uuid(),
        user_id:         CHANA_USER_ID,
        cliente_id:      oldClienteId ? (clienteMap.get(String(oldClienteId)) || null) : null,
        prenda:          col(r, 'prenda') || '',
        precio_venta:    parseDecimal(col(r, 'precio_venta', 'precioVenta')),
        costo:           parseDecimal(col(r, 'costo')),
        pagado:          parseDecimal(col(r, 'pagado')),
        adeuda:          parseDecimal(col(r, 'adeuda')),
        cantidad:        parseInt(col(r, 'cantidad')) || 1,
        precio_unitario: parseDecimal(col(r, 'precio_unitario', 'precioUnitario')),
        costo_unitario:  parseDecimal(col(r, 'costo_unitario', 'costoUnitario')),
        fecha_compra:    parseDate(col(r, 'fecha_compra', 'fechaCompra')),
        prox_cuota:      parseDate(col(r, 'prox_cuota', 'proxCuota')),
        notas:           col(r, 'notas') || '',
        numero_venta:    numVenta || null,
        notificado_at:   parseDate(col(r, 'notificado_at', 'notificadoAt')),
        created_at:      parseTimestamp(col(r, 'created_at', 'createdAt')) || new Date().toISOString(),
        updated_at:      parseTimestamp(col(r, 'updated_at', 'updatedAt')) || new Date().toISOString()
      };
    });
    await upsert('ventas', mapped);

    if (maxNum > 0) {
      const { error } = await sb.from('contadores')
        .upsert({ user_id: CHANA_USER_ID, venta_counter: maxNum }, { onConflict: 'user_id' });
      if (error) console.warn('  WARN contador:', error.message);
      else console.log(`  Contador actualizado a ${maxNum}`);
    }
  }

  // 3. GASTOS
  console.log('→ Migrando gastos...');
  {
    const rows = db.prepare('SELECT * FROM gastos').all();
    console.log(`  ${rows.length} encontradas`);
    const mapped = rows.map(r => ({
      id:              uuid(),
      user_id:         CHANA_USER_ID,
      descripcion:     col(r, 'descripcion') || '',
      monto:           parseDecimal(col(r, 'monto')),
      fecha:           parseDate(col(r, 'fecha')),
      categoria:       col(r, 'categoria') || '',
      notas:           col(r, 'notas') || '',
      cantidad:        parseInt(col(r, 'cantidad')) || 1,
      precio_unitario: parseDecimal(col(r, 'precio_unitario', 'precioUnitario')),
      created_at:      parseTimestamp(col(r, 'created_at', 'createdAt')) || new Date().toISOString()
    }));
    await upsert('gastos', mapped);
  }

  // 4. PRODUCTOS
  console.log('→ Migrando productos...');
  {
    const rows = db.prepare('SELECT * FROM productos').all();
    console.log(`  ${rows.length} encontrados`);
    const mapped = rows.map(r => {
      const oldId = col(r, 'id');
      const newId = uuid();
      productoMap.set(String(oldId), newId);
      let imagenes = [];
      try { imagenes = JSON.parse(col(r, 'imagenes') || '[]'); } catch (_) {}
      return {
        id:             newId,
        user_id:        CHANA_USER_ID,
        nombre:         col(r, 'nombre') || '',
        categoria:      col(r, 'categoria') || '',
        precio:         parseDecimal(col(r, 'precio')),
        costo:          parseDecimal(col(r, 'costo')),
        imagen_url:     col(r, 'imagen_url', 'imagenUrl') || '',
        imagenes:       imagenes,
        descripcion:    col(r, 'descripcion') || '',
        guia_de_talles: col(r, 'guia_de_talles', 'guiaDeTalles') || '',
        peso:           parseInt(col(r, 'peso')) || 0,
        dimensiones:    col(r, 'dimensiones') || '',
        nuevo:          !!(col(r, 'nuevo')),
        activo:         col(r, 'activo') !== 0,
        created_at:     parseTimestamp(col(r, 'created_at', 'createdAt')) || new Date().toISOString(),
        updated_at:     parseTimestamp(col(r, 'updated_at', 'updatedAt')) || new Date().toISOString()
      };
    });
    await upsert('productos', mapped);
  }

  // 5. VARIANTES
  console.log('→ Migrando variantes...');
  {
    const rows = db.prepare('SELECT * FROM producto_variantes ORDER BY id').all();
    console.log(`  ${rows.length} encontradas`);

    // Primero, construir mapa de variantes color (para color_id de talles)
    const varianteMap = new Map(); // oldId → newUUID
    rows.forEach(r => varianteMap.set(String(col(r, 'id')), uuid()));

    const mapped = rows.map(r => {
      const oldId       = String(col(r, 'id'));
      const oldProdId   = col(r, 'producto_id', 'productoId');
      const oldColorId  = col(r, 'color_id', 'colorId');
      return {
        id:          varianteMap.get(oldId),
        producto_id: oldProdId ? (productoMap.get(String(oldProdId)) || null) : null,
        tipo:        col(r, 'tipo') || 'color',
        nombre:      col(r, 'nombre') || '',
        cantidad:    parseInt(col(r, 'cantidad')) || 0,
        imagen:      col(r, 'imagen') || '',
        color_id:    oldColorId ? (varianteMap.get(String(oldColorId)) || null) : null
      };
    });
    await upsert('producto_variantes', mapped);
  }

  // 6. VENTAS ONLINE
  {
    let rows = [];
    try { rows = db.prepare('SELECT * FROM ventas_online').all(); } catch (_) {}
    if (rows.length > 0) {
      console.log(`→ Migrando ventas_online (${rows.length})...`);
      const mapped = rows.map(r => {
        let items = [];
        try { items = JSON.parse(col(r, 'items') || '[]'); } catch (_) {}
        return {
          id:           uuid(),
          user_id:      CHANA_USER_ID,
          external_ref: col(r, 'external_ref', 'externalRef') || null,
          payment_id:   col(r, 'payment_id', 'paymentId') || null,
          items:        items,
          estado:       col(r, 'estado') || 'procesado',
          fecha_venta:  parseTimestamp(col(r, 'fecha_venta', 'fechaVenta')),
          created_at:   parseTimestamp(col(r, 'created_at', 'createdAt')) || new Date().toISOString()
        };
      });
      await upsert('ventas_online', mapped);
    }
  }

  console.log('\n============================');
  console.log(`OK:      ${okCount} filas`);
  console.log(`Errores: ${errCount} filas`);
  if (errCount > 0) {
    console.log('\nRevisá los errores. El script es idempotente — podés volver a ejecutar tras limpiar.');
    process.exit(1);
  }
  console.log('\n✅ Migración completa.');
}

migrate().catch(err => {
  console.error('\n❌ Error fatal:', err.message);
  process.exit(1);
});
