'use strict';
/**
 * api/[...route].js — Vercel catch-all serverless handler
 * Reemplaza server.js. Sin http.createServer, sin setInterval, sin escrituras a disco.
 */

const { createClient } = require('@supabase/supabase-js');
const nodemailer       = require('nodemailer');
const { encrypt, decrypt } = require('../lib/encrypt');

// ── Supabase clients ──────────────────────────────────────────────────────────
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY    = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const APP_URL              = process.env.APP_URL || 'https://chana-gestion.vercel.app';
const ALLOWED_ORIGIN       = process.env.ALLOWED_ORIGIN || 'https://chanaindumentaria.vercel.app';

const anonSupabase  = createClient(SUPABASE_URL, SUPABASE_ANON_KEY,  { auth: { persistSession: false } });
const adminSupabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });

// ── Brevo SMTP (hardcoded — mismas credenciales que server.js) ─────────────────
const mailer = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  auth: {
    user: 'ab17ad001@smtp-brevo.com',
    pass: process.env.BREVO_SMTP_PASS
  }
});

// ── MercadoPago ───────────────────────────────────────────────────────────────
const MP_CLIENT_ID     = process.env.MP_CLIENT_ID;
const MP_CLIENT_SECRET = process.env.MP_CLIENT_SECRET;
const MP_REDIRECT_URI  = process.env.MP_REDIRECT_URI || `${APP_URL}/api/mp/callback`;

// ── Helpers: transforms snake_case → camelCase ────────────────────────────────
function toCliente(r) {
  return { id: r.id, nombre: r.nombre, telefono: r.telefono, notas: r.notas, createdAt: r.created_at };
}

function toVenta(r) {
  return {
    id: r.id, clienteId: r.cliente_id, prenda: r.prenda,
    precioVenta: r.precio_venta, costo: r.costo, pagado: r.pagado, adeuda: r.adeuda,
    cantidad: r.cantidad, precioUnitario: r.precio_unitario, costoUnitario: r.costo_unitario,
    fechaCompra: r.fecha_compra, proxCuota: r.prox_cuota, notas: r.notas,
    numeroVenta: r.numero_venta, notificadoAt: r.notificado_at,
    cliente: r.clientes ? toCliente(r.clientes) : null,
    createdAt: r.created_at, updatedAt: r.updated_at
  };
}

function toGasto(r) {
  return {
    id: r.id, descripcion: r.descripcion, monto: r.monto, fecha: r.fecha,
    categoria: r.categoria, notas: r.notas, cantidad: r.cantidad,
    precioUnitario: r.precio_unitario, createdAt: r.created_at
  };
}

function toVariante(r) {
  return {
    id: r.id, productoId: r.producto_id, tipo: r.tipo,
    nombre: r.nombre, cantidad: r.cantidad, imagen: r.imagen, colorId: r.color_id
  };
}

function toProducto(r) {
  return {
    id: r.id, nombre: r.nombre, categoria: r.categoria, precio: r.precio, costo: r.costo,
    imagenUrl: r.imagen_url, imagenes: r.imagenes || [], descripcion: r.descripcion,
    guiaDeTalles: r.guia_de_talles, peso: r.peso, dimensiones: r.dimensiones,
    nuevo: r.nuevo, activo: r.activo,
    variantes: (r.producto_variantes || []).map(toVariante),
    createdAt: r.created_at, updatedAt: r.updated_at
  };
}

// ── Rate limiting (Supabase table — stateless, serverless-safe) ───────────────
async function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const resetAt = new Date(now + windowMs).toISOString();

  const { data } = await adminSupabase
    .from('rate_limits').select('count, reset_at').eq('key', key).single();

  if (!data || new Date(data.reset_at).getTime() < now) {
    await adminSupabase.from('rate_limits')
      .upsert({ key, count: 1, reset_at: resetAt }, { onConflict: 'key' });
    return true;
  }
  if (data.count >= max) return false;
  await adminSupabase.from('rate_limits').update({ count: data.count + 1 }).eq('key', key);
  return true;
}

// ── Auth ──────────────────────────────────────────────────────────────────────
async function requireAuth(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;

  // Soporte para GESTION_SYNC_TOKEN (acceso especial de la tienda)
  if (token === process.env.GESTION_SYNC_TOKEN && process.env.GESTION_SYNC_TOKEN) {
    return { userId: null, email: 'sync@system', role: 'sync' };
  }

  const { data: { user }, error } = await anonSupabase.auth.getUser(token);
  if (error || !user) return null;

  const { data: perfil } = await adminSupabase
    .from('perfiles').select('rol, activo, nombre, tipo_cuenta, tienda_configurada').eq('id', user.id).single();

  if (!perfil || !perfil.activo) return null;
  return {
    userId: user.id, email: user.email, role: perfil.rol,
    nombre: perfil.nombre, tipoCuenta: perfil.tipo_cuenta || 'gestion',
    tiendaConfigurada: perfil.tienda_configurada || false
  };
}

// ── Body parsing (Vercel no parsea automáticamente) ────────────────────────────
async function parseBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch (_) { resolve({}); }
    });
    req.on('error', () => resolve({}));
  });
}

// ── Cookie parsing ─────────────────────────────────────────────────────────────
function parseCookies(req) {
  const str = req.headers.cookie || '';
  return Object.fromEntries(str.split(';').map(c => {
    const [k, ...v] = c.trim().split('=');
    return [k, decodeURIComponent(v.join('='))];
  }).filter(([k]) => k));
}

// ── Helpers MP token ──────────────────────────────────────────────────────────
async function getMpToken(userId) {
  const { data } = await adminSupabase
    .from('mp_conexiones')
    .select('access_token_encrypted, conectado, expires_at')
    .eq('user_id', userId)
    .single();
  if (!data || !data.conectado || !data.access_token_encrypted) return null;
  return decrypt(data.access_token_encrypted);
}

async function getDeployHook(userId) {
  const { data } = await adminSupabase
    .from('mp_conexiones').select('vercel_deploy_hook').eq('user_id', userId).single();
  return data?.vercel_deploy_hook || null;
}

// ── Número de venta ────────────────────────────────────────────────────────────
async function nextNumeroVenta(userId) {
  const { data } = await adminSupabase
    .from('contadores').select('venta_counter').eq('user_id', userId).single();
  const next = (data?.venta_counter || 0) + 1;
  await adminSupabase.from('contadores')
    .upsert({ user_id: userId, venta_counter: next }, { onConflict: 'user_id' });
  return next;
}

// ── Email (Brevo) ─────────────────────────────────────────────────────────────
async function sendEmail(subject, html) {
  try {
    await mailer.sendMail({
      from: '"Chana Gestión" <tomipieri@hotmail.com>',
      to: 'sanlatorre@hotmail.com, chanaindumentaria@hotmail.com',
      subject,
      html
    });
  } catch (e) {
    console.error('Email error:', e.message);
  }
}

// ── Telegram ──────────────────────────────────────────────────────────────────
async function sendTelegram(msg) {
  const token  = process.env.TELEGRAM_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: msg, parse_mode: 'HTML' })
    });
  } catch (e) {
    console.error('Telegram error:', e.message);
  }
}

// ── CORS headers ──────────────────────────────────────────────────────────────
function setCors(req, res) {
  const origin = req.headers.origin || '';
  const allowed = [ALLOWED_ORIGIN, APP_URL, 'http://localhost:3000', 'http://localhost:5500'];
  if (allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', APP_URL);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}

function json(res, status, data) {
  res.status(status).json(data);
}

// ── Correo Argentino quote ─────────────────────────────────────────────────────
async function getCorreoQuote(payload) {
  const user = process.env.CORREO_ARG_USER;
  const pass = process.env.CORREO_ARG_PASS;
  if (!user || !pass) return null;

  const env = process.env.CORREO_ARG_ENV === 'prod' ? '' : 'test.';
  const url = `https://${env}apis.correoargentino.com.ar/miCorreo/v1/tarifas`;
  const auth = Buffer.from(`${user}:${pass}`).toString('base64');

  const body = {
    modalidad: 'CP',
    codigoPostalOrigen: '1424',
    codigoPostalDestino: payload.cp || '1000',
    pesoPiezas: payload.peso || 500,
    valorDeclarado: 0,
    ancho: 20, alto: 5, largo: 20
  };

  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${auth}` },
    body: JSON.stringify(body)
  });
  if (!r.ok) return null;
  const data = await r.json();
  return data;
}

// ══════════════════════════════════════════════════════════════════════════════
// HANDLER PRINCIPAL
// ══════════════════════════════════════════════════════════════════════════════
module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  // Parsear path desde req.url (más confiable que req.query.route cuando hay rewrite)
  const rawUrl  = req.url || '';
  const pathOnly = rawUrl.split('?')[0];                    // sin query string
  const p        = pathOnly.replace(/^\/api\//, '').replace(/\/$/, '');  // "auth/login", "clientes/123"
  const segments = p.split('/');
  const method = req.method;

  // Rutas públicas
  if (method === 'POST' && p === 'auth/login')    return handleLogin(req, res);
  if (method === 'POST' && p === 'auth/registro') return handleRegistro(req, res);
  if (method === 'GET'  && p === 'mp/callback')   return handleMpCallback(req, res);
  if (method === 'POST' && p === 'shipping-quote') return handleShippingQuote(req, res);

  // Rutas protegidas
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'No autorizado' });

  // Admin routes
  if (segments[0] === 'admin') {
    if (user.role !== 'admin') return json(res, 403, { error: 'Sin permiso' });
    const adminRl = await rateLimit(`admin:${user.userId}`, 60, 60000);
    if (!adminRl) return json(res, 429, { error: 'Demasiadas solicitudes' });
    if (method === 'GET'  && p === 'admin/stats')                               return handleAdminStats(req, res);
    if (method === 'GET'  && p === 'admin/usuarios')                             return handleAdminGetUsuarios(req, res);
    if (method === 'PUT'  && segments[0]==='admin' && segments[1]==='usuarios' && segments[2] && !segments[3]) return handleAdminPutUsuario(req, res, segments[2]);
    if (method === 'POST' && segments[1]==='usuarios' && segments[2]==='crear')  return handleAdminCrearUsuario(req, res);
    if (method === 'POST' && segments[1]==='usuarios' && segments[3]==='activar')   return handleAdminToggleUsuario(req, res, segments[2], true);
    if (method === 'POST' && segments[1]==='usuarios' && segments[3]==='desactivar') return handleAdminToggleUsuario(req, res, segments[2], false);
    if (method === 'POST' && segments[1]==='usuarios' && segments[3]==='reset-password') return handleAdminResetPassword(req, res, segments[2]);
    if (method === 'GET'  && p === 'admin/ventas-globales')                      return handleAdminVentasGlobales(req, res);
    if (method === 'GET'  && p === 'admin/actividad')                            return handleAdminActividad(req, res);
    if (method === 'GET'  && p === 'admin/config')                               return handleAdminGetConfig(req, res);
    if (method === 'POST' && p === 'admin/config')                               return handleAdminPostConfig(req, res);
    return json(res, 404, { error: 'Ruta admin no encontrada' });
  }

  // Auth
  if (method === 'GET'  && p === 'auth/me') return json(res, 200, {
    user: {
      id: user.userId, email: user.email, rol: user.role,
      nombre: user.nombre, tipoCuenta: user.tipoCuenta, tiendaConfigurada: user.tiendaConfigurada
    }
  });
  if (method === 'POST' && p === 'auth/logout')  return json(res, 200, { ok: true });

  // Clientes
  if (method === 'GET'  && p === 'clientes')           return handleGetClientes(req, res, user);
  if (method === 'POST' && p === 'clientes')           return handlePostCliente(req, res, user);
  if (method === 'PUT'  && segments[0] === 'clientes') return handlePutCliente(req, res, user, segments[1]);
  if (method === 'DELETE' && segments[0] === 'clientes') return handleDeleteCliente(req, res, user, segments[1]);

  // Ventas
  if (method === 'GET'  && p === 'ventas')             return handleGetVentas(req, res, user);
  if (method === 'POST' && p === 'ventas')             return handlePostVenta(req, res, user);
  if (method === 'PUT'  && segments[0] === 'ventas' && !segments[2])
    return handlePutVenta(req, res, user, segments[1]);
  if (method === 'DELETE' && segments[0] === 'ventas') return handleDeleteVenta(req, res, user, segments[1]);
  if (method === 'POST' && segments[0] === 'ventas' && segments[2] === 'pago')
    return handlePagoVenta(req, res, user, segments[1]);

  // Gastos
  if (method === 'GET'  && p === 'gastos')             return handleGetGastos(req, res, user);
  if (method === 'POST' && p === 'gastos')             return handlePostGasto(req, res, user);
  if (method === 'PUT'  && segments[0] === 'gastos')   return handlePutGasto(req, res, user, segments[1]);
  if (method === 'DELETE' && segments[0] === 'gastos') return handleDeleteGasto(req, res, user, segments[1]);

  // Productos
  if (method === 'GET'  && p === 'productos')          return handleGetProductos(req, res, user);
  if (method === 'POST' && p === 'productos')          return handlePostProducto(req, res, user);
  if (method === 'PUT'  && segments[0] === 'productos' && !segments[2])
    return handlePutProducto(req, res, user, segments[1]);
  if (method === 'DELETE' && segments[0] === 'productos' && !segments[2])
    return handleDeleteProducto(req, res, user, segments[1]);

  // Variantes
  if (method === 'GET'  && segments[0] === 'productos' && segments[2] === 'variantes')
    return handleGetVariantes(req, res, user, segments[1]);
  if (method === 'POST' && segments[0] === 'productos' && segments[2] === 'variantes')
    return handlePostVariante(req, res, user, segments[1]);
  if (method === 'PUT'  && segments[0] === 'variantes') return handlePutVariante(req, res, user, segments[1]);
  if (method === 'DELETE' && segments[0] === 'variantes') return handleDeleteVariante(req, res, user, segments[1]);

  // Ventas online
  if (method === 'GET' && p === 'ventas-online')       return handleGetVentasOnline(req, res, user);

  // Config (tienda + MP)
  if (method === 'GET' && p === 'config')              return handleGetConfig(req, res, user);
  if (method === 'PUT' && p === 'config')              return handlePutConfig(req, res, user);

  // Stock
  if (method === 'POST' && p === 'stock/publicar')     return handlePublicarStock(req, res, user);

  // MP OAuth
  if (method === 'GET'  && p === 'mp/connect')         return handleMpConnect(req, res, user);
  if (method === 'POST' && p === 'mp/disconnect')      return handleMpDisconnect(req, res, user);
  if (method === 'POST' && p === 'mp/sync')            return handleMpSync(req, res, user);

  // Upload imágenes (Supabase Storage)
  if (method === 'POST' && p === 'upload-imagenes')    return handleUploadImagenes(req, res, user);

  // Cron jobs (llegan aquí cuando el rewrite los redirige al catch-all)
  if (p === 'cron/check-cuotas') return handleCronCheckCuotas(req, res);
  if (p === 'cron/sync-mp')      return handleCronSyncMp(req, res);

  return json(res, 404, { error: 'Ruta no encontrada' });
};

// ── LOGIN ──────────────────────────────────────────────────────────────────────
async function handleLogin(req, res) {
  const body = await parseBody(req);
  const { email, password } = body;
  if (!email || !password) return json(res, 400, { error: 'Faltan credenciales' });

  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  const allowed = await rateLimit(`login:${ip}`, 10, 15 * 60 * 1000);
  if (!allowed) return json(res, 429, { error: 'Demasiados intentos. Esperá 15 minutos.' });

  const { data, error } = await anonSupabase.auth.signInWithPassword({ email, password });
  if (error) return json(res, 401, { error: 'Credenciales incorrectas' });

  const { data: perfil } = await adminSupabase
    .from('perfiles').select('rol, activo, nombre').eq('id', data.user.id).single();

  if (!perfil?.activo) return json(res, 403, { error: 'Cuenta desactivada' });

  await logActividad(data.user.id, data.user.email, 'login_exitoso', '', ip);

  return json(res, 200, {
    token: data.session.access_token,
    user: {
      id: data.user.id, email: data.user.email,
      rol: perfil.rol, nombre: perfil.nombre,
      tipoCuenta: perfil.tipo_cuenta || 'gestion',
      tiendaConfigurada: perfil.tienda_configurada || false
    }
  });
}

// ── CLIENTES ──────────────────────────────────────────────────────────────────
async function handleGetClientes(req, res, user) {
  let q = adminSupabase.from('clientes').select('*').order('nombre');
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { data, error } = await q;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, data.map(toCliente));
}

async function handlePostCliente(req, res, user) {
  const body = await parseBody(req);
  const row = {
    user_id:  user.role === 'admin' ? (body.userId || user.userId) : user.userId,
    nombre:   body.nombre || '',
    telefono: body.telefono || '',
    notas:    body.notas || ''
  };
  const { data, error } = await adminSupabase.from('clientes').insert(row).select().single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 201, toCliente(data));
}

async function handlePutCliente(req, res, user, id) {
  const body = await parseBody(req);
  const updates = {};
  if (body.nombre   !== undefined) updates.nombre   = body.nombre;
  if (body.telefono !== undefined) updates.telefono = body.telefono;
  if (body.notas    !== undefined) updates.notas    = body.notas;

  let q = adminSupabase.from('clientes').update(updates).eq('id', id);
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { data, error } = await q.select().single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, toCliente(data));
}

async function handleDeleteCliente(req, res, user, id) {
  let q = adminSupabase.from('clientes').delete().eq('id', id);
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { error } = await q;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

// ── VENTAS ────────────────────────────────────────────────────────────────────
async function handleGetVentas(req, res, user) {
  let q = adminSupabase.from('ventas')
    .select('*, clientes(id, nombre, telefono, notas, created_at)')
    .order('created_at', { ascending: false });
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { data, error } = await q;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, data.map(toVenta));
}

async function handlePostVenta(req, res, user) {
  const body = await parseBody(req);
  const userId = user.role === 'admin' ? (body.userId || user.userId) : user.userId;
  const numero = await nextNumeroVenta(userId);

  const precioVenta = parseFloat(body.precioVenta) || 0;
  const pagado      = parseFloat(body.pagado)      || 0;
  const cantidad    = parseInt(body.cantidad)       || 1;
  const costo       = parseFloat(body.costo)        || 0;

  const row = {
    user_id:         userId,
    cliente_id:      body.clienteId || null,
    prenda:          body.prenda || '',
    precio_venta:    precioVenta,
    costo:           costo,
    pagado:          pagado,
    adeuda:          precioVenta - pagado,
    cantidad:        cantidad,
    precio_unitario: body.precioUnitario != null ? parseFloat(body.precioUnitario) : precioVenta / cantidad,
    costo_unitario:  body.costoUnitario  != null ? parseFloat(body.costoUnitario)  : costo / cantidad,
    fecha_compra:    body.fechaCompra   || new Date().toISOString().split('T')[0],
    prox_cuota:      body.proxCuota     || null,
    notas:           body.notas         || '',
    numero_venta:    numero
  };
  const { data, error } = await adminSupabase.from('ventas').insert(row).select('*, clientes(*)').single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 201, toVenta(data));
}

async function handlePutVenta(req, res, user, id) {
  const body = await parseBody(req);
  const updates = {};
  const fields = ['prenda','fechaCompra','proxCuota','notas','clienteId'];
  if (body.prenda      !== undefined) updates.prenda       = body.prenda;
  if (body.fechaCompra !== undefined) updates.fecha_compra = body.fechaCompra;
  if (body.proxCuota   !== undefined) updates.prox_cuota   = body.proxCuota;
  if (body.notas       !== undefined) updates.notas        = body.notas;
  if (body.clienteId   !== undefined) updates.cliente_id   = body.clienteId;
  if (body.precioVenta !== undefined) {
    updates.precio_venta = parseFloat(body.precioVenta);
    if (body.pagado !== undefined) {
      updates.pagado = parseFloat(body.pagado);
      updates.adeuda = updates.precio_venta - updates.pagado;
    }
  }
  if (body.costo !== undefined)       updates.costo        = parseFloat(body.costo);
  if (body.cantidad !== undefined)    updates.cantidad     = parseInt(body.cantidad);
  updates.updated_at = new Date().toISOString();

  let q = adminSupabase.from('ventas').update(updates).eq('id', id);
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { data, error } = await q.select('*, clientes(*)').single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, toVenta(data));
}

async function handleDeleteVenta(req, res, user, id) {
  let q = adminSupabase.from('ventas').delete().eq('id', id);
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { error } = await q;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

async function handlePagoVenta(req, res, user, id) {
  const body = await parseBody(req);
  const monto = parseFloat(body.monto);
  if (!monto || monto <= 0) return json(res, 400, { error: 'Monto inválido' });

  let qGet = adminSupabase.from('ventas').select('pagado, precio_venta, adeuda').eq('id', id);
  if (user.role !== 'admin') qGet = qGet.eq('user_id', user.userId);
  const { data: venta } = await qGet.single();
  if (!venta) return json(res, 404, { error: 'Venta no encontrada' });

  const nuevoPagado = parseFloat(venta.pagado) + monto;
  const nuevaAdeuda = parseFloat(venta.precio_venta) - nuevoPagado;

  let qUpd = adminSupabase.from('ventas')
    .update({ pagado: nuevoPagado, adeuda: Math.max(0, nuevaAdeuda), updated_at: new Date().toISOString() })
    .eq('id', id);
  if (user.role !== 'admin') qUpd = qUpd.eq('user_id', user.userId);
  const { data, error } = await qUpd.select('*, clientes(*)').single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, toVenta(data));
}

// ── GASTOS ────────────────────────────────────────────────────────────────────
async function handleGetGastos(req, res, user) {
  let q = adminSupabase.from('gastos').select('*').order('fecha', { ascending: false });
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { data, error } = await q;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, data.map(toGasto));
}

async function handlePostGasto(req, res, user) {
  const body = await parseBody(req);
  const cantidad = parseInt(body.cantidad) || 1;
  const monto    = parseFloat(body.monto)  || 0;
  const row = {
    user_id:         user.role === 'admin' ? (body.userId || user.userId) : user.userId,
    descripcion:     body.descripcion || '',
    monto:           monto,
    fecha:           body.fecha || new Date().toISOString().split('T')[0],
    categoria:       body.categoria || '',
    notas:           body.notas || '',
    cantidad:        cantidad,
    precio_unitario: body.precioUnitario != null ? parseFloat(body.precioUnitario) : monto / cantidad
  };
  const { data, error } = await adminSupabase.from('gastos').insert(row).select().single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 201, toGasto(data));
}

async function handlePutGasto(req, res, user, id) {
  const body = await parseBody(req);
  const updates = {};
  if (body.descripcion   !== undefined) updates.descripcion     = body.descripcion;
  if (body.monto         !== undefined) updates.monto           = parseFloat(body.monto);
  if (body.fecha         !== undefined) updates.fecha           = body.fecha;
  if (body.categoria     !== undefined) updates.categoria       = body.categoria;
  if (body.notas         !== undefined) updates.notas           = body.notas;
  if (body.cantidad      !== undefined) updates.cantidad        = parseInt(body.cantidad);
  if (body.precioUnitario !== undefined) updates.precio_unitario = parseFloat(body.precioUnitario);

  let q = adminSupabase.from('gastos').update(updates).eq('id', id);
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { data, error } = await q.select().single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, toGasto(data));
}

async function handleDeleteGasto(req, res, user, id) {
  let q = adminSupabase.from('gastos').delete().eq('id', id);
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { error } = await q;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

// ── PRODUCTOS ─────────────────────────────────────────────────────────────────
async function handleGetProductos(req, res, user) {
  let q = adminSupabase.from('productos')
    .select('*, producto_variantes(*)')
    .order('nombre');
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { data, error } = await q;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, data.map(toProducto));
}

async function handlePostProducto(req, res, user) {
  const body = await parseBody(req);
  const row = {
    user_id:        user.role === 'admin' ? (body.userId || user.userId) : user.userId,
    nombre:         body.nombre || '',
    categoria:      body.categoria || '',
    precio:         parseFloat(body.precio) || 0,
    costo:          parseFloat(body.costo)  || 0,
    imagen_url:     body.imagenUrl || '',
    imagenes:       body.imagenes  || [],
    descripcion:    body.descripcion || '',
    guia_de_talles: body.guiaDeTalles || '',
    peso:           parseInt(body.peso) || 0,
    dimensiones:    body.dimensiones || '',
    nuevo:          !!body.nuevo,
    activo:         body.activo !== false
  };
  const { data, error } = await adminSupabase.from('productos').insert(row).select('*, producto_variantes(*)').single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 201, toProducto(data));
}

async function handlePutProducto(req, res, user, id) {
  const body = await parseBody(req);
  const updates = {};
  const map = {
    nombre:'nombre', categoria:'categoria', descripcion:'descripcion',
    guiaDeTalles:'guia_de_talles', dimensiones:'dimensiones'
  };
  for (const [k, v] of Object.entries(map)) {
    if (body[k] !== undefined) updates[v] = body[k];
  }
  if (body.precio    !== undefined) updates.precio    = parseFloat(body.precio);
  if (body.costo     !== undefined) updates.costo     = parseFloat(body.costo);
  if (body.imagenUrl !== undefined) updates.imagen_url = body.imagenUrl;
  if (body.imagenes  !== undefined) updates.imagenes  = body.imagenes;
  if (body.peso      !== undefined) updates.peso      = parseInt(body.peso);
  if (body.nuevo     !== undefined) updates.nuevo     = !!body.nuevo;
  if (body.activo    !== undefined) updates.activo    = !!body.activo;
  updates.updated_at = new Date().toISOString();

  let q = adminSupabase.from('productos').update(updates).eq('id', id);
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { data, error } = await q.select('*, producto_variantes(*)').single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, toProducto(data));
}

async function handleDeleteProducto(req, res, user, id) {
  let q = adminSupabase.from('productos').delete().eq('id', id);
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { error } = await q;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

// ── VARIANTES ─────────────────────────────────────────────────────────────────
async function handleGetVariantes(req, res, user, productoId) {
  const { data, error } = await adminSupabase
    .from('producto_variantes').select('*').eq('producto_id', productoId);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, data.map(toVariante));
}

async function handlePostVariante(req, res, user, productoId) {
  const body = await parseBody(req);
  const row = {
    producto_id: productoId,
    tipo:        body.tipo || 'color',
    nombre:      body.nombre || '',
    cantidad:    parseInt(body.cantidad) || 0,
    imagen:      body.imagen || '',
    color_id:    body.colorId || null
  };
  const { data, error } = await adminSupabase.from('producto_variantes').insert(row).select().single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 201, toVariante(data));
}

async function handlePutVariante(req, res, user, id) {
  const body = await parseBody(req);
  const updates = {};
  if (body.nombre   !== undefined) updates.nombre   = body.nombre;
  if (body.cantidad !== undefined) updates.cantidad = parseInt(body.cantidad);
  if (body.imagen   !== undefined) updates.imagen   = body.imagen;
  if (body.colorId  !== undefined) updates.color_id = body.colorId;

  const { data, error } = await adminSupabase
    .from('producto_variantes').update(updates).eq('id', id).select().single();
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, toVariante(data));
}

async function handleDeleteVariante(req, res, user, id) {
  const { error } = await adminSupabase.from('producto_variantes').delete().eq('id', id);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

// ── VENTAS ONLINE ─────────────────────────────────────────────────────────────
async function handleGetVentasOnline(req, res, user) {
  let q = adminSupabase.from('ventas_online').select('*').order('created_at', { ascending: false });
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { data, error } = await q;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, data);
}

// ── CONFIG (tienda + MP) ──────────────────────────────────────────────────────
async function handleGetConfig(req, res, user) {
  const { data } = await adminSupabase
    .from('mp_conexiones')
    .select('conectado, tienda_url, tienda_nombre, vercel_deploy_hook, mp_last_sync, mp_user_id')
    .eq('user_id', user.userId)
    .single();

  return json(res, 200, {
    tiendaUrl:         data?.tienda_url         || '',
    tiendaNombre:      data?.tienda_nombre       || '',
    vercelDeployHook:  data?.vercel_deploy_hook  || '',
    mpConectado:       data?.conectado           || false,
    mpUserId:          data?.mp_user_id          || null,
    mpLastSync:        data?.mp_last_sync        || null
  });
}

async function handlePutConfig(req, res, user) {
  const body = await parseBody(req);
  const updates = { user_id: user.userId, updated_at: new Date().toISOString() };
  if (body.tiendaUrl        !== undefined) updates.tienda_url        = body.tiendaUrl;
  if (body.tiendaNombre     !== undefined) updates.tienda_nombre     = body.tiendaNombre;
  if (body.vercelDeployHook !== undefined) updates.vercel_deploy_hook = body.vercelDeployHook;

  const { error } = await adminSupabase
    .from('mp_conexiones').upsert(updates, { onConflict: 'user_id' });
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

// ── STOCK PUBLICAR ────────────────────────────────────────────────────────────
async function handlePublicarStock(req, res, user) {
  const hook = await getDeployHook(user.userId);
  if (!hook) {
    return json(res, 400, { error: 'No hay Vercel Deploy Hook configurado. Configuralo en "Mi Tienda".' });
  }

  try {
    const r = await fetch(hook, { method: 'POST' });
    if (!r.ok) {
      const txt = await r.text();
      return json(res, 500, { error: `Deploy hook error: ${txt}` });
    }
    return json(res, 200, { ok: true, message: 'Deploy iniciado. La tienda se actualizará en ~2 minutos.' });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
}

// ── MP OAUTH — Iniciar ────────────────────────────────────────────────────────
async function handleMpConnect(req, res, user) {
  if (!MP_CLIENT_ID) return json(res, 500, { error: 'MP_CLIENT_ID no configurado' });

  const state = Buffer.from(JSON.stringify({ userId: user.userId, ts: Date.now() })).toString('base64url');
  const url = new URL('https://auth.mercadopago.com.ar/authorization');
  url.searchParams.set('client_id', MP_CLIENT_ID);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('platform_id', 'mp');
  url.searchParams.set('redirect_uri', MP_REDIRECT_URI);
  url.searchParams.set('state', state);

  res.setHeader('Set-Cookie', `mp_state=${state}; HttpOnly; Path=/; SameSite=Lax; Max-Age=600`);
  res.writeHead(302, { Location: url.toString() });
  return res.end();
}

// ── MP OAUTH — Callback ───────────────────────────────────────────────────────
async function handleMpCallback(req, res) {
  const { code, state, error: mpError } = req.query;
  const cookies = parseCookies(req);

  if (mpError) {
    return res.writeHead(302, { Location: `${APP_URL}/?mp_error=${encodeURIComponent(mpError)}` }), res.end();
  }
  if (!code || !state || cookies.mp_state !== state) {
    return res.writeHead(302, { Location: `${APP_URL}/?mp_error=state_mismatch` }), res.end();
  }

  let userId;
  try {
    const parsed = JSON.parse(Buffer.from(state, 'base64url').toString());
    userId = parsed.userId;
    if (Date.now() - parsed.ts > 10 * 60 * 1000) throw new Error('expired');
  } catch (_) {
    return res.writeHead(302, { Location: `${APP_URL}/?mp_error=invalid_state` }), res.end();
  }

  // Intercambiar code por tokens
  const tokenRes = await fetch('https://api.mercadopago.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id:     MP_CLIENT_ID,
      client_secret: MP_CLIENT_SECRET,
      grant_type:    'authorization_code',
      code,
      redirect_uri:  MP_REDIRECT_URI
    })
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.text();
    console.error('MP token error:', err);
    return res.writeHead(302, { Location: `${APP_URL}/?mp_error=token_exchange` }), res.end();
  }

  const tokens = await tokenRes.json();
  const expiresAt = new Date(Date.now() + tokens.expires_in * 1000).toISOString();

  await adminSupabase.from('mp_conexiones').upsert({
    user_id:                userId,
    mp_user_id:             String(tokens.user_id),
    access_token_encrypted:  encrypt(tokens.access_token),
    refresh_token_encrypted: tokens.refresh_token ? encrypt(tokens.refresh_token) : null,
    expires_at:             expiresAt,
    conectado:              true,
    updated_at:             new Date().toISOString()
  }, { onConflict: 'user_id' });

  res.setHeader('Set-Cookie', 'mp_state=; HttpOnly; Path=/; Max-Age=0');
  res.writeHead(302, { Location: `${APP_URL}/?mp_ok=1` });
  return res.end();
}

// ── MP DISCONNECT ─────────────────────────────────────────────────────────────
async function handleMpDisconnect(req, res, user) {
  await adminSupabase.from('mp_conexiones').upsert({
    user_id:   user.userId,
    conectado: false,
    access_token_encrypted:  null,
    refresh_token_encrypted: null,
    expires_at: null,
    updated_at: new Date().toISOString()
  }, { onConflict: 'user_id' });
  return json(res, 200, { ok: true });
}

// ── MP SYNC ────────────────────────────────────────────────────────────────────
async function handleMpSync(req, res, user) {
  const result = await doMpSync(user.userId);
  return json(res, result.error ? 500 : 200, result);
}

async function doMpSync(userId) {
  const token = await getMpToken(userId);
  if (!token) return { error: 'MercadoPago no conectado' };

  const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const url = `https://api.mercadopago.com/v1/payments/search?status=approved&sort=date_created&criteria=desc&range=date_created&begin_date=${since}&limit=50`;

  const r = await fetch(url, { headers: { 'Authorization': `Bearer ${token}` } });
  if (!r.ok) return { error: `MP API error: ${r.status}` };

  const { results } = await r.json();
  if (!results?.length) {
    await adminSupabase.from('mp_conexiones')
      .update({ mp_last_sync: new Date().toISOString() }).eq('user_id', userId);
    return { synced: 0, message: 'Sin pagos nuevos' };
  }

  // Obtener payment_ids ya procesados
  const { data: existentes } = await adminSupabase
    .from('ventas_online').select('payment_id').eq('user_id', userId);
  const yaProcesados = new Set((existentes || []).map(v => String(v.payment_id)));

  let synced = 0;
  for (const pago of results) {
    const pid = String(pago.id);
    if (yaProcesados.has(pid)) continue;

    const items = (pago.additional_info?.items || []).map(i => ({
      id:       i.id,
      nombre:   i.title,
      cantidad: parseInt(i.quantity) || 1,
      precio:   parseFloat(i.unit_price) || 0
    }));

    // Buscar o crear cliente
    const nombrePagador = pago.payer?.first_name
      ? `${pago.payer.first_name} ${pago.payer.last_name || ''}`.trim()
      : 'Cliente MP';
    const telefonoPagador = pago.payer?.phone?.number || '';

    let clienteId = null;
    if (pago.payer?.email) {
      const { data: clienteExistente } = await adminSupabase
        .from('clientes').select('id')
        .eq('user_id', userId)
        .ilike('nombre', nombrePagador)
        .limit(1).single();

      if (clienteExistente) {
        clienteId = clienteExistente.id;
      } else {
        const { data: nuevoCliente } = await adminSupabase.from('clientes')
          .insert({ user_id: userId, nombre: nombrePagador, telefono: telefonoPagador, notas: `MP: ${pago.payer.email}` })
          .select('id').single();
        if (nuevoCliente) clienteId = nuevoCliente.id;
      }
    }

    // Registrar venta online
    await adminSupabase.from('ventas_online').insert({
      user_id:      userId,
      external_ref: pago.external_reference || null,
      payment_id:   pid,
      items:        items,
      estado:       'procesado',
      fecha_venta:  pago.date_approved || new Date().toISOString()
    });

    // Crear venta en el registro principal
    const totalPago = parseFloat(pago.transaction_amount) || 0;
    if (totalPago > 0) {
      const numero = await nextNumeroVenta(userId);
      const prenda = items.map(i => `${i.nombre} x${i.cantidad}`).join(', ') || 'Venta MP';
      await adminSupabase.from('ventas').insert({
        user_id:      userId,
        cliente_id:   clienteId,
        prenda:       prenda,
        precio_venta: totalPago,
        costo:        0,
        pagado:       totalPago,
        adeuda:       0,
        cantidad:     items.reduce((s, i) => s + i.cantidad, 0) || 1,
        precio_unitario: totalPago,
        costo_unitario:  0,
        fecha_compra: (pago.date_approved || new Date().toISOString()).split('T')[0],
        notas:        `Pago MP #${pid}`,
        numero_venta: numero
      });
    }

    // Descontar stock
    for (const item of items) {
      if (!item.id) continue;
      const { data: variante } = await adminSupabase
        .from('producto_variantes').select('id, cantidad, producto_id')
        .eq('id', item.id).single();
      if (variante) {
        const nueva = Math.max(0, (variante.cantidad || 0) - item.cantidad);
        await adminSupabase.from('producto_variantes').update({ cantidad: nueva }).eq('id', item.id);
      }
    }

    synced++;
    yaProcesados.add(pid);
  }

  await adminSupabase.from('mp_conexiones')
    .update({ mp_last_sync: new Date().toISOString() }).eq('user_id', userId);

  return { synced, message: `${synced} pago(s) sincronizado(s)` };
}

// ── UPLOAD IMÁGENES (Supabase Storage) ────────────────────────────────────────
async function handleUploadImagenes(req, res, user) {
  // En serverless no podemos parsear multipart fácilmente sin librería.
  // Retornamos instrucciones para que el cliente suba directo a Supabase Storage.
  return json(res, 501, {
    error: 'Upload directo no disponible en serverless.',
    hint: 'Subí las imágenes directamente a Supabase Storage desde el cliente con la anon key.'
  });
}

// ── REGISTRO ──────────────────────────────────────────────────────────────────
async function handleRegistro(req, res) {
  const body = await parseBody(req);
  const { nombre, email, password, tipoCuenta, tiendaNombre, tiendaUrl, vercelDeployHook, tiendaConfigurada } = body;

  if (!nombre || !email || !password) return json(res, 400, { error: 'Nombre, email y contraseña son requeridos' });
  if (password.length < 8) return json(res, 400, { error: 'La contraseña debe tener al menos 8 caracteres' });
  if (!['gestion','gestion_tienda'].includes(tipoCuenta)) return json(res, 400, { error: 'Tipo de cuenta inválido' });

  // Verificar si los registros están habilitados
  const { data: cfgRegistros } = await adminSupabase.from('config_sistema').select('valor').eq('clave', 'registros_habilitados').single();
  if (cfgRegistros?.valor === 'false') return json(res, 403, { error: 'El registro de nuevas cuentas está deshabilitado.' });

  // Rate limit: 3 registros por IP por hora
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  const allowed = await rateLimit(`registro:${ip}`, 3, 60 * 60 * 1000);
  if (!allowed) return json(res, 429, { error: 'Demasiados registros desde tu IP. Esperá 1 hora.' });

  // Crear usuario en Supabase Auth
  const { data: authData, error: authError } = await adminSupabase.auth.admin.createUser({
    email, password, email_confirm: true,
    user_metadata: { nombre }
  });
  if (authError) {
    if (authError.message?.includes('already registered')) return json(res, 409, { error: 'Este email ya está registrado.' });
    return json(res, 500, { error: authError.message });
  }

  const userId = authData.user.id;

  // Crear perfil
  await adminSupabase.from('perfiles').insert({
    id: userId, nombre, rol: 'usuario', activo: true,
    tipo_cuenta: tipoCuenta,
    tienda_configurada: !!tiendaConfigurada
  });

  // Si tiene datos de tienda, guardar
  if (tipoCuenta === 'gestion_tienda' && tiendaUrl && tiendaNombre) {
    await adminSupabase.from('mp_conexiones').upsert({
      user_id: userId,
      tienda_nombre: tiendaNombre,
      tienda_url: tiendaUrl,
      vercel_deploy_hook: vercelDeployHook || '',
      conectado: false,
      updated_at: new Date().toISOString()
    }, { onConflict: 'user_id' });
  }

  // Log
  await logActividad(userId, email, 'nuevo_registro', `tipo: ${tipoCuenta}`, ip);

  // Auto-login
  const { data: loginData, error: loginError } = await adminSupabase.auth.signInWithPassword({ email, password });
  if (loginError) return json(res, 201, { ok: true, message: 'Cuenta creada. Iniciá sesión.' });

  return json(res, 201, {
    ok: true,
    token: loginData.session.access_token,
    user: { id: userId, email, rol: 'usuario', nombre, tipoCuenta, tiendaConfigurada: !!tiendaConfigurada }
  });
}

// ── ACTIVIDAD LOG ─────────────────────────────────────────────────────────────
async function logActividad(userId, email, accion, detalle = '', ip = '') {
  try {
    await adminSupabase.from('logs_actividad').insert({ user_id: userId || null, accion, detalle: `${email ? email+' — ' : ''}${detalle}`, ip });
  } catch {}
}

// ── ADMIN HANDLERS ────────────────────────────────────────────────────────────
async function handleAdminStats(req, res) {
  const now = new Date();
  const inicioMes = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

  const [
    { count: totalUsuarios },
    { data: ventasMes },
    { data: ventasOnlineMes },
    { count: cuentasConTienda },
    { count: mpConectados },
    { data: actividadReciente }
  ] = await Promise.all([
    adminSupabase.from('perfiles').select('*', { count: 'exact', head: true }).eq('rol', 'usuario'),
    adminSupabase.from('ventas').select('precio_venta').gte('created_at', inicioMes),
    adminSupabase.from('ventas_online').select('monto').gte('created_at', inicioMes),
    adminSupabase.from('perfiles').select('*', { count: 'exact', head: true }).eq('tipo_cuenta', 'gestion_tienda'),
    adminSupabase.from('mp_conexiones').select('*', { count: 'exact', head: true }).eq('conectado', true),
    adminSupabase.from('logs_actividad').select('accion, detalle, created_at').order('created_at', { ascending: false }).limit(20),
  ]);

  const facturadoMes = (ventasMes || []).reduce((s, v) => s + (parseFloat(v.precio_venta) || 0), 0);
  const ventasOnlineMesTotal = (ventasOnlineMes || []).reduce((s, v) => s + (parseFloat(v.monto) || 0), 0);

  // Usuarios activos este mes (con ventas o actividad)
  const { data: activosMesData } = await adminSupabase
    .from('logs_actividad').select('user_id').gte('created_at', inicioMes).not('user_id', 'is', null);
  const activosMes = new Set((activosMesData || []).map(a => a.user_id)).size;

  return json(res, 200, {
    totalUsuarios: totalUsuarios || 0, activosMes,
    facturadoMes, ventasOnlineMes: ventasOnlineMesTotal,
    cuentasConTienda: cuentasConTienda || 0, mpConectados: mpConectados || 0,
    actividadReciente: actividadReciente || []
  });
}

async function handleAdminGetUsuarios(req, res) {
  const { data: perfiles } = await adminSupabase.from('perfiles').select('*').order('created_at', { ascending: false });
  const { data: authUsers } = await adminSupabase.auth.admin.listUsers({ perPage: 1000 });
  const { data: mpData } = await adminSupabase.from('mp_conexiones').select('user_id, conectado');

  const mpMap = {};
  (mpData || []).forEach(m => { mpMap[m.user_id] = m.conectado; });
  const authMap = {};
  (authUsers?.users || []).forEach(u => { authMap[u.id] = u; });

  const result = (perfiles || []).map(p => ({
    id: p.id,
    nombre: p.nombre,
    email: authMap[p.id]?.email || '',
    rol: p.rol,
    activo: p.activo,
    tipoCuenta: p.tipo_cuenta,
    tiendaConfigurada: p.tienda_configurada,
    mpConectado: !!mpMap[p.id],
    ultimoAcceso: authMap[p.id]?.last_sign_in_at || null,
  }));

  return json(res, 200, result);
}

async function handleAdminPutUsuario(req, res, id) {
  const body = await parseBody(req);
  const updates = {};
  if (body.nombre      !== undefined) updates.nombre       = body.nombre;
  if (body.tipoCuenta  !== undefined) updates.tipo_cuenta  = body.tipoCuenta;
  if (body.activo      !== undefined) updates.activo       = !!body.activo;
  const { error } = await adminSupabase.from('perfiles').update(updates).eq('id', id);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

async function handleAdminToggleUsuario(req, res, id, activar) {
  const { error } = await adminSupabase.from('perfiles').update({ activo: activar }).eq('id', id);
  if (error) return json(res, 500, { error: error.message });
  await logActividad(null, 'admin', activar ? 'usuario_activado' : 'usuario_desactivado', `user_id: ${id}`);
  return json(res, 200, { ok: true });
}

async function handleAdminResetPassword(req, res, id) {
  const { data: authUser } = await adminSupabase.auth.admin.getUserById(id);
  if (!authUser?.user?.email) return json(res, 404, { error: 'Usuario no encontrado' });
  const { error } = await adminSupabase.auth.resetPasswordForEmail(authUser.user.email);
  if (error) return json(res, 500, { error: error.message });
  await logActividad(null, 'admin', 'reset_password_enviado', `email: ${authUser.user.email}`);
  return json(res, 200, { ok: true });
}

async function handleAdminCrearUsuario(req, res) {
  const body = await parseBody(req);
  const { nombre, email, password, tipoCuenta } = body;
  if (!nombre || !email || !password) return json(res, 400, { error: 'Faltan campos requeridos' });

  const { data: authData, error } = await adminSupabase.auth.admin.createUser({
    email, password, email_confirm: true, user_metadata: { nombre }
  });
  if (error) return json(res, 500, { error: error.message });

  await adminSupabase.from('perfiles').insert({
    id: authData.user.id, nombre, rol: 'usuario', activo: true,
    tipo_cuenta: tipoCuenta || 'gestion', tienda_configurada: false
  });
  await logActividad(null, 'admin', 'usuario_creado_por_admin', `email: ${email}`);
  return json(res, 201, { ok: true, id: authData.user.id });
}

async function handleAdminVentasGlobales(req, res) {
  const { data, error } = await adminSupabase
    .from('ventas_online')
    .select('*, perfiles!inner(nombre)')
    .order('created_at', { ascending: false })
    .limit(500);
  if (error) return json(res, 500, { error: error.message });
  const result = (data || []).map(v => ({
    ...v,
    cuenta: v.perfiles?.nombre || '—',
    comprador: (v.items?.[0]?.nombre || '').slice(0, 30),
    monto: (v.items || []).reduce((s, i) => s + (i.precio * i.cantidad), 0),
  }));
  return json(res, 200, result);
}

async function handleAdminActividad(req, res) {
  const { data: logs } = await adminSupabase
    .from('logs_actividad')
    .select('*, perfiles(nombre)')
    .order('created_at', { ascending: false })
    .limit(100);
  return json(res, 200, (logs || []).map(l => ({
    ...l, email: l.detalle?.split(' — ')?.[0] || l.perfiles?.nombre || '—'
  })));
}

async function handleAdminGetConfig(req, res) {
  const { data } = await adminSupabase.from('config_sistema').select('clave, valor');
  const cfg = {};
  (data || []).forEach(r => { cfg[r.clave] = r.valor; });
  return json(res, 200, cfg);
}

async function handleAdminPostConfig(req, res) {
  const body = await parseBody(req);
  const updates = Object.entries(body).map(([clave, valor]) => ({ clave, valor: String(valor), updated_at: new Date().toISOString() }));
  for (const row of updates) {
    await adminSupabase.from('config_sistema').upsert(row, { onConflict: 'clave' });
  }
  await logActividad(null, 'admin', 'config_sistema_actualizada', Object.keys(body).join(', '));
  return json(res, 200, { ok: true });
}

// ── SHIPPING QUOTE ────────────────────────────────────────────────────────────
async function handleShippingQuote(req, res) {
  const body = await parseBody(req);
  const { provincia, cp, peso } = body;

  try {
    const data = await getCorreoQuote({ cp, peso });
    if (!data) return json(res, 200, { envio: null });

    const tarifa = Array.isArray(data) ? data[0] : data;
    return json(res, 200, {
      envio: {
        precio:   tarifa?.price || tarifa?.precio || 0,
        dias:     tarifa?.deliveryDays || tarifa?.dias || '5-10',
        servicio: tarifa?.description || tarifa?.servicio || 'Correo Argentino'
      }
    });
  } catch (e) {
    return json(res, 200, { envio: null });
  }
}

// ── Exportar función de chequeo de cuotas (usada por cron) ───────────────────
module.exports.checkCuotasVencimiento = async function () {
  const { data: ventas } = await adminSupabase
    .from('ventas')
    .select('id, prenda, adeuda, prox_cuota, notificado_at, user_id, clientes(nombre, telefono)')
    .gt('adeuda', 0)
    .not('prox_cuota', 'is', null);

  if (!ventas?.length) return { notificados: 0 };

  const hoy = new Date().toISOString().split('T')[0];
  const enTresDias = new Date(Date.now() + 3 * 86400000).toISOString().split('T')[0];

  const vencer = ventas.filter(v => v.prox_cuota <= enTresDias && v.notificado_at !== hoy);
  if (!vencer.length) return { notificados: 0 };

  const lines = vencer.map(v => {
    const nombre = v.clientes?.nombre || 'Sin nombre';
    const tel    = v.clientes?.telefono || '';
    return `• ${nombre}${tel ? ` (${tel})` : ''} — ${v.prenda} — $${v.adeuda} — vence ${v.prox_cuota}`;
  }).join('\n');

  await sendEmail(
    `⚠️ Cuotas por vencer — ${hoy}`,
    `<p>Las siguientes cuotas vencen en los próximos 3 días:</p><pre>${lines}</pre>`
  );
  await sendTelegram(`⚠️ <b>Cuotas por vencer</b>\n\n${lines}`);

  // Marcar notificadas
  for (const v of vencer) {
    await adminSupabase.from('ventas').update({ notificado_at: hoy }).eq('id', v.id);
  }

  return { notificados: vencer.length };
};

// Exportar doMpSync para el cron
module.exports.doMpSync = doMpSync;

// ── HANDLERS DE CRON (se ejecutan cuando el rewrite los redirige al catch-all) ──
async function handleCronCheckCuotas(req, res) {
  const secret = process.env.CRON_SECRET;
  const auth   = req.headers['authorization'] || '';
  if (secret && auth !== `Bearer ${secret}`) return json(res, 401, { error: 'Unauthorized' });
  try {
    const result = await module.exports.checkCuotasVencimiento();
    return json(res, 200, { ok: true, ...result });
  } catch (err) {
    return json(res, 500, { error: err.message });
  }
}

async function handleCronSyncMp(req, res) {
  const secret = process.env.CRON_SECRET;
  const auth   = req.headers['authorization'] || '';
  if (secret && auth !== `Bearer ${secret}`) return json(res, 401, { error: 'Unauthorized' });
  const { data: conexiones } = await adminSupabase
    .from('mp_conexiones').select('user_id').eq('conectado', true);
  if (!conexiones?.length) return json(res, 200, { ok: true, message: 'Sin usuarios con MP conectado' });
  const results = [];
  for (const { user_id } of conexiones) {
    try { results.push({ user_id, ...(await doMpSync(user_id)) }); }
    catch (err) { results.push({ user_id, error: err.message }); }
  }
  return json(res, 200, { ok: true, results });
}
