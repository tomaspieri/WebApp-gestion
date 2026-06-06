// Servidor de Gestión de Ventas — Supabase + Auth multisucursal
'use strict';

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const os    = require('os');
const { createCipheriv, createDecipheriv, randomBytes } = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');

// ─── ENV ──────────────────────────────────────────────────────────────────────
const SUPABASE_URL         = process.env.SUPABASE_URL         || '';
const SUPABASE_ANON_KEY    = process.env.SUPABASE_ANON_KEY    || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_KEY) {
  console.error('[ERROR] Faltan SUPABASE_URL, SUPABASE_ANON_KEY o SUPABASE_SERVICE_KEY');
  process.exit(1);
}

// ─── SUPABASE ────────────────────────────────────────────────────────────────
function supabaseAdmin() {
  return createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

async function requireAuth(req) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;

  // Token interno servidor→servidor
  const syncToken = process.env.GESTION_SYNC_TOKEN;
  if (syncToken && token === syncToken)
    return { userId: null, email: 'system', rol: 'system', nombre: 'System' };

  const anonClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  });
  const { data: { user }, error } = await anonClient.auth.getUser();
  if (error || !user) return null;

  const { data: perfil } = await supabaseAdmin()
    .from('perfiles').select('rol, nombre, activo').eq('id', user.id).single();
  if (!perfil || !perfil.activo) return null;

  return { userId: user.id, email: user.email, rol: perfil.rol, nombre: perfil.nombre };
}

// ─── LOCAL CONFIG (Telegram, no va a Supabase) ────────────────────────────────
const CONFIG_PATH = path.join(__dirname, 'gestion-config.json');

function getLocalConfig(key) {
  try { return (JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')))[key] ?? null; }
  catch { return null; }
}
function setLocalConfig(key, value) {
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); } catch {}
  cfg[key] = value;
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), 'utf8');
}

// ─── ENCRIPTACIÓN AES-256-GCM ─────────────────────────────────────────────────
const ALG = 'aes-256-gcm';
function _encKey() {
  const k = process.env.ENCRYPTION_KEY;
  if (!k || k.length !== 64) throw new Error('ENCRYPTION_KEY inválida (debe ser 64 chars hex)');
  return Buffer.from(k, 'hex');
}
function encrypt(text) {
  const iv  = randomBytes(12);
  const c   = createCipheriv(ALG, _encKey(), iv);
  const enc = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return `${iv.toString('hex')}:${c.getAuthTag().toString('hex')}:${enc.toString('hex')}`;
}
function decrypt(ciphertext) {
  const [ivH, tagH, encH] = ciphertext.split(':');
  if (!ivH || !tagH || !encH) throw new Error('Token encriptado inválido');
  const d = createDecipheriv(ALG, _encKey(), Buffer.from(ivH, 'hex'));
  d.setAuthTag(Buffer.from(tagH, 'hex'));
  return Buffer.concat([d.update(Buffer.from(encH, 'hex')), d.final()]).toString('utf8');
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

function json(res, code, data) {
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', c => { raw += c; });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch { reject(new Error('JSON inválido')); }
    });
    req.on('error', reject);
  });
}

function getLocalIP() {
  for (const ifaces of Object.values(os.networkInterfaces()))
    for (const i of ifaces)
      if (i.family === 'IPv4' && !i.internal) return i.address;
  return 'localhost';
}

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
const _rateMap = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const e   = _rateMap.get(key) || { count: 0, reset: now + windowMs };
  if (now > e.reset) { e.count = 0; e.reset = now + windowMs; }
  e.count++;
  _rateMap.set(key, e);
  if (_rateMap.size > 500) for (const [k, v] of _rateMap) if (now > v.reset) _rateMap.delete(k);
  return e.count <= max;
}

// ─── TRANSFORMS snake_case → camelCase ───────────────────────────────────────
function toCliente(c) {
  return { id: c.id, nombre: c.nombre, telefono: c.telefono || '', notas: c.notas || '', createdAt: c.created_at };
}
function toVenta(v) {
  return {
    id: v.id, clienteId: v.cliente_id, prenda: v.prenda,
    precioVenta: v.precio_venta, costo: v.costo, pagado: v.pagado, adeuda: v.adeuda,
    cantidad: v.cantidad || 1, precioUnitario: v.precio_unitario || 0, costoUnitario: v.costo_unitario || 0,
    fechaCompra: v.fecha_compra, proxCuota: v.prox_cuota, notas: v.notas || '',
    notificadoAt: v.notificado_at, numeroVenta: v.numero_venta,
    createdAt: v.created_at, updatedAt: v.updated_at,
  };
}
function toGasto(g) {
  return {
    id: g.id, descripcion: g.descripcion, monto: g.monto, fecha: g.fecha,
    categoria: g.categoria || '', notas: g.notas || '',
    cantidad: g.cantidad || 1, precioUnitario: g.precio_unitario || 0,
    createdAt: g.created_at,
  };
}
function toVariante(v) {
  return {
    id: v.id, productoId: v.producto_id, tipo: v.tipo, nombre: v.nombre,
    cantidad: v.cantidad || 0, imagen: v.imagen || '', colorId: v.color_id || '',
  };
}
function toProducto(p) {
  let imagenes = [];
  try { imagenes = Array.isArray(p.imagenes) ? p.imagenes : JSON.parse(p.imagenes || '[]'); } catch {}
  return {
    id: p.id, nombre: p.nombre, categoria: p.categoria || '',
    precio: p.precio || 0, costo: p.costo || 0, imagenUrl: p.imagen_url || '',
    descripcion: p.descripcion || '', guia_de_talles: p.guia_de_talles || '',
    imagenes, peso: p.peso || 0, dimensiones: p.dimensiones || '',
    nuevo: !!p.nuevo, activo: !!p.activo,
    createdAt: p.created_at, updatedAt: p.updated_at,
    variantes: (p.producto_variantes || []).map(toVariante),
  };
}

// ─── EMAIL ────────────────────────────────────────────────────────────────────
function crearTransportBrevo() {
  return nodemailer.createTransport({
    host: 'smtp-relay.brevo.com', port: 587, secure: false,
    auth: {
      user: 'ab17ad001@smtp-brevo.com',
      pass: process.env.BREVO_SMTP_PASS,
    },
  });
}

async function enviarEmailNotificacion(venta) {
  const itemsHtml = (venta.items || []).map(i => `<li>${i.t} × ${i.q} — $${i.p}</li>`).join('');
  await crearTransportBrevo().sendMail({
    from: '"CHANA Indumentaria" <tomipieri@hotmail.com>',
    to: 'sanlatorre@hotmail.com, chanaindumentaria@hotmail.com',
    subject: `🛍 Nueva venta #${String(venta.numeroVenta).padStart(4,'0')} — ${venta.clienteNombre}`,
    html: `<h2>Nueva venta en CHANA Indumentaria</h2>
      <p><strong>Venta #${String(venta.numeroVenta).padStart(4,'0')}</strong></p>
      <p><strong>Cliente:</strong> ${venta.clienteNombre} — <strong>Email:</strong> ${venta.clienteEmail}</p>
      <p><strong>Teléfono:</strong> ${venta.clienteTel} — <strong>Envío:</strong> ${venta.envio}</p>
      <ul>${itemsHtml}</ul>
      <p><strong>Total:</strong> $${venta.total} — <strong>MP ID:</strong> ${venta.paymentId}</p>
      <p><strong>Fecha:</strong> ${venta.fecha}</p>`,
  });
}

async function enviarEmailCliente(venta) {
  if (!venta.clienteEmail) return;
  const itemsHtml = (venta.items || []).map(i => `<li>${i.t} × ${i.q}</li>`).join('');
  await crearTransportBrevo().sendMail({
    from: '"CHANA Indumentaria" <tomipieri@hotmail.com>',
    to: venta.clienteEmail,
    subject: `Tu pedido CHANA #${String(venta.numeroVenta).padStart(4,'0')} fue confirmado ✅`,
    html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto">
      <h2 style="color:#111">¡Gracias por tu compra, ${venta.clienteNombre}!</h2>
      <p>Tu pedido fue confirmado y estamos preparándolo.</p>
      <div style="background:#f8f8f8;border-radius:8px;padding:16px;margin:16px 0">
        <p style="margin:0;font-size:18px;font-weight:bold">Pedido #${String(venta.numeroVenta).padStart(4,'0')}</p>
      </div>
      <ul>${itemsHtml}</ul>
      <p><strong>Total pagado:</strong> $${venta.total} — <strong>Forma de entrega:</strong> ${venta.envio}</p>
      <hr/><p style="font-size:12px;color:#888">CHANA Indumentaria — Alem 1653, Castelar, Buenos Aires</p>
    </div>`,
  });
}

// ─── TELEGRAM ────────────────────────────────────────────────────────────────
function sendTelegram(token, chatId, text) {
  const url = `https://api.telegram.org/bot${token}/sendMessage?chat_id=${chatId}&text=${encodeURIComponent(text)}`;
  https.get(url, r => {
    let b = '';
    r.on('data', d => b += d);
    r.on('end', () => {
      const rj = JSON.parse(b);
      if (rj.ok) console.log(`[Telegram] Enviado a ${chatId}`);
      else        console.error(`[Telegram] Error: ${rj.description}`);
    });
  }).on('error', e => console.error('[Telegram] Error de red:', e.message));
}

async function checkCuotasVencimiento() {
  const token  = getLocalConfig('tg_token');
  const chatId = getLocalConfig('tg_chatid');
  const dias   = parseInt(getLocalConfig('wa_dias') || '3');
  if (!token || !chatId) return;

  const hoy       = new Date();
  const hoyStr    = hoy.toISOString().split('T')[0];
  const limiteStr = new Date(hoy.getTime() + dias * 864e5).toISOString().split('T')[0];

  const { data: filas } = await supabaseAdmin()
    .from('ventas')
    .select('id, cliente_id, adeuda, prox_cuota, notificado_at, clientes(nombre)')
    .gt('adeuda', 0)
    .not('prox_cuota', 'is', null)
    .lte('prox_cuota', limiteStr);

  if (!filas?.length) return;

  const toNotify = filas.filter(v =>
    v.prox_cuota && (!v.notificado_at || v.notificado_at !== hoyStr)
  );
  if (!toNotify.length) return;

  const porCliente = {};
  for (const v of toNotify) {
    const cid = v.cliente_id;
    if (!porCliente[cid]) porCliente[cid] = {
      nombre: v.clientes?.nombre || 'Desconocido',
      totalAdeuda: 0, proxCuota: v.prox_cuota, ids: [],
    };
    porCliente[cid].totalAdeuda += parseFloat(v.adeuda) || 0;
    if (v.prox_cuota < porCliente[cid].proxCuota) porCliente[cid].proxCuota = v.prox_cuota;
    porCliente[cid].ids.push(v.id);
  }

  const lineasVenc = [], lineasProx = [];
  for (const d of Object.values(porCliente)) {
    const [ay, am, ad] = d.proxCuota.split('-');
    const fmt   = `${ad}/${am}/${ay}`;
    const monto = `$${d.totalAdeuda.toLocaleString('es-AR', { minimumFractionDigits: 2 })}`;
    if (d.proxCuota < hoyStr) lineasVenc.push(`• ${d.nombre}: ${monto} (venció el ${fmt})`);
    else                       lineasProx.push(`• ${d.nombre}: ${monto} (vence el ${fmt})`);
  }

  let msg = '';
  if (lineasVenc.length) msg += `⚠️ CUOTAS VENCIDAS:\n${lineasVenc.join('\n')}`;
  if (lineasProx.length) { if (msg) msg += '\n\n'; msg += `📅 PRÓXIMAS (${dias} días):\n${lineasProx.join('\n')}`; }
  sendTelegram(token, chatId, msg);

  const allIds = Object.values(porCliente).flatMap(d => d.ids);
  await supabaseAdmin().from('ventas').update({ notificado_at: hoyStr }).in('id', allIds);
  console.log(`[Cuotas] Notificadas — ${Object.keys(porCliente).length} cliente(s)`);
}

// ─── MP TOKEN ─────────────────────────────────────────────────────────────────
async function getMpToken(userId) {
  const { data } = await supabaseAdmin()
    .from('mp_conexiones').select('access_token_encrypted, conectado').eq('user_id', userId).single();
  if (!data?.conectado || !data.access_token_encrypted) return null;
  try { return decrypt(data.access_token_encrypted); } catch { return null; }
}

async function getSitioPath(userId) {
  const { data } = await supabaseAdmin()
    .from('mp_conexiones').select('sitio_path').eq('user_id', userId).single();
  return data?.sitio_path || '';
}

// ─── NUMERO DE VENTA ──────────────────────────────────────────────────────────
async function nextNumeroVenta(userId) {
  const sb = supabaseAdmin();
  const { data } = await sb.from('contadores').select('venta_counter').eq('user_id', userId).maybeSingle();
  const next = (data?.venta_counter || 0) + 1;
  await sb.from('contadores').upsert({ user_id: userId, venta_counter: next }, { onConflict: 'user_id' });
  return next;
}

// ─── RUTAS PÚBLICAS ───────────────────────────────────────────────────────────
const PUBLIC = ['/health', '/api/auth/login', '/api/mp/callback'];

// ─── ROUTER ───────────────────────────────────────────────────────────────────
async function handleRequest(req, res) {
  const urlObj = new URL(req.url, 'http://localhost');
  const p      = urlObj.pathname;
  const method = req.method;

  // OPTIONS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    });
    res.end(); return;
  }

  // ── Auth middleware ────────────────────────────────────────────────────────
  if (p.startsWith('/api/') && !PUBLIC.some(pp => p === pp || p.startsWith(pp + '?'))) {
    req._user = await requireAuth(req);
    if (!req._user) return json(res, 401, { error: 'No autenticado. Iniciá sesión.' });
  }

  const user = req._user;

  // ── Health ──────────────────────────────────────────────────────────────────
  if (p === '/health' && method === 'GET')
    return json(res, 200, { ok: true, uptime: Math.round(process.uptime()) });

  // ── Auth: login ─────────────────────────────────────────────────────────────
  if (p === '/api/auth/login' && method === 'POST') {
    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'x').split(',')[0].trim();
    if (!rateLimit(`login:${ip}`, 5, 15 * 60 * 1000))
      return json(res, 429, { error: 'Demasiados intentos. Esperá 15 minutos.' });
    const b  = await readBody(req);
    const sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false } });
    const { data, error } = await sb.auth.signInWithPassword({
      email: (b.email || '').trim().toLowerCase(), password: b.password,
    });
    if (error || !data?.session) return json(res, 401, { error: 'Credenciales incorrectas' });
    const { data: perfil } = await supabaseAdmin()
      .from('perfiles').select('rol, nombre').eq('id', data.user.id).single();
    return json(res, 200, {
      ok: true,
      access_token: data.session.access_token,
      rol: perfil?.rol || 'usuario',
      nombre: perfil?.nombre || '',
    });
  }

  // ── Auth: me ────────────────────────────────────────────────────────────────
  if (p === '/api/auth/me' && method === 'GET')
    return json(res, 200, { userId: user.userId, email: user.email, rol: user.rol, nombre: user.nombre });

  // ── Auth: usuarios (admin) ───────────────────────────────────────────────────
  if (p === '/api/auth/usuarios' && method === 'GET') {
    if (user.rol !== 'admin') return json(res, 403, { error: 'Solo admin' });
    const { data } = await supabaseAdmin().from('perfiles').select('id, nombre, rol, activo');
    return json(res, 200, data || []);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Helper: resuelve el userId efectivo según rol
  const uid = () => {
    if (user.rol === 'system' || user.rol === 'admin') {
      const fu = urlObj.searchParams.get('userId');
      return fu || user.userId;
    }
    return user.userId;
  };

  // ── Clientes ─────────────────────────────────────────────────────────────────
  if (p === '/api/clientes' && method === 'GET') {
    const sb = supabaseAdmin();
    let q = sb.from('clientes').select('*').order('nombre');
    if (user.rol !== 'admin' && user.rol !== 'system') q = q.eq('user_id', user.userId);
    else if (urlObj.searchParams.get('userId')) q = q.eq('user_id', urlObj.searchParams.get('userId'));
    const { data, error } = await q;
    if (error) return json(res, 500, { error: error.message });
    return json(res, 200, (data || []).map(toCliente));
  }

  if (p === '/api/clientes' && method === 'POST') {
    const b = await readBody(req);
    if (!b.nombre?.trim()) return json(res, 400, { error: 'Nombre requerido' });
    const { data, error } = await supabaseAdmin().from('clientes').insert({
      user_id: user.userId, nombre: b.nombre.trim(),
      telefono: (b.telefono || '').trim(), notas: (b.notas || '').trim(),
    }).select().single();
    if (error) return json(res, 500, { error: error.message });
    return json(res, 201, toCliente(data));
  }

  const mC = p.match(/^\/api\/clientes\/([^/]+)$/);
  if (mC) {
    const id = mC[1];
    const { data: ex } = await supabaseAdmin().from('clientes').select('user_id').eq('id', id).single();
    if (!ex) return json(res, 404, { error: 'No encontrado' });
    if (user.rol === 'usuario' && ex.user_id !== user.userId) return json(res, 403, { error: 'Sin permiso' });
    if (method === 'PUT') {
      const b = await readBody(req);
      const { data, error } = await supabaseAdmin().from('clientes')
        .update({ nombre: b.nombre?.trim() || '', telefono: (b.telefono||'').trim(), notas: (b.notas||'').trim() })
        .eq('id', id).select().single();
      if (error) return json(res, 500, { error: error.message });
      return json(res, 200, toCliente(data));
    }
    if (method === 'DELETE') {
      await supabaseAdmin().from('ventas').delete().eq('cliente_id', id);
      await supabaseAdmin().from('clientes').delete().eq('id', id);
      return json(res, 200, { ok: true });
    }
  }

  // ── Ventas ──────────────────────────────────────────────────────────────────
  if (p === '/api/ventas' && method === 'GET') {
    let q = supabaseAdmin().from('ventas').select('*').order('fecha_compra', { ascending: false });
    const cid = urlObj.searchParams.get('clienteId');
    if (cid) q = q.eq('cliente_id', cid);
    if (user.rol === 'usuario') q = q.eq('user_id', user.userId);
    else if (urlObj.searchParams.get('userId')) q = q.eq('user_id', urlObj.searchParams.get('userId'));
    const { data, error } = await q;
    if (error) return json(res, 500, { error: error.message });
    return json(res, 200, (data || []).map(toVenta));
  }

  if (p === '/api/ventas' && method === 'POST') {
    const b    = await readBody(req);
    const cant = Math.max(1, parseInt(b.cantidad) || 1);
    const pu   = parseFloat(b.precioUnitario) || 0;
    const cu   = parseFloat(b.costoUnitario)  || 0;
    const pg   = parseFloat(b.pagado) || 0;
    const pv   = pu * cant;
    const { data, error } = await supabaseAdmin().from('ventas').insert({
      user_id: user.userId, cliente_id: b.clienteId,
      prenda: (b.prenda || '').trim(), precio_venta: pv, costo: cu * cant,
      pagado: pg, adeuda: Math.max(0, pv - pg),
      cantidad: cant, precio_unitario: pu, costo_unitario: cu,
      fecha_compra: b.fechaCompra || null, prox_cuota: b.proxCuota || null,
      notas: (b.notas || '').trim(),
    }).select().single();
    if (error) return json(res, 500, { error: error.message });
    return json(res, 201, toVenta(data));
  }

  const mV = p.match(/^\/api\/ventas\/([^/]+)$/);
  if (mV) {
    const id = mV[1];
    const { data: ex } = await supabaseAdmin().from('ventas').select('user_id').eq('id', id).single();
    if (!ex) return json(res, 404, { error: 'No encontrado' });
    if (user.rol === 'usuario' && ex.user_id !== user.userId) return json(res, 403, { error: 'Sin permiso' });
    if (method === 'PUT') {
      const b    = await readBody(req);
      const cant = Math.max(1, parseInt(b.cantidad) || 1);
      const pu   = parseFloat(b.precioUnitario) || 0;
      const cu   = parseFloat(b.costoUnitario)  || 0;
      const pg   = parseFloat(b.pagado) || 0;
      const pv   = pu * cant;
      const { data, error } = await supabaseAdmin().from('ventas').update({
        cliente_id: b.clienteId, prenda: (b.prenda || '').trim(),
        precio_venta: pv, costo: cu * cant, pagado: pg, adeuda: Math.max(0, pv - pg),
        cantidad: cant, precio_unitario: pu, costo_unitario: cu,
        fecha_compra: b.fechaCompra || null, prox_cuota: b.proxCuota || null,
        notas: (b.notas || '').trim(), updated_at: new Date().toISOString(),
      }).eq('id', id).select().single();
      if (error) return json(res, 500, { error: error.message });
      return json(res, 200, toVenta(data));
    }
    if (method === 'DELETE') {
      await supabaseAdmin().from('ventas').delete().eq('id', id);
      return json(res, 200, { ok: true });
    }
  }

  // ── Gastos ──────────────────────────────────────────────────────────────────
  if (p === '/api/gastos' && method === 'GET') {
    let q = supabaseAdmin().from('gastos').select('*').order('fecha', { ascending: false });
    if (user.rol === 'usuario') q = q.eq('user_id', user.userId);
    else if (urlObj.searchParams.get('userId')) q = q.eq('user_id', urlObj.searchParams.get('userId'));
    const { data, error } = await q;
    if (error) return json(res, 500, { error: error.message });
    return json(res, 200, (data || []).map(toGasto));
  }

  if (p === '/api/gastos' && method === 'POST') {
    const b    = await readBody(req);
    const cant = Math.max(1, parseInt(b.cantidad) || 1);
    const pu   = parseFloat(b.precioUnitario) || 0;
    const { data, error } = await supabaseAdmin().from('gastos').insert({
      user_id: user.userId, descripcion: (b.descripcion || '').trim(),
      monto: pu * cant, fecha: b.fecha || null,
      categoria: (b.categoria || '').trim(), notas: (b.notas || '').trim(),
      cantidad: cant, precio_unitario: pu,
    }).select().single();
    if (error) return json(res, 500, { error: error.message });
    return json(res, 201, toGasto(data));
  }

  const mG = p.match(/^\/api\/gastos\/([^/]+)$/);
  if (mG) {
    const id = mG[1];
    const { data: ex } = await supabaseAdmin().from('gastos').select('user_id').eq('id', id).single();
    if (!ex) return json(res, 404, { error: 'No encontrado' });
    if (user.rol === 'usuario' && ex.user_id !== user.userId) return json(res, 403, { error: 'Sin permiso' });
    if (method === 'PUT') {
      const b    = await readBody(req);
      const cant = Math.max(1, parseInt(b.cantidad) || 1);
      const pu   = parseFloat(b.precioUnitario) || 0;
      const { data, error } = await supabaseAdmin().from('gastos').update({
        descripcion: (b.descripcion || '').trim(), monto: pu * cant,
        fecha: b.fecha || null, categoria: (b.categoria || '').trim(),
        notas: (b.notas || '').trim(), cantidad: cant, precio_unitario: pu,
      }).eq('id', id).select().single();
      if (error) return json(res, 500, { error: error.message });
      return json(res, 200, toGasto(data));
    }
    if (method === 'DELETE') {
      await supabaseAdmin().from('gastos').delete().eq('id', id);
      return json(res, 200, { ok: true });
    }
  }

  // ── Configuración Telegram ──────────────────────────────────────────────────
  if (p === '/api/config' && method === 'GET')
    return json(res, 200, {
      tg_token: getLocalConfig('tg_token')  || '',
      tg_chatid: getLocalConfig('tg_chatid') || '',
      wa_dias: getLocalConfig('wa_dias')    || '3',
    });

  if (p === '/api/config' && method === 'POST') {
    const b = await readBody(req);
    for (const [k, v] of Object.entries(b)) setLocalConfig(k, v);
    return json(res, 200, { ok: true });
  }

  if (p === '/api/notificar-ahora' && method === 'POST') {
    const { error } = await supabaseAdmin()
      .from('ventas').update({ notificado_at: null }).gt('adeuda', 0);
    if (error) console.error('[Notificar]', error.message);
    await checkCuotasVencimiento();
    return json(res, 200, { ok: true });
  }

  if (p === '/api/test-telegram' && method === 'POST') {
    const token  = getLocalConfig('tg_token');
    const chatId = getLocalConfig('tg_chatid');
    if (!token || !chatId) return json(res, 400, { error: 'Token o Chat ID no configurado' });
    return new Promise(resolve => {
      const url = `https://api.telegram.org/bot${token}/sendMessage?chat_id=${chatId}&text=${encodeURIComponent('✅ Conexión exitosa!')}`;
      https.get(url, r => {
        let b = '';
        r.on('data', d => b += d);
        r.on('end', () => resolve(json(res, JSON.parse(b).ok ? 200 : 400, JSON.parse(b))));
      }).on('error', e => resolve(json(res, 500, { error: e.message })));
    });
  }

  // ── Productos ────────────────────────────────────────────────────────────────
  if (p === '/api/productos' && method === 'GET') {
    let q = supabaseAdmin().from('productos').select('*, producto_variantes(*)').order('nombre');
    if (user.rol === 'usuario') q = q.eq('user_id', user.userId);
    else if (urlObj.searchParams.get('userId')) q = q.eq('user_id', urlObj.searchParams.get('userId'));
    q = q.eq('activo', true);
    const { data, error } = await q;
    if (error) return json(res, 500, { error: error.message });
    return json(res, 200, (data || []).map(toProducto));
  }

  if (p === '/api/productos' && method === 'POST') {
    const b = await readBody(req);
    if (!b.nombre?.trim()) return json(res, 400, { error: 'Nombre requerido' });
    let imagenes = Array.isArray(b.imagenes) ? b.imagenes : [];
    const { data, error } = await supabaseAdmin().from('productos').insert({
      user_id: user.userId, nombre: b.nombre.trim(),
      categoria: (b.categoria || '').trim(), precio: parseFloat(b.precio) || 0,
      costo: parseFloat(b.costo) || 0, imagen_url: (b.imagenUrl || '').trim(),
      descripcion: (b.descripcion || '').trim(), guia_de_talles: (b.guia_de_talles || '').trim(),
      imagenes, peso: parseInt(b.peso) || 0, dimensiones: (b.dimensiones || '').trim(),
      nuevo: !!b.nuevo, activo: true,
    }).select().single();
    if (error) return json(res, 500, { error: error.message });
    return json(res, 201, { ...toProducto(data), variantes: [] });
  }

  const mProd = p.match(/^\/api\/productos\/([^/]+)$/);
  if (mProd) {
    const id = mProd[1];
    const { data: ex } = await supabaseAdmin().from('productos').select('user_id').eq('id', id).single();
    if (!ex) return json(res, 404, { error: 'No encontrado' });
    if (user.rol === 'usuario' && ex.user_id !== user.userId) return json(res, 403, { error: 'Sin permiso' });
    if (method === 'PUT') {
      const b = await readBody(req);
      let imagenes = Array.isArray(b.imagenes) ? b.imagenes : [];
      const { data, error } = await supabaseAdmin().from('productos').update({
        nombre: (b.nombre || '').trim(), categoria: (b.categoria || '').trim(),
        precio: parseFloat(b.precio) || 0, costo: parseFloat(b.costo) || 0,
        imagen_url: (b.imagenUrl || '').trim(), descripcion: (b.descripcion || '').trim(),
        guia_de_talles: (b.guia_de_talles || '').trim(), imagenes,
        peso: parseInt(b.peso) || 0, dimensiones: (b.dimensiones || '').trim(),
        nuevo: !!b.nuevo, updated_at: new Date().toISOString(),
      }).eq('id', id).select('*, producto_variantes(*)').single();
      if (error) return json(res, 500, { error: error.message });
      return json(res, 200, toProducto(data));
    }
    if (method === 'DELETE') {
      await supabaseAdmin().from('productos').update({ activo: false, updated_at: new Date().toISOString() }).eq('id', id);
      return json(res, 200, { ok: true });
    }
  }

  // ── Upload imágenes ───────────────────────────────────────────────────────
  if (p === '/api/upload-imagenes' && method === 'POST') {
    const b = await readBody(req);
    const { productoId, images } = b;
    if (!productoId || !Array.isArray(images) || !images.length)
      return json(res, 400, { error: 'productoId e images requeridos' });
    const sitioPth = await getSitioPath(user.userId);
    if (!sitioPth) return json(res, 400, { error: 'sitio_path no configurado en Stock > Configuración' });
    const destDir = path.join(sitioPth, 'sitio', 'assets', 'productos', productoId);
    fs.mkdirSync(destDir, { recursive: true });
    const savedPaths = [];
    for (const img of images) {
      const origExt = path.extname(img.filename || '').toLowerCase();
      const safeExt = ['.jpg','.jpeg','.png','.webp','.gif'].includes(origExt) ? origExt : '.jpg';
      const filename = `${Date.now()}-${Math.random().toString(36).slice(2)}${safeExt}`;
      const b64 = (img.b64 || '').replace(/^data:[^;]+;base64,/, '');
      fs.writeFileSync(path.join(destDir, filename), Buffer.from(b64, 'base64'));
      savedPaths.push(`assets/productos/${productoId}/${filename}`);
    }
    return json(res, 200, { ok: true, paths: savedPaths });
  }

  // ── Preview imagen ─────────────────────────────────────────────────────────
  if (p.startsWith('/api/preview-imagen') && method === 'GET') {
    const imgPath = urlObj.searchParams.get('path');
    if (!imgPath || imgPath.includes('..')) return json(res, 400, { error: 'path inválido' });
    const sitioPth = await getSitioPath(user.userId);
    if (!sitioPth) return json(res, 404, { error: 'sitio_path no configurado' });
    const filePath = path.join(sitioPth, 'sitio', imgPath);
    if (!fs.existsSync(filePath)) return json(res, 404, { error: 'No encontrado' });
    const ext   = path.extname(filePath).toLowerCase();
    const mimes = { '.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.webp':'image/webp','.gif':'image/gif' };
    res.writeHead(200, { 'Content-Type': mimes[ext] || 'application/octet-stream', 'Access-Control-Allow-Origin': ALLOWED_ORIGIN });
    fs.createReadStream(filePath).pipe(res);
    return;
  }

  // ── Variantes ──────────────────────────────────────────────────────────────
  if (p === '/api/variantes' && method === 'POST') {
    const b = await readBody(req);
    if (!b.productoId || !b.tipo || !b.nombre) return json(res, 400, { error: 'productoId, tipo y nombre requeridos' });
    const { data, error } = await supabaseAdmin().from('producto_variantes').insert({
      user_id: user.userId, producto_id: b.productoId,
      tipo: (b.tipo || '').trim(), nombre: (b.nombre || '').trim(),
      cantidad: parseInt(b.cantidad) || 0, imagen: (b.imagen || '').trim(),
      color_id: b.colorId || null,
    }).select().single();
    if (error) return json(res, 500, { error: error.message });
    return json(res, 201, toVariante(data));
  }

  const mVar = p.match(/^\/api\/variantes\/([^/]+)$/);
  if (mVar) {
    const id = mVar[1];
    if (method === 'PUT') {
      const b = await readBody(req);
      const { data, error } = await supabaseAdmin().from('producto_variantes').update({
        nombre: (b.nombre || '').trim(), cantidad: parseInt(b.cantidad) || 0,
        imagen: (b.imagen || '').trim(), color_id: b.colorId || null,
      }).eq('id', id).select().single();
      if (error) return json(res, 500, { error: error.message });
      return json(res, 200, toVariante(data));
    }
    if (method === 'DELETE') {
      await supabaseAdmin().from('producto_variantes').delete().eq('id', id);
      return json(res, 200, { ok: true });
    }
  }

  // ── Ventas Online ──────────────────────────────────────────────────────────
  if (p === '/api/ventas-online' && method === 'GET') {
    let q = supabaseAdmin().from('ventas_online').select('*').eq('estado', 'pendiente').order('created_at', { ascending: false });
    if (user.rol === 'usuario') q = q.eq('user_id', user.userId);
    const { data, error } = await q;
    if (error) return json(res, 500, { error: error.message });
    return json(res, 200, data || []);
  }

  if (p === '/api/ventas-online/procesar' && method === 'POST') {
    const b = await readBody(req);
    const ids = Array.isArray(b.ids) ? b.ids : [];
    let procesadas = 0;
    for (const id of ids) {
      const { data: venta } = await supabaseAdmin().from('ventas_online').select('*').eq('id', id).single();
      if (!venta) continue;
      const items = Array.isArray(venta.items) ? venta.items : [];
      for (const item of items) {
        if (item.varianteId) {
          const { data: varActual } = await supabaseAdmin().from('producto_variantes').select('cantidad').eq('id', item.varianteId).single();
          if (varActual)
            await supabaseAdmin().from('producto_variantes').update({ cantidad: Math.max(0, (varActual.cantidad || 0) - (item.qty || 1)) }).eq('id', item.varianteId);
        }
      }
      await supabaseAdmin().from('ventas_online').update({ estado: 'procesado' }).eq('id', id);
      procesadas++;
    }
    return json(res, 200, { ok: true, procesadas });
  }

  // ── Sync MP ────────────────────────────────────────────────────────────────
  if (p === '/api/sync-mp' && method === 'POST') {
    let usersToSync = [];
    if (user.rol === 'system' || user.rol === 'admin') {
      // Sincronizar todos los usuarios con MP conectado
      const { data: conexiones } = await supabaseAdmin()
        .from('mp_conexiones').select('user_id').eq('conectado', true);
      usersToSync = (conexiones || []).map(c => c.user_id);
    } else {
      usersToSync = [user.userId];
    }

    let totalNuevas = 0;
    const detalleTotal = [];

    for (const userId of usersToSync) {
      const mpToken = await getMpToken(userId);
      if (!mpToken) continue;

      const beginDate = new Date(Date.now() - 30 * 864e5).toISOString().split('.')[0] + '.000-00:00';
      const endDate   = new Date(Date.now() + 864e5).toISOString().split('.')[0] + '.000-00:00';
      const url = `https://api.mercadopago.com/v1/payments/search?status=approved&operation_type=regular_payment&sort=date_created&criteria=desc&range=date_created&begin_date=${encodeURIComponent(beginDate)}&end_date=${encodeURIComponent(endDate)}&limit=50`;

      let payments = [];
      try {
        const mpRes = await new Promise((resolve, reject) => {
          https.get(url, { headers: { Authorization: `Bearer ${mpToken}` } }, r => {
            let body = ''; r.on('data', d => body += d); r.on('end', () => resolve(JSON.parse(body)));
          }).on('error', reject);
        });
        payments = mpRes.results || [];
      } catch (e) {
        console.error(`[Sync] Error MP user ${userId}:`, e.message); continue;
      }

      for (const pago of payments) {
        const pid = String(pago.id);
        let clienteData = null;
        try { clienteData = JSON.parse(pago.external_reference || ''); } catch {}
        if (!clienteData || (!clienteData.n && !clienteData.e && !clienteData.items)) continue;

        const { data: yaExiste } = await supabaseAdmin().from('ventas_online').select('id').eq('payment_id', pid).maybeSingle();
        if (yaExiste) continue;

        const fecha     = pago.date_approved || pago.date_created || '';
        const itemsVenta = clienteData.items || [];

        // Descontar stock
        for (const item of itemsVenta) {
          if (!item.v || item.v === 'envio') continue;
          try {
            const titulo     = item.t || '';
            const talleMatch = titulo.match(/\(Talle\s+([^)]+)\)/i);
            const colorMatch = titulo.match(/—\s*([^(]+?)\s*\(/);
            const talleName  = talleMatch ? talleMatch[1].trim() : '';
            const colorName  = colorMatch ? colorMatch[1].trim() : '';
            let varianteId   = null;
            if (talleName && colorName) {
              const { data: colorVar } = await supabaseAdmin().from('producto_variantes')
                .select('id').eq('producto_id', item.v).eq('tipo', 'color').ilike('nombre', colorName).maybeSingle();
              if (colorVar) {
                const { data: talleVar } = await supabaseAdmin().from('producto_variantes')
                  .select('id').eq('color_id', colorVar.id).eq('tipo', 'talle').ilike('nombre', talleName).maybeSingle();
                if (talleVar) varianteId = talleVar.id;
              }
            } else if (talleName) {
              const { data: talleVar } = await supabaseAdmin().from('producto_variantes')
                .select('id').eq('producto_id', item.v).eq('tipo', 'talle').ilike('nombre', talleName).maybeSingle();
              if (talleVar) varianteId = talleVar.id;
            }
            if (varianteId) {
              const { data: varActual } = await supabaseAdmin().from('producto_variantes').select('cantidad').eq('id', varianteId).single();
              if (varActual)
                await supabaseAdmin().from('producto_variantes').update({ cantidad: Math.max(0, (varActual.cantidad || 0) - (item.q || 1)) }).eq('id', varianteId);
            }
          } catch (stockErr) { console.error('[Sync] Stock err:', stockErr.message); }
        }

        // Registrar venta online
        await supabaseAdmin().from('ventas_online').insert({
          user_id: userId, payment_id: pid,
          external_ref: pago.external_reference || '',
          items: itemsVenta, estado: 'procesado', fecha_venta: fecha,
        });

        // Crear/actualizar cliente y registrar venta
        try {
          const nombreCompleto = ((clienteData.n || '') + ' ' + (clienteData.a || '')).trim();
          const telefono       = clienteData.t || '';
          const email          = clienteData.e || '';
          const notas          = [
            email           ? 'Email: ' + email : '',
            clienteData.d   ? 'DNI: '   + clienteData.d : '',
            clienteData.dir ? 'Dir: '   + clienteData.dir + (clienteData.ciudad ? ', ' + clienteData.ciudad : '') + (clienteData.prov ? ' (' + clienteData.prov + ')' : '') : '',
          ].filter(Boolean).join(' | ');

          let { data: cliente } = email
            ? await supabaseAdmin().from('clientes').select('*').eq('user_id', userId).ilike('notas', `%Email: ${email}%`).maybeSingle()
            : { data: null };
          if (!cliente && nombreCompleto)
            ({ data: cliente } = await supabaseAdmin().from('clientes').select('*').eq('user_id', userId).eq('nombre', nombreCompleto).maybeSingle());
          if (!cliente) {
            const { data: nuevoCliente } = await supabaseAdmin().from('clientes').insert({
              user_id: userId, nombre: nombreCompleto || email, telefono, notas,
            }).select().single();
            cliente = nuevoCliente;
          } else if (email && !(cliente.notas || '').includes('Email:')) {
            await supabaseAdmin().from('clientes').update({
              notas: ((cliente.notas ? cliente.notas + ' | ' : '') + notas),
              telefono: telefono || cliente.telefono,
            }).eq('id', cliente.id);
          }

          const numeroVenta = await nextNumeroVenta(userId);
          let totalVenta = 0;
          for (const item of itemsVenta) {
            if ((item.t || '').toLowerCase().includes('envío')) continue;
            const pu   = parseFloat(item.p) || 0;
            const cant = parseInt(item.q) || 1;
            totalVenta += pu * cant;
            const { data: prod } = await supabaseAdmin().from('productos').select('costo').eq('user_id', userId).ilike('nombre', `%${(item.t || '').split(' ')[0]}%`).maybeSingle();
            await supabaseAdmin().from('ventas').insert({
              user_id: userId, cliente_id: cliente.id,
              prenda: String(item.t || 'Producto').slice(0, 120),
              precio_venta: pu * cant, costo: (prod?.costo || 0) * cant,
              pagado: pu * cant, adeuda: 0,
              cantidad: cant, precio_unitario: pu, costo_unitario: prod?.costo || 0,
              fecha_compra: fecha ? fecha.split('T')[0] : new Date().toISOString().split('T')[0],
              notas: `Venta online #${String(numeroVenta).padStart(4,'0')} — MP #${pid}`,
              numero_venta: numeroVenta,
            });
          }

          const ventaInfo = {
            numeroVenta, clienteNombre: nombreCompleto, clienteEmail: email,
            clienteTel: telefono,
            envio: clienteData.prov ? `Envío a ${clienteData.prov}` : 'Retiro en Showroom',
            items: itemsVenta.filter(i => !(i.t || '').toLowerCase().includes('envío')),
            total: totalVenta, paymentId: pid,
            fecha: fecha ? fecha.split('T')[0] : new Date().toISOString().split('T')[0],
          };
          try { await enviarEmailNotificacion(ventaInfo); } catch(e) { console.error('Email notif:', e.message); }
          try { await enviarEmailCliente(ventaInfo); } catch(e) { console.error('Email cliente:', e.message); }
        } catch (e) { console.error('[Sync] Cliente/venta err:', e.message); }

        detalleTotal.push({ paymentId: pid, userId, fecha });
        totalNuevas++;
      }

      await supabaseAdmin().from('mp_conexiones').update({ mp_last_sync: new Date().toISOString() }).eq('user_id', userId);
    }

    return json(res, 200, { ok: true, nuevas: totalNuevas, detalle: detalleTotal });
  }

  // ── Stock config ───────────────────────────────────────────────────────────
  if (p === '/api/stock/config' && method === 'GET') {
    const { data: conn } = await supabaseAdmin().from('mp_conexiones').select('sitio_path, mp_last_sync, conectado, mp_user_id').eq('user_id', user.userId).maybeSingle();
    return json(res, 200, {
      sitio_path:   conn?.sitio_path   || '',
      mp_last_sync: conn?.mp_last_sync || '',
      mp_conectado: conn?.conectado    || false,
      mp_user_id:   conn?.mp_user_id   || '',
    });
  }

  if (p === '/api/stock/config' && method === 'POST') {
    const b = await readBody(req);
    if (b.sitio_path !== undefined) {
      await supabaseAdmin().from('mp_conexiones').upsert(
        { user_id: user.userId, sitio_path: b.sitio_path },
        { onConflict: 'user_id' }
      );
    }
    return json(res, 200, { ok: true });
  }

  // ── MercadoPago OAuth ─────────────────────────────────────────────────────
  if (p === '/api/mp/oauth' && method === 'GET') {
    const clientId = process.env.MP_CLIENT_ID;
    if (!clientId) return json(res, 500, { error: 'MP_CLIENT_ID no configurado' });
    const state    = randomBytes(16).toString('hex');
    const redirect = process.env.MP_REDIRECT_URI || `http://localhost:${PORT}/api/mp/callback`;
    const authUrl  = `https://auth.mercadopago.com/authorization?client_id=${clientId}&response_type=code&platform_id=mp&state=${state}&redirect_uri=${encodeURIComponent(redirect)}`;
    res.writeHead(302, { Location: authUrl });
    res.end(); return;
  }

  if (p === '/api/mp/callback' && method === 'GET') {
    const code = urlObj.searchParams.get('code');
    if (!code) {
      res.writeHead(302, { Location: '/?mp_error=no_code' }); res.end(); return;
    }
    const clientId     = process.env.MP_CLIENT_ID;
    const clientSecret = process.env.MP_CLIENT_SECRET;
    const redirectUri  = process.env.MP_REDIRECT_URI || `http://localhost:${PORT}/api/mp/callback`;
    let tokenData;
    try {
      tokenData = await new Promise((resolve, reject) => {
        const body = JSON.stringify({ grant_type: 'authorization_code', client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri });
        const opts = {
          hostname: 'api.mercadopago.com', path: '/oauth/token', method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        };
        const r = https.request(opts, res2 => {
          let b = ''; res2.on('data', d => b += d);
          res2.on('end', () => { try { resolve(JSON.parse(b)); } catch { reject(new Error('MP response inválido')); } });
        });
        r.on('error', reject); r.write(body); r.end();
      });
    } catch(e) {
      console.error('[MP OAuth]', e.message);
      res.writeHead(302, { Location: '/?mp_error=token_failed' }); res.end(); return;
    }
    if (!tokenData.access_token) {
      console.error('[MP OAuth] Sin access_token:', JSON.stringify(tokenData));
      res.writeHead(302, { Location: '/?mp_error=no_access_token' }); res.end(); return;
    }
    // Identificar el user_id del callback — viene del state o de la sesión
    // Para simplificar: guardamos en mp_conexiones pendiente de asignar al usuario que inició el OAuth
    // En producción se usaría el state para recuperar el user_id de una sesión
    const mpUserId = String(tokenData.user_id || '');
    // Guardamos los tokens encriptados: necesitamos asociarlo al usuario que hizo el OAuth
    // Buscamos por mp_user_id si ya existe, sino lo dejamos sin user_id para que el frontend lo complete
    const encAccess  = encrypt(tokenData.access_token);
    const encRefresh = tokenData.refresh_token ? encrypt(tokenData.refresh_token) : '';
    if (mpUserId) {
      const { data: existing } = await supabaseAdmin().from('mp_conexiones').select('user_id').eq('mp_user_id', mpUserId).maybeSingle();
      if (existing) {
        await supabaseAdmin().from('mp_conexiones').update({
          access_token_encrypted: encAccess, refresh_token_encrypted: encRefresh,
          conectado: true, mp_user_id: mpUserId, updated_at: new Date().toISOString(),
        }).eq('mp_user_id', mpUserId);
      }
    }
    res.writeHead(302, { Location: '/?mp_ok=1' }); res.end(); return;
  }

  if (p === '/api/mp/connect' && method === 'POST') {
    // Asociar tokens MP al usuario actual (llamado luego de callback si el state no alcanzó)
    const b = await readBody(req);
    const { access_token, refresh_token, mp_user_id } = b;
    if (!access_token) return json(res, 400, { error: 'access_token requerido' });
    await supabaseAdmin().from('mp_conexiones').upsert({
      user_id: user.userId,
      access_token_encrypted: encrypt(access_token),
      refresh_token_encrypted: refresh_token ? encrypt(refresh_token) : '',
      mp_user_id: mp_user_id || '',
      conectado: true, updated_at: new Date().toISOString(),
    }, { onConflict: 'user_id' });
    return json(res, 200, { ok: true });
  }

  if (p === '/api/mp/disconnect' && method === 'POST') {
    await supabaseAdmin().from('mp_conexiones').upsert({
      user_id: user.userId, conectado: false,
      access_token_encrypted: '', refresh_token_encrypted: '',
      updated_at: new Date().toISOString(),
    }, { onConflict: 'user_id' });
    return json(res, 200, { ok: true });
  }

  if (p === '/api/mp/status' && method === 'GET') {
    const { data } = await supabaseAdmin().from('mp_conexiones').select('conectado, mp_user_id, mp_last_sync').eq('user_id', user.userId).maybeSingle();
    return json(res, 200, { conectado: data?.conectado || false, mp_user_id: data?.mp_user_id || '', mp_last_sync: data?.mp_last_sync || '' });
  }

  // ── Stock: publicar ────────────────────────────────────────────────────────
  if (p === '/api/stock/publicar' && method === 'POST') {
    const sitioPth = await getSitioPath(user.userId);
    if (!sitioPth) return json(res, 400, { error: 'sitio_path no configurado en Stock > Configuración' });

    const { data: prods } = await supabaseAdmin().from('productos').select('*, producto_variantes(*)').eq('user_id', user.userId).eq('activo', true);
    if (!prods?.length) return json(res, 400, { error: 'No hay productos activos' });

    const productosJS = prods.map(p => {
      const vars      = (p.producto_variantes || []);
      const colorVars = vars.filter(v => v.tipo === 'color');
      const talleVars = vars.filter(v => v.tipo === 'talle');
      let imagenes = Array.isArray(p.imagenes) ? p.imagenes : [];
      let imagen   = imagenes[0] || p.imagen_url || '';
      let variantesJS = [], talles = [], colores = [];

      if (colorVars.length > 0) {
        const tallesSinColor = talleVars.filter(tv => !tv.color_id);
        variantesJS = colorVars.map(cv => {
          const tallesDeColor = talleVars.filter(tv => tv.color_id === cv.id);
          const tallesFinal   = tallesDeColor.length > 0 ? tallesDeColor : tallesSinColor;
          return { id: cv.id, nombre: cv.nombre, imagen: cv.imagen || p.imagen_url,
            talles: tallesFinal.map(tv => ({ id: tv.id, nombre: tv.nombre, cantidad: tv.cantidad || 0 })) };
        });
        colores = colorVars.map(v => v.nombre);
        talles  = [...new Set(talleVars.map(v => v.nombre))];
        if (!imagenes.length) { imagen = variantesJS[0]?.imagen || ''; imagenes = [...new Set(variantesJS.map(v => v.imagen).filter(Boolean))]; }
      } else {
        talles = talleVars.map(v => ({ nombre: v.nombre, cantidad: v.cantidad || 0 }));
      }

      return {
        id: p.id, nombre: p.nombre, precio: p.precio, costo: p.costo,
        categoria: p.categoria, descripcion: p.descripcion, guia_de_talles: p.guia_de_talles || '',
        imagen, imagenes, peso: p.peso, dimensiones: p.dimensiones,
        nuevo: !!p.nuevo, talles, colores, variantes: variantesJS,
      };
    });

    const cats = [...new Set(productosJS.map(p => p.categoria).filter(Boolean))];
    const dataJsContent = `// Generado automáticamente por GestionVentas — ${new Date().toISOString()}\nconst PRODUCTOS = ${JSON.stringify(productosJS, null, 2)};\n\nconst CATEGORIAS = ${JSON.stringify(cats)};\n\nif (typeof module !== 'undefined') module.exports = { PRODUCTOS, CATEGORIAS };\n`;

    // Actualizar CATALOG_PRICES en create-preference.js (nuevo path Vercel)
    const dataJsPath    = path.join(sitioPth, 'sitio', 'js', 'data.js');
    const createPrefPath = path.join(sitioPth, 'sitio', 'api', 'create-preference.js');
    let deployed = false, message = '';

    try {
      fs.writeFileSync(dataJsPath, dataJsContent, 'utf8');
      message += `data.js generado con ${productosJS.length} productos. `;
    } catch (e) {
      return json(res, 500, { ok: false, deployed: false, message: `Error escribiendo data.js: ${e.message}` });
    }

    try {
      let prefContent = fs.readFileSync(createPrefPath, 'utf8');
      const catalogPrices = {};
      for (const p of prods) catalogPrices[p.id] = p.precio;
      catalogPrices['envio'] = null;
      const newCatalog = `const CATALOG_PRICES = ${JSON.stringify(catalogPrices, null, 2)};`;
      prefContent = prefContent.replace(/const CATALOG_PRICES\s*=\s*\{[\s\S]*?\};/, newCatalog);
      fs.writeFileSync(createPrefPath, prefContent, 'utf8');
      message += 'CATALOG_PRICES actualizado. ';
    } catch (e) { message += `Advertencia: no se pudo actualizar create-preference.js: ${e.message}. `; }

    try {
      const { execSync } = require('child_process');
      execSync('vercel deploy --prod', { cwd: path.join(sitioPth, 'sitio'), timeout: 120000, stdio: 'pipe' });
      deployed = true;
      message += 'Deploy exitoso a Vercel.';
    } catch (e) {
      message += `Deploy falló (podés hacerlo manual): ${e.message.slice(0, 200)}`;
    }

    return json(res, 200, { ok: true, deployed, message });
  }

  // ── Cotización envío ────────────────────────────────────────────────────────
  if (p === '/api/shipping/quote' && method === 'POST') {
    try {
      const body       = await readBody(req);
      const { cpDestino, peso, alto, largo, ancho } = body;
      const cp         = String(cpDestino || '').trim().replace(/\D/g, '');
      if (cp.length < 4) return json(res, 400, { error: 'Código postal inválido' });
      const correoUser = process.env.CORREO_ARG_USER;
      const correoPass = process.env.CORREO_ARG_PASS;
      if (!correoUser || !correoPass) return json(res, 200, { correo: null, error: 'CORREO_ARG_USER y CORREO_ARG_PASS no configurados' });

      const base  = process.env.CORREO_ARG_ENV === 'prod' ? 'https://api.correoargentino.com.ar/micorreo/v1' : 'https://apitest.correoargentino.com.ar/micorreo/v1';
      const CP_OR = '1712';
      function correoReq(urlStr, m, hdrs, bodyObj) {
        return new Promise((resolve, reject) => {
          const u = new URL(urlStr); const raw = JSON.stringify(bodyObj);
          const r = https.request({ hostname: u.hostname, path: u.pathname, method: m, headers: { ...hdrs, 'Content-Length': Buffer.byteLength(raw) } }, res2 => {
            let data = ''; res2.on('data', d => data += d);
            res2.on('end', () => { try { resolve({ status: res2.statusCode, body: JSON.parse(data) }); } catch { resolve({ status: res2.statusCode, body: data }); } });
          });
          r.on('error', reject); r.write(raw); r.end();
        });
      }
      const creds   = Buffer.from(`${correoUser}:${correoPass}`).toString('base64');
      const authRes = await correoReq(`${base}/token`, 'POST', { Authorization: `Basic ${creds}`, 'Content-Type': 'application/json' }, {});
      const tokenVal = authRes.body?.token ?? authRes.body?.access_token ?? authRes.body?.accessToken ?? authRes.body?.jwt;
      if (!tokenVal) return json(res, 200, { correo: null, error: 'Auth Correo Argentino falló' });
      const ratesRes = await correoReq(`${base}/shipments/rates`, 'POST', { Authorization: `Bearer ${tokenVal}`, 'Content-Type': 'application/json' }, {
        codigoPostalOrigen: CP_OR, codigoPostalDestino: cp,
        peso: Math.max(parseInt(peso) || 500, 1), alto: Math.max(parseInt(alto) || 5, 1),
        largo: Math.max(parseInt(largo) || 35, 1), ancho: Math.max(parseInt(ancho) || 25, 1),
        tipoProducto: 'CP',
      });
      const parsePrecio = d => {
        if (!d) return null;
        if (Array.isArray(d) && d.length > 0) return parsePrecio(d[0]);
        const v = d.precio ?? d.price ?? d.tarifa ?? d.monto ?? d.total ?? d.costo ?? null;
        return v !== null ? Math.round(Number(v)) : null;
      };
      return json(res, 200, { correo: parsePrecio(ratesRes.body) });
    } catch (e) {
      console.error('[Correo]', e.message);
      return json(res, 200, { correo: null, error: e.message });
    }
  }

  // ── Archivos estáticos ──────────────────────────────────────────────────────
  const filePath = p === '/' ? path.join(__dirname, 'index.html') : path.join(__dirname, p);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext  = path.extname(filePath);
    const mime = { '.html':'text/html','.js':'application/javascript','.css':'text/css','.ico':'image/x-icon' };
    res.writeHead(200, { 'Content-Type': mime[ext] || 'text/plain' });
    fs.createReadStream(filePath).pipe(res);
    return;
  }

  return json(res, 404, { error: 'No encontrado' });
}

// ─── INICIO ───────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT) || 3000;

function findFreePort(start) {
  return new Promise(resolve => {
    const s = http.createServer();
    s.listen(start, '0.0.0.0', () => { s.close(() => resolve(start)); });
    s.on('error', () => resolve(findFreePort(start + 1)));
  });
}

const server = http.createServer(async (req, res) => {
  try { await handleRequest(req, res); }
  catch (err) { console.error('[Error]', err.message); json(res, 500, { error: err.message }); }
});

findFreePort(PORT).then(port => {
  server.listen(port, '0.0.0.0', () => {
    const ip = getLocalIP();
    if (port !== PORT) console.log(`\n⚠️  Puerto ${PORT} ocupado — usando ${port}\n`);
    console.log('\n╔══════════════════════════════════════════════╗');
    console.log('║        GESTIÓN DE VENTAS — Servidor OK       ║');
    console.log('╠══════════════════════════════════════════════╣');
    console.log(`║  Esta PC:   http://localhost:${port}             ║`);
    console.log(`║  Celular:   http://${ip}:${port}          ║`);
    console.log('╠══════════════════════════════════════════════╣');
    console.log('║  Ctrl+C para cerrar                          ║');
    console.log('╚══════════════════════════════════════════════╝\n');

    // Verificar cuotas al iniciar y cada 6 horas
    checkCuotasVencimiento().catch(e => console.error('[Cuotas]', e.message));
    setInterval(() => checkCuotasVencimiento().catch(e => console.error('[Cuotas]', e.message)), 6 * 60 * 60 * 1000);

    // Auto-sync MP cada 5 minutos
    const syncToken = process.env.GESTION_SYNC_TOKEN;
    async function autoSyncMP() {
      if (!syncToken) return;
      try {
        await new Promise((resolve, reject) => {
          const r = http.request(
            { hostname: 'localhost', port, path: '/api/sync-mp', method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Content-Length': '2', 'Authorization': `Bearer ${syncToken}` } },
            res => {
              let b = '';
              res.on('data', d => b += d);
              res.on('end', () => {
                try { const d = JSON.parse(b); if (d.nuevas > 0) console.log(`[AutoSync] ${d.nuevas} venta(s) nueva(s)`); else console.log('[AutoSync] Sin ventas nuevas'); } catch {}
                resolve();
              });
            }
          );
          r.on('error', reject); r.write('{}'); r.end();
        });
      } catch(e) { console.error('[AutoSync]', e.message); }
    }

    setTimeout(autoSyncMP, 10000);
    setInterval(autoSyncMP, 5 * 60 * 1000);
  });
});
