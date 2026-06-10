'use strict';
/**
 * api/[...route].js — Vercel catch-all serverless handler
 * Reemplaza server.js. Sin http.createServer, sin setInterval, sin escrituras a disco.
 */

const { createClient } = require('@supabase/supabase-js');
const nodemailer       = require('nodemailer');
const crypto           = require('crypto');
const dns              = require('dns').promises;
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
  return {
    id: r.id, nombre: r.nombre, telefono: r.telefono, notas: r.notas, createdAt: r.created_at,
    tags: Array.isArray(r.tags) ? r.tags : [],
    saldo: r.saldo != null ? parseFloat(r.saldo) : null,
    totalComprado: r.total_comprado != null ? parseFloat(r.total_comprado) : null,
    totalPagado: r.total_pagado != null ? parseFloat(r.total_pagado) : null,
    cantCompras: r.cant_compras != null ? parseInt(r.cant_compras) : null,
    ultimaCompra: r.ultima_compra || null,
    ultimoPago: r.ultimo_pago || null,
  };
}

function toVenta(r) {
  return {
    id: r.id, clienteId: r.cliente_id, prenda: r.prenda,
    precioVenta: r.precio_venta, costo: r.costo, pagado: r.pagado, adeuda: r.adeuda,
    cantidad: r.cantidad, precioUnitario: r.precio_unitario, costoUnitario: r.costo_unitario,
    fechaCompra: r.fecha_compra, proxCuota: r.prox_cuota, notas: r.notas,
    numeroVenta: r.numero_venta, notificadoAt: r.notificado_at,
    descuento: parseFloat(r.descuento) || 0,
    tipoDescuento: r.tipo_descuento || 'fijo',
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
    nombre: r.nombre, cantidad: r.cantidad, imagen: r.imagen, colorId: r.color_id,
    stockMinimo: r.stock_minimo || 0
  };
}

function toPago(r) {
  return {
    id: r.id, userId: r.user_id, clienteId: r.cliente_id,
    monto: r.monto, fecha: r.fecha, medioPago: r.medio_pago,
    nota: r.nota, createdAt: r.created_at
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
    .from('perfiles').select('rol, activo, nombre, tipo_cuenta, tienda_configurada, alertas_email, email_alternativo, telegram_config, meta_mensual, telefono_usuario, tienda_public_id, avatar_url').eq('id', user.id).single();

  if (!perfil || !perfil.activo) return null;
  return {
    userId: user.id, email: user.email, role: perfil.rol,
    nombre: perfil.nombre, tipoCuenta: perfil.tipo_cuenta || 'gestion',
    tiendaConfigurada: perfil.tienda_configurada || false,
    alertasEmail: perfil.alertas_email !== false,
    emailAlternativo: perfil.email_alternativo || '',
    telegramConfig: perfil.telegram_config || null,
    metaMensual: perfil.meta_mensual || null,
    telefonoUsuario: perfil.telefono_usuario || '',
    tiendaPublicId: perfil.tienda_public_id || null,
    avatarUrl: perfil.avatar_url || null,
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
      from: '"En Orden" <tomipieri@hotmail.com>',
      to: 'sanlatorre@hotmail.com, chanaindumentaria@hotmail.com',
      subject,
      html
    });
  } catch (e) {
    console.error('Email error:', e.message);
  }
}

// ── Email de bienvenida ────────────────────────────────────────────────────────
async function sendWelcomeEmail(toEmail, nombre) {
  const appUrl = APP_URL;
  const html = `<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Inter,Arial,sans-serif;background:#f5f5f5;margin:0;padding:0}
.wrap{max-width:520px;margin:40px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.07)}
.hdr{background:#111;padding:28px 32px;text-align:center}
.hdr h1{color:#fff;font-size:22px;margin:0;letter-spacing:-.3px}
.body{padding:32px}
.body p{color:#333;font-size:15px;line-height:1.6;margin:0 0 16px}
.btn{display:inline-block;background:#111;color:#fff;text-decoration:none;padding:14px 28px;border-radius:8px;font-size:15px;font-weight:600;margin:8px 0 24px}
.footer{background:#f9f9f9;padding:16px 32px;text-align:center;color:#999;font-size:12px}
</style></head><body>
<div class="wrap">
  <div class="hdr"><h1>En Orden</h1></div>
  <div class="body">
    <p>Hola <strong>${nombre}</strong>,</p>
    <p>Tu cuenta en <strong>En Orden</strong> fue creada exitosamente.</p>
    <p>Ya podés empezar a gestionar tus ventas, clientes y cobros desde cualquier dispositivo.</p>
    <a href="${appUrl}" class="btn">Ir a En Orden</a>
    <p style="font-size:13px;color:#999">Si no creaste esta cuenta, podés ignorar este email.</p>
  </div>
  <div class="footer">El equipo de En Orden</div>
</div>
</body></html>`;

  try {
    await mailer.sendMail({
      from: '"En Orden" <tomipieri@hotmail.com>',
      to: toEmail,
      subject: '¡Bienvenida a En Orden! 🎉',
      html
    });
  } catch (e) {
    console.error('Welcome email error:', e.message);
  }
}

// ── Validación de dominio de email (DNS MX) ────────────────────────────────────
const BLOCKED_EMAIL_DOMAINS = new Set([
  'mailinator.com','guerrillamail.com','throwaway.email','tempmail.com','yopmail.com',
  'sharklasers.com','trashmail.com','dispostable.com','mailnull.com','spam4.me',
  'test.com','example.com','example.org','example.net','fake.com','noemail.com',
]);

async function emailDomainExists(email) {
  const at = email.lastIndexOf('@');
  if (at < 0) return false;
  const domain = email.slice(at + 1).toLowerCase();
  if (!domain.includes('.')) return false;
  if (BLOCKED_EMAIL_DOMAINS.has(domain)) return false;
  try {
    const records = await dns.resolveMx(domain);
    return Array.isArray(records) && records.length > 0;
  } catch (e) {
    // ENOTFOUND o ENODATA = dominio no existe
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA' || e.code === 'ESERVFAIL') return false;
    // Error transitorio de red — fail-open para no bloquear usuarios legítimos
    return true;
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
  // Parsear path desde req.url (más confiable que req.query.route cuando hay rewrite)
  const rawUrl  = req.url || '';
  const pathOnly = rawUrl.split('?')[0];                    // sin query string
  const p        = pathOnly.replace(/^\/api\//, '').replace(/\/$/, '');  // "auth/login", "clientes/123"
  const segments = p.split('/');
  const method = req.method;

  // Rutas de tienda con CORS propio — no interceptar aquí el OPTIONS
  const isTiendaPost = segments[0] === 'tienda' && segments[1] && (
    segments[2] === 'checkout' || segments[2] === 'validar-codigo' || segments[2] === 'analytics'
  );
  if (!isTiendaPost) {
    setCors(req, res);
    if (method === 'OPTIONS') return res.status(204).end();
  }

  // Rutas públicas
  if (method === 'POST' && p === 'auth/login')    return handleLogin(req, res);
  if (method === 'POST' && p === 'auth/refresh')  return handleRefreshToken(req, res);
  if (method === 'POST' && p === 'auth/registro') return handleRegistro(req, res);
  if (method === 'GET'  && p === 'mp/callback')   return handleMpCallback(req, res);
  if (method === 'POST' && p === 'shipping-quote') return handleShippingQuote(req, res);
  if (method === 'POST' && p === 'run-migration-v3') return handleMigrationV3(req, res);
  if (method === 'POST' && p === 'run-migration-v4') return handleMigrationV4(req, res);
  if (method === 'POST' && p === 'run-migration-v5') return handleMigrationV5(req, res);
  if (method === 'POST' && p === 'run-migration-v6') return handleMigrationV6(req, res);

  // Anuncios — ruta pública
  if (method === 'GET' && p === 'anuncios/activo') return handleGetAnuncioActivo(req, res);

  // API pública tienda — no requiere auth (order matters: específico antes de genérico)
  if (segments[0] === 'tienda' && segments[1] && segments[2] === 'config' && !segments[3])
    return handleTiendaGetConfig(req, res, segments[1]);
  if (segments[0] === 'tienda' && segments[1] && segments[2] === 'productos' && !segments[3])
    return handleTiendaPublica(req, res, segments[1]);
  if (segments[0] === 'tienda' && segments[1] && segments[2] === 'promociones' && segments[3] === 'activas')
    return handleTiendaPromosActivas(req, res, segments[1]);
  if ((method === 'POST' || method === 'OPTIONS') && segments[0] === 'tienda' && segments[1] && segments[2] === 'validar-codigo' && !segments[3])
    return handleTiendaValidarCodigo(req, res, segments[1]);
  if ((method === 'POST' || method === 'OPTIONS') && segments[0] === 'tienda' && segments[1] && segments[2] === 'checkout' && !segments[3])
    return handleTiendaCheckout(req, res, segments[1]);
  if ((method === 'POST' || method === 'OPTIONS') && segments[0] === 'tienda' && segments[1] && segments[2] === 'analytics' && !segments[3])
    return handleTiendaAnalytics(req, res, segments[1]);
  if (segments[0] === 'tienda' && segments[1] && segments[2] === 'webhook-mp' && !segments[3])
    return handleTiendaWebhookMP(req, res, segments[1]);

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
    if (method === 'GET'  && p === 'admin/sistema-status')                       return handleAdminSistemaStatus(req, res);
    if (method === 'GET'  && p === 'admin/anuncios')                             return handleAdminGetAnuncios(req, res);
    if (method === 'POST' && p === 'admin/anuncios')                             return handleAdminPostAnuncio(req, res);
    if (method === 'PUT'  && segments[1]==='anuncios' && segments[2] && !segments[3]) return handleAdminPutAnuncio(req, res, segments[2]);
    if (method === 'DELETE' && segments[1]==='anuncios' && segments[2])          return handleAdminDeleteAnuncio(req, res, segments[2]);
    return json(res, 404, { error: 'Ruta admin no encontrada' });
  }

  // Auth
  if (method === 'GET'  && p === 'auth/me') return json(res, 200, {
    user: {
      id: user.userId, email: user.email, rol: user.role,
      nombre: user.nombre, tipoCuenta: user.tipoCuenta, tiendaConfigurada: user.tiendaConfigurada,
      metaMensual: user.metaMensual, telefonoUsuario: user.telefonoUsuario,
      tiendaPublicId: user.tiendaPublicId, avatarUrl: user.avatarUrl || null,
    }
  });
  if (method === 'POST' && p === 'auth/logout')  return json(res, 200, { ok: true });

  // Clientes
  if (method === 'GET'  && p === 'clientes')           return handleGetClientes(req, res, user);
  if (method === 'POST' && p === 'clientes')           return handlePostCliente(req, res, user);
  if (method === 'POST' && p === 'clientes/importar')  return handleImportarClientes(req, res, user);
  if (method === 'PUT'  && segments[0] === 'clientes' && !segments[2]) return handlePutCliente(req, res, user, segments[1]);
  if (method === 'DELETE' && segments[0] === 'clientes' && !segments[2]) return handleDeleteCliente(req, res, user, segments[1]);
  if (method === 'GET'  && segments[0] === 'clientes' && segments[2] === 'cuenta-corriente')
    return handleGetCuentaCorriente(req, res, user, segments[1]);

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

  // Pagos (cuenta corriente)
  if (method === 'POST'   && p === 'pagos')             return handlePostPago(req, res, user);
  if (method === 'DELETE' && segments[0] === 'pagos')   return handleDeletePago(req, res, user, segments[1]);

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

  // Notificaciones
  if (method === 'GET'   && p === 'notificaciones')                                            return handleGetNotificaciones(req, res, user);
  if (method === 'PATCH' && segments[0] === 'notificaciones' && segments[2] === 'leer')        return handlePatchNotificacionLeer(req, res, user, segments[1]);
  if (method === 'POST'  && p === 'notificaciones/leer-todas')                                 return handlePostNotificacionesLeerTodas(req, res, user);

  // Perfil
  if (method === 'GET'  && p === 'perfil')                    return handleGetPerfil(req, res, user);
  if (method === 'PUT'  && p === 'perfil')                    return handlePutPerfil(req, res, user);
  if (method === 'PUT'  && p === 'perfil/tienda')             return handlePutPerfilTienda(req, res, user);
  if (method === 'POST' && p === 'perfil/password')           return handleCambiarPassword(req, res, user);
  if (method === 'POST' && p === 'perfil/eliminar-cuenta')    return handleEliminarCuenta(req, res, user);
  if (method === 'POST' && p === 'perfil/avatar')             return handleAvatarUpload(req, res, user);
  if (method === 'DELETE' && p === 'perfil/avatar')           return handleAvatarDelete(req, res, user);
  if (method === 'POST' && p === 'config-img')                return handleConfigImgUpload(req, res, user);

  // Config (tienda + MP + notificaciones)
  if (method === 'GET'  && p === 'config')                   return handleGetConfig(req, res, user);
  if (method === 'PUT'  && p === 'config')                   return handlePutConfig(req, res, user);
  if (method === 'POST' && p === 'config/telegram')          return handleTelegramConfig(req, res, user);
  if (method === 'POST' && p === 'config/telegram-test')     return handleTelegramTest(req, res, user);

  // Stock
  if (method === 'POST' && p === 'stock/publicar')     return handlePublicarStock(req, res, user);

  // Tienda — regenerar ID público
  if (method === 'POST' && p === 'tienda/regen-id')    return handleRegenTiendaId(req, res, user);

  // Mi tienda config (gestion_tienda)
  if (method === 'GET'  && p === 'tienda-config')       return handleGetMiTiendaConfig(req, res, user);
  if (method === 'PUT'  && p === 'tienda-config')       return handlePutMiTiendaConfig(req, res, user);
  // Analytics resumen (propietario)
  if (method === 'GET'  && segments[0] === 'tienda' && segments[1] && segments[2] === 'analytics-resumen' && !segments[3])
    return handleTiendaAnalyticsResumen(req, res, user, segments[1]);
  // Promociones CRUD
  if (method === 'GET'    && p === 'promociones')        return handleGetPromociones(req, res, user);
  if (method === 'POST'   && p === 'promociones')        return handlePostPromocion(req, res, user);
  if ((method === 'PUT' || method === 'PATCH') && segments[0] === 'promociones' && segments[1] && !segments[2])
    return handlePutPromocion(req, res, user, segments[1]);
  if (method === 'DELETE' && segments[0] === 'promociones' && segments[1] && !segments[2])
    return handleDeletePromocion(req, res, user, segments[1]);
  // Producto PATCH (destacado / orden)
  if (method === 'PATCH'  && segments[0] === 'productos' && segments[1] && !segments[2])
    return handlePatchProducto(req, res, user, segments[1]);

  // MP OAuth
  if (method === 'GET'  && p === 'mp/connect')         return handleMpConnect(req, res, user);
  if (method === 'POST' && p === 'mp/get-oauth-url')   return handleMpGetOauthUrl(req, res, user);
  if (method === 'POST' && p === 'mp/disconnect')      return handleMpDisconnect(req, res, user);
  if (method === 'POST' && p === 'mp/sync')            return handleMpSync(req, res, user);

  // Upload imágenes (Supabase Storage — signed URL)
  if (method === 'POST' && p === 'storage/sign-upload') return handleSignStorageUpload(req, res, user);
  if (method === 'POST' && p === 'storage/delete')      return handleDeleteStorageFile(req, res, user);

  // Exportar datos
  if (method === 'GET'  && p === 'exportar')           return handleExportarDatos(req, res, user);

  // Devoluciones
  if (method === 'GET'  && p === 'devoluciones')       return handleGetDevoluciones(req, res, user);
  if (method === 'POST' && p === 'devoluciones')       return handlePostDevolucion(req, res, user);

  // Cron jobs (llegan aquí cuando el rewrite los redirige al catch-all)
  if (p === 'cron/check-cuotas')      return handleCronCheckCuotas(req, res);
  if (p === 'cron/sync-mp')           return handleCronSyncMp(req, res);
  if (p === 'cron/reporte-mensual')   return handleCronReporteMensual(req, res);

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
    refreshToken: data.session.refresh_token,
    user: {
      id: data.user.id, email: data.user.email,
      rol: perfil.rol, nombre: perfil.nombre,
      tipoCuenta: perfil.tipo_cuenta || 'gestion',
      tiendaConfigurada: perfil.tienda_configurada || false
    }
  });
}

async function handleRefreshToken(req, res) {
  const body = await parseBody(req);
  const { refreshToken } = body;
  if (!refreshToken) return json(res, 400, { error: 'Falta refreshToken' });
  const { data, error } = await anonSupabase.auth.refreshSession({ refresh_token: refreshToken });
  if (error || !data?.session) return json(res, 401, { error: 'Sesión inválida o expirada' });
  return json(res, 200, {
    token: data.session.access_token,
    refreshToken: data.session.refresh_token
  });
}

// ── CLIENTES ──────────────────────────────────────────────────────────────────
async function handleGetClientes(req, res, user) {
  // Traer clientes junto con saldo de saldos_clientes en una sola query
  let qClientes = adminSupabase.from('clientes').select('*').order('nombre');
  if (user.role !== 'admin') qClientes = qClientes.eq('user_id', user.userId);
  const { data: clientesData, error } = await qClientes;
  if (error) return json(res, 500, { error: error.message });

  // Enriquecer con saldos
  const { data: saldos } = await adminSupabase
    .from('saldos_clientes')
    .select('cliente_id, saldo, total_comprado, total_pagado, cant_compras, ultima_compra, ultimo_pago')
    .eq('user_id', user.userId);

  const saldoMap = {};
  (saldos || []).forEach(s => { saldoMap[s.cliente_id] = s; });

  return json(res, 200, clientesData.map(c => {
    const s = saldoMap[c.id] || {};
    return toCliente({ ...c, ...s });
  }));
}

async function handlePostCliente(req, res, user) {
  const body = await parseBody(req);
  const nombre = (body.nombre || '').trim();
  if (!nombre) return json(res, 400, { error: 'El nombre del cliente es requerido' });
  const row = {
    user_id:  user.role === 'admin' ? (body.userId || user.userId) : user.userId,
    nombre,
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
  if (Array.isArray(body.tags))    updates.tags     = body.tags;

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

  const cantidad = parseInt(body.cantidad) || 1;
  let precioVenta = parseFloat(body.precioVenta) || 0;
  if (!precioVenta && body.precioUnitario) {
    precioVenta = parseFloat(body.precioUnitario) * cantidad;
  }
  if (!precioVenta || precioVenta <= 0) return json(res, 400, { error: 'El precio de la venta es requerido' });

  const descuento     = parseFloat(body.descuento) || 0;
  const tipoDescuento = ['fijo','porcentaje'].includes(body.tipoDescuento) ? body.tipoDescuento : 'fijo';
  if (tipoDescuento === 'fijo'       && descuento > precioVenta) return json(res, 400, { error: 'El descuento no puede superar el precio de la venta' });
  if (tipoDescuento === 'porcentaje' && descuento > 100)         return json(res, 400, { error: 'El porcentaje de descuento no puede superar 100%' });

  const precioFinal = tipoDescuento === 'porcentaje'
    ? precioVenta * (1 - descuento / 100)
    : Math.max(0, precioVenta - descuento);

  const pagado = parseFloat(body.pagado) || 0;
  if (pagado < 0)              return json(res, 400, { error: 'El pago no puede ser negativo' });
  if (pagado > precioFinal)    return json(res, 400, { error: 'El pago no puede ser mayor al total de la venta' });

  const costo  = parseFloat(body.costo)  || 0;
  const fecha  = body.fechaCompra || new Date().toISOString().split('T')[0];

  const row = {
    user_id:         userId,
    cliente_id:      body.clienteId || null,
    prenda:          body.prenda || '',
    precio_venta:    precioVenta,
    costo:           costo,
    pagado:          pagado,
    adeuda:          precioFinal - pagado,
    cantidad:        cantidad,
    precio_unitario: body.precioUnitario != null ? parseFloat(body.precioUnitario) : precioVenta / cantidad,
    costo_unitario:  body.costoUnitario  != null ? parseFloat(body.costoUnitario)  : costo / cantidad,
    fecha_compra:    fecha,
    prox_cuota:      body.proxCuota     || null,
    notas:           body.notas         || '',
    numero_venta:    numero,
    descuento,
    tipo_descuento:  tipoDescuento
  };
  const { data, error } = await adminSupabase.from('ventas').insert(row).select('*, clientes(*)').single();
  if (error) return json(res, 500, { error: error.message });

  // Si hubo pago inicial, registrarlo en pagos para que afecte el saldo del cliente
  if (pagado > 0 && body.clienteId) {
    const medios    = ['efectivo','transferencia','tarjeta','otro'];
    const medioPago = medios.includes(body.medioPago) ? body.medioPago : 'efectivo';
    await adminSupabase.from('pagos').insert({
      user_id:    userId,
      cliente_id: body.clienteId,
      monto:      pagado,
      fecha,
      medio_pago: medioPago,
      nota:       `Pago al momento de compra (${body.prenda || 'venta #' + numero})`
    });
  }

  return json(res, 201, toVenta(data));
}

async function handlePutVenta(req, res, user, id) {
  const body = await parseBody(req);

  // Fetch current venta to detect pagado change
  let qCurrent = adminSupabase.from('ventas').select('pagado, precio_venta, cliente_id, prenda').eq('id', id);
  if (user.role !== 'admin') qCurrent = qCurrent.eq('user_id', user.userId);
  const { data: currentVenta } = await qCurrent.single();
  if (!currentVenta) return json(res, 404, { error: 'Venta no encontrada' });

  const updates = {};
  if (body.prenda      !== undefined) updates.prenda       = body.prenda;
  if (body.fechaCompra !== undefined) updates.fecha_compra = body.fechaCompra;
  if (body.proxCuota   !== undefined) updates.prox_cuota   = body.proxCuota;
  if (body.notas       !== undefined) updates.notas        = body.notas;
  if (body.clienteId   !== undefined) updates.cliente_id   = body.clienteId;
  if (body.descuento      !== undefined) updates.descuento      = parseFloat(body.descuento) || 0;
  if (body.tipoDescuento  !== undefined) updates.tipo_descuento = ['fijo','porcentaje'].includes(body.tipoDescuento) ? body.tipoDescuento : 'fijo';

  if (body.precioVenta !== undefined) {
    updates.precio_venta = parseFloat(body.precioVenta);
    if (body.pagado !== undefined) {
      updates.pagado = parseFloat(body.pagado);
      updates.adeuda = updates.precio_venta - updates.pagado;
    }
  }
  if (body.costo !== undefined)        updates.costo           = parseFloat(body.costo);
  if (body.cantidad !== undefined)     updates.cantidad        = parseInt(body.cantidad);
  if (body.precioUnitario !== undefined) updates.precio_unitario = parseFloat(body.precioUnitario);
  if (body.costoUnitario  !== undefined) updates.costo_unitario  = parseFloat(body.costoUnitario);
  if (body.precioUnitario !== undefined && body.precioVenta === undefined) {
    const pu  = parseFloat(body.precioUnitario);
    const qty = updates.cantidad || parseInt(body.cantidad) || 1;
    updates.precio_venta = pu * qty;
    if (body.pagado !== undefined) {
      updates.pagado = parseFloat(body.pagado);
      updates.adeuda = updates.precio_venta - updates.pagado;
    }
  }
  updates.updated_at = new Date().toISOString();

  let q = adminSupabase.from('ventas').update(updates).eq('id', id);
  if (user.role !== 'admin') q = q.eq('user_id', user.userId);
  const { data, error } = await q.select('*, clientes(*)').single();
  if (error) return json(res, 500, { error: error.message });

  // Si el pagado aumentó, registrar la diferencia como nuevo pago
  if (body.pagado !== undefined) {
    const clienteId = updates.cliente_id || currentVenta.cliente_id;
    const pagadoNuevo    = parseFloat(body.pagado) || 0;
    const pagadoAnterior = parseFloat(currentVenta.pagado) || 0;
    const diferencia     = pagadoNuevo - pagadoAnterior;
    if (diferencia > 0 && clienteId) {
      const medios    = ['efectivo','transferencia','tarjeta','otro'];
      const medioPago = medios.includes(body.medioPago) ? body.medioPago : 'efectivo';
      const fecha     = body.fechaCompra || updates.fecha_compra || new Date().toISOString().split('T')[0];
      await adminSupabase.from('pagos').insert({
        user_id:    user.userId,
        cliente_id: clienteId,
        monto:      diferencia,
        fecha,
        medio_pago: medioPago,
        nota:       `Pago adicional en edición de venta (${body.prenda || currentVenta.prenda || 'venta editada'})`
      });
    }
  }

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
  let monto = parseFloat(body.monto) || 0;
  if (!monto && body.precioUnitario) {
    monto = parseFloat(body.precioUnitario) * cantidad;
  }
  if (!monto || monto <= 0) return json(res, 400, { error: 'El monto del gasto es requerido' });
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
  if (body.monto !== undefined) {
    updates.monto = parseFloat(body.monto);
  } else if (body.precioUnitario !== undefined) {
    updates.monto = parseFloat(body.precioUnitario) * (parseInt(body.cantidad) || 1);
  }
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
  const nombre = (body.nombre || '').trim();
  if (!nombre) return json(res, 400, { error: 'El nombre del producto es requerido' });
  const precio = parseFloat(body.precio) || 0;
  if (precio <= 0) return json(res, 400, { error: 'El precio del producto debe ser mayor a $0' });
  const row = {
    user_id:        user.role === 'admin' ? (body.userId || user.userId) : user.userId,
    nombre,
    categoria:      body.categoria || '',
    precio,
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
  // Verificar que el producto existe y pertenece al usuario
  const { data: prod, error: prodErr } = await adminSupabase
    .from('productos').select('id').eq('id', productoId).eq('user_id', user.userId).single();
  if (prodErr || !prod) return json(res, 404, { error: 'Producto no encontrado' });

  const body = await parseBody(req);
  const row = {
    producto_id: productoId,
    user_id:     user.userId,
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
  if (body.nombre      !== undefined) updates.nombre      = body.nombre;
  if (body.cantidad    !== undefined) updates.cantidad    = parseInt(body.cantidad);
  if (body.imagen      !== undefined) updates.imagen      = body.imagen;
  if (body.colorId     !== undefined) updates.color_id    = body.colorId;
  if (body.stockMinimo !== undefined) updates.stock_minimo = parseInt(body.stockMinimo) || 0;

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

// ── NOTIFICACIONES ───────────────────────────────────────────────────────────
async function handleGetNotificaciones(req, res, user) {
  const { data, error } = await adminSupabase
    .from('notificaciones').select('*')
    .eq('user_id', user.userId)
    .order('created_at', { ascending: false })
    .limit(20);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { notificaciones: data || [] });
}

async function handlePatchNotificacionLeer(req, res, user, id) {
  const { error } = await adminSupabase
    .from('notificaciones').update({ leida: true })
    .eq('id', id).eq('user_id', user.userId);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

async function handlePostNotificacionesLeerTodas(req, res, user) {
  const { error } = await adminSupabase
    .from('notificaciones').update({ leida: true })
    .eq('user_id', user.userId).eq('leida', false);
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

// ── CONFIG (tienda + MP + notificaciones) ─────────────────────────────────────
async function handleGetConfig(req, res, user) {
  const { data: mp } = await adminSupabase
    .from('mp_conexiones')
    .select('conectado, tienda_url, tienda_nombre, vercel_deploy_hook, mp_last_sync, mp_user_id')
    .eq('user_id', user.userId)
    .single();

  let telegramToken = '';
  const tgCfg = user.telegramConfig;
  if (tgCfg?.token) { try { telegramToken = decrypt(tgCfg.token); } catch {} }

  return json(res, 200, {
    tiendaUrl:                mp?.tienda_url        || '',
    tiendaNombre:             mp?.tienda_nombre     || '',
    tiendaPublicId:           user.tiendaPublicId   || null,
    supabaseUrl:              process.env.SUPABASE_URL || '',
    mpConectado:              mp?.conectado         || false,
    mpUserId:            mp?.mp_user_id           || null,
    mpLastSync:          mp?.mp_last_sync         || null,
    alertasEmail:        user.alertasEmail,
    emailAlternativo:    user.emailAlternativo,
    tipoCuenta:          user.tipoCuenta           || 'gestion',
    telegramConfigurado: !!(tgCfg?.token && tgCfg?.chat_id),
    telegramActivo:      tgCfg?.activo === true,
    telegramToken,
    telegramChatId:      tgCfg?.chat_id || process.env.TELEGRAM_CHAT_ID || ''
  });
}

async function handleGetPerfil(req, res, user) {
  return json(res, 200, {
    nombre:            user.nombre,
    email:             user.email,
    tipoCuenta:        user.tipoCuenta,
    tiendaConfigurada: user.tiendaConfigurada,
    metaMensual:       user.metaMensual,
    telefonoUsuario:   user.telefonoUsuario,
    tiendaPublicId:    user.tiendaPublicId,
  });
}

async function handlePutPerfilTienda(req, res, user) {
  const body = await parseBody(req);
  const mpUpdates = {};
  if (body.tiendaNombre    !== undefined) mpUpdates.tienda_nombre        = body.tiendaNombre;
  if (body.tiendaUrl       !== undefined) mpUpdates.tienda_url           = body.tiendaUrl;
  if (body.vercelDeployHook !== undefined) mpUpdates.vercel_deploy_hook  = body.vercelDeployHook;

  const { error: mpErr } = await adminSupabase
    .from('mp_conexiones')
    .upsert({ user_id: user.userId, ...mpUpdates, updated_at: new Date().toISOString() }, { onConflict: 'user_id' });
  if (mpErr) return json(res, 500, { error: mpErr.message });

  await adminSupabase.from('perfiles')
    .update({ tienda_configurada: true }).eq('id', user.userId);

  return json(res, 200, { ok: true });
}

async function handlePutPerfil(req, res, user) {
  const body = await parseBody(req);
  const updates = {};
  if (body.nombre            !== undefined) updates.nombre            = body.nombre;
  if (body.alertasEmail      !== undefined) updates.alertas_email     = body.alertasEmail;
  if (body.emailAlternativo  !== undefined) updates.email_alternativo = body.emailAlternativo;
  if (body.metaMensual       !== undefined) updates.meta_mensual      = body.metaMensual ? parseFloat(body.metaMensual) : null;
  if (body.telefonoUsuario   !== undefined) updates.telefono_usuario  = body.telefonoUsuario || '';
  const { error } = await adminSupabase.from('perfiles').update(updates).eq('id', user.userId);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

async function handleCambiarPassword(req, res, user) {
  const body = await parseBody(req);
  const { passwordActual, passwordNuevo } = body;
  if (!passwordActual || !passwordNuevo) return json(res, 400, { error: 'Faltan datos' });
  if (passwordNuevo.length < 8) return json(res, 400, { error: 'La contraseña debe tener al menos 8 caracteres' });

  const { error: signInErr } = await anonSupabase.auth.signInWithPassword({ email: user.email, password: passwordActual });
  if (signInErr) return json(res, 400, { error: 'La contraseña actual es incorrecta' });

  const { error } = await adminSupabase.auth.admin.updateUserById(user.userId, { password: passwordNuevo });
  if (error) return json(res, 500, { error: error.message });

  await logActividad(user.userId, user.email, 'cambio_password', '', '');
  return json(res, 200, { ok: true });
}

async function handleEliminarCuenta(req, res, user) {
  const rl = await rateLimit(`del-cuenta:${user.userId}`, 1, 60 * 60 * 1000);
  if (!rl) return json(res, 429, { error: 'Demasiados intentos. Esperá 1 hora.' });

  const uid = user.userId;

  // Eliminar en orden para respetar FK: primero hijos, luego padres
  const tablas = ['pagos','ventas','gastos','clientes','ventas_online','contadores','mp_oauth_states','mp_conexiones','rate_limits','logs_actividad'];
  for (const tabla of tablas) {
    await adminSupabase.from(tabla).delete().eq('user_id', uid).catch(() => {});
  }

  // Variantes y productos (variantes no tienen user_id → borrar por producto_id)
  const { data: prods } = await adminSupabase.from('productos').select('id').eq('user_id', uid);
  if (prods?.length) {
    await adminSupabase.from('producto_variantes').delete().in('producto_id', prods.map(p => p.id));
    await adminSupabase.from('productos').delete().eq('user_id', uid);
  }

  await adminSupabase.from('perfiles').delete().eq('id', uid);

  const { error } = await adminSupabase.auth.admin.deleteUser(uid);
  if (error) return json(res, 500, { error: 'Error al eliminar la cuenta: ' + error.message });

  return json(res, 200, { ok: true });
}

async function handleTelegramConfig(req, res, user) {
  const body = await parseBody(req);
  const { chatId, activo } = body;
  const tokenInput = body.token || '';

  let encryptedToken;
  if (tokenInput) {
    encryptedToken = encrypt(tokenInput);
  } else {
    // Mantener token existente
    const existing = user.telegramConfig;
    encryptedToken = existing?.token || null;
  }

  if (!encryptedToken && !chatId) {
    await adminSupabase.from('perfiles').update({ telegram_config: null }).eq('id', user.userId);
    return json(res, 200, { ok: true });
  }
  if (!encryptedToken || !chatId) return json(res, 400, { error: 'Faltan token o Chat ID' });

  const telegramConfig = { token: encryptedToken, chat_id: chatId, activo: activo !== false };
  const { error } = await adminSupabase.from('perfiles').update({ telegram_config: telegramConfig }).eq('id', user.userId);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

async function handleTelegramTest(req, res, user) {
  const body = await parseBody(req);
  const chatId = body.chatId;
  let token = body.token;

  if (!token) {
    const tgCfg = user.telegramConfig;
    if (tgCfg?.token) { try { token = decrypt(tgCfg.token); } catch {} }
  }
  if (!token || !chatId) return json(res, 400, { error: 'Faltan token o Chat ID' });

  try {
    const resp = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: 'En Orden: conexión de Telegram funcionando correctamente.' })
    });
    const data = await resp.json();
    if (!data.ok) return json(res, 400, { error: data.description || 'Error de Telegram' });
    return json(res, 200, { ok: true });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
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

// ── TIENDA PÚBLICA — Catálogo de productos ─────────────────────────────────────
async function handleTiendaPublica(req, res, rawPublicId) {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
  res.setHeader('Cache-Control', 'public, max-age=5, s-maxage=5');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET');

  if (req.method !== 'GET') return res.status(405).json({ error: 'Método no permitido' });

  // Validar formato: exactamente 32 hex lowercase — ANTES de tocar la DB (evita timing attacks)
  if (!/^[a-f0-9]{32}$/.test(rawPublicId)) {
    return res.status(400).json({ error: 'Solicitud inválida' });
  }

  // Rate limiting doble: por publicId y por IP
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.headers['x-real-ip'] || 'unknown';
  const ipHash = 'ip_' + crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16);

  const [rlTienda, rlIp] = await Promise.all([
    rateLimit(`tienda_${rawPublicId}`, 120, 60000),
    rateLimit(ipHash, 200, 60000),
  ]);
  if (!rlTienda || !rlIp) {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({ error: 'Demasiadas solicitudes. Intentá en 60 segundos.' });
  }

  // Buscar perfil por publicId (solo activos)
  const { data: perfil, error: perfilErr } = await adminSupabase
    .from('perfiles')
    .select('id, activo')
    .eq('tienda_public_id', rawPublicId)
    .eq('activo', true)
    .single();

  console.log('[tienda] perfil encontrado:', perfil?.id, '| error:', perfilErr?.message || null);
  if (perfilErr || !perfil) {
    return res.status(404).json({ error: 'Tienda no encontrada' });
  }

  // Nombre de tienda
  const { data: mp } = await adminSupabase
    .from('mp_conexiones').select('tienda_nombre').eq('user_id', perfil.id).single();

  // Paginación
  const urlObj = new URL(req.url, 'http://localhost');
  const pagina = Math.max(1, parseInt(urlObj.searchParams.get('pagina') || '1', 10));
  const limit = 100;
  const offset = (pagina - 1) * limit;

  // Productos — solo campos públicos, nunca SELECT *
  const { data: productos, error: prodErr, count } = await adminSupabase
    .from('productos')
    .select('id, nombre, categoria, precio, imagenes, descripcion, nuevo, destacado, orden, producto_variantes(id, tipo, nombre, cantidad, imagen, color_id)', { count: 'exact' })
    .eq('user_id', perfil.id)
    .eq('activo', true)
    .order('orden', { ascending: true })
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  console.log('[tienda] productos encontrados:', productos?.length, '| error:', prodErr?.message || null);
  if (prodErr) {
    console.error('handleTiendaPublica productos error:', prodErr.message);
    return res.status(500).json({ error: 'Error del servidor' });
  }

  // Mapear: nunca exponer cantidad exacta de stock
  const productosPublicos = (productos || []).map(p => ({
    id:          p.id,
    nombre:      p.nombre,
    categoria:   p.categoria,
    precio:      p.precio,
    imagenes:    p.imagenes || [],
    descripcion: p.descripcion || '',
    nuevo:       !!p.nuevo,
    destacado:   !!p.destacado,
    orden:       p.orden || 0,
    variantes:   (p.producto_variantes || []).map(v => ({
      id:         v.id,
      tipo:       v.tipo,
      nombre:     v.nombre,
      disponible: (v.cantidad || 0) > 0,
      imagen:     v.imagen || '',
      colorId:    v.color_id || null,
    })),
  }));

  // Log no bloqueante
  logActividad(null, '', 'api_tienda_acceso',
    `publicId: ${rawPublicId.slice(0, 8)}... ip_hash: ${ipHash} productos: ${productosPublicos.length}`
  ).catch(() => {});

  return res.status(200).json({
    tienda:      mp?.tienda_nombre || 'Tienda',
    productos:   productosPublicos,
    total:       count || 0,
    pagina,
    hay_mas:     (offset + limit) < (count || 0),
    actualizado: new Date().toISOString(),
  });
}

// ── TIENDA — Regenerar ID público ─────────────────────────────────────────────
async function handleRegenTiendaId(req, res, user) {
  const newId = crypto.randomBytes(16).toString('hex');
  const { error } = await adminSupabase
    .from('perfiles').update({ tienda_public_id: newId }).eq('id', user.userId);
  if (error) return json(res, 500, { error: 'Error al regenerar el ID' });
  logActividad(user.userId, user.email, 'tienda_id_regenerado', 'ID de tienda regenerado').catch(() => {});
  return json(res, 200, { tiendaPublicId: newId });
}

// ── MP OAUTH — Iniciar (legado: GET, requiere header — usar POST get-oauth-url) ─
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

// ── MP OAUTH — Iniciar (nuevo: POST, devuelve URL como JSON) ──────────────────
async function handleMpGetOauthUrl(req, res, user) {
  if (!MP_CLIENT_ID) return json(res, 500, { error: 'MP_CLIENT_ID no configurado' });
  const state = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  const { error: stateErr } = await adminSupabase
    .from('mp_oauth_states')
    .insert({ state, user_id: user.userId, expires_at: expiresAt });
  if (stateErr) return json(res, 500, { error: 'Error al iniciar OAuth: ' + stateErr.message });

  const url = new URL('https://auth.mercadopago.com.ar/authorization');
  url.searchParams.set('client_id', MP_CLIENT_ID);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('platform_id', 'mp');
  url.searchParams.set('redirect_uri', MP_REDIRECT_URI);
  url.searchParams.set('state', state);
  url.searchParams.set('prompt', 'login');
  console.log('[MP OAuth] URL generada:', url.toString());
  return json(res, 200, { url: url.toString() });
}

// ── MP OAUTH — Callback ───────────────────────────────────────────────────────
async function handleMpCallback(req, res) {
  const { code, state, error: mpError } = req.query;

  if (mpError) {
    return res.writeHead(302, { Location: `${APP_URL}/?mp_error=${encodeURIComponent(mpError)}` }), res.end();
  }
  if (!code || !state) {
    return res.writeHead(302, { Location: `${APP_URL}/?mp_error=params_faltantes` }), res.end();
  }

  // Validar state desde DB (one-time use: SELECT + DELETE atómico)
  const { data: stateRow } = await adminSupabase
    .from('mp_oauth_states')
    .select('user_id, expires_at')
    .eq('state', state)
    .single();

  if (!stateRow) {
    return res.writeHead(302, { Location: `${APP_URL}/?mp_error=state_invalido` }), res.end();
  }

  // Eliminar inmediatamente para evitar reutilización
  await adminSupabase.from('mp_oauth_states').delete().eq('state', state);

  if (new Date(stateRow.expires_at) < new Date()) {
    return res.writeHead(302, { Location: `${APP_URL}/?mp_error=state_expirado` }), res.end();
  }

  const userId = stateRow.user_id;

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

  res.writeHead(302, { Location: `${APP_URL}/?mp=conectado` });
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
async function handleSignStorageUpload(req, res, user) {
  const body = await parseBody(req);
  const { productoId, fileName, contentType } = body;
  if (!productoId || !fileName || !contentType) return json(res, 400, { error: 'Faltan campos requeridos' });

  const allowed = ['image/jpeg', 'image/png', 'image/webp'];
  if (!allowed.includes(contentType)) return json(res, 400, { error: 'Tipo de archivo no permitido. Usá JPG, PNG o WEBP.' });

  // Verificar que el producto pertenece al usuario
  const { data: prod } = await adminSupabase
    .from('productos').select('id').eq('id', productoId).eq('user_id', user.userId).single();
  if (!prod) return json(res, 404, { error: 'Producto no encontrado' });

  const ext = (fileName.split('.').pop() || 'jpg').toLowerCase().replace(/[^a-z0-9]/g, '');
  const safeName = Date.now() + '-' + Math.random().toString(36).slice(2, 8) + '.' + ext;
  const path = `${user.userId}/${productoId}/${safeName}`;

  const { data, error } = await adminSupabase.storage
    .from('productos')
    .createSignedUploadUrl(path);

  if (error) return json(res, 500, { error: error.message });

  return json(res, 200, {
    signedUrl: data.signedUrl,
    path,
    publicUrl: `${process.env.SUPABASE_URL}/storage/v1/object/public/productos/${path}`
  });
}

async function handleDeleteStorageFile(req, res, user) {
  const body = await parseBody(req);
  const { path } = body;
  if (!path) return json(res, 400, { error: 'Falta el path' });
  // Solo puede borrar archivos de su propio folder (userId/)
  if (!path.startsWith(user.userId + '/')) return json(res, 403, { error: 'Acceso denegado' });

  const { error } = await adminSupabase.storage.from('productos').remove([path]);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

// ── REGISTRO ──────────────────────────────────────────────────────────────────
async function handleRegistro(req, res) {
  const body = await parseBody(req);
  const { nombre, email, password, tipoCuenta, tiendaNombre, tiendaUrl, tiendaConfigurada } = body;

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

  // Validar que el dominio del email existe (MX record lookup)
  const emailNorm = email.trim().toLowerCase();
  const dominioValido = await emailDomainExists(emailNorm);
  if (!dominioValido) return json(res, 400, { error: 'Este email no parece válido. Verificá que el dominio exista.' });

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
      conectado: false,
      updated_at: new Date().toISOString()
    }, { onConflict: 'user_id' });
  }

  // Log
  await logActividad(userId, email, 'nuevo_registro', `tipo: ${tipoCuenta}`, ip);

  // Email de bienvenida (no bloquea el registro si falla)
  sendWelcomeEmail(emailNorm, nombre).catch(() => {});

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
  const inicioMes    = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
  const inicioSemana = new Date(now.getTime() - 7 * 24 * 3600 * 1000).toISOString();

  const [
    { count: totalUsuarios },
    { count: cuentasConTienda },
    { count: cuentasGestion },
    { count: mpConectados },
    { count: nuevosEsteMes },
    { count: nuevosEstaSemana },
  ] = await Promise.all([
    adminSupabase.from('perfiles').select('*', { count: 'exact', head: true }).eq('rol', 'usuario'),
    adminSupabase.from('perfiles').select('*', { count: 'exact', head: true }).eq('rol', 'usuario').eq('tipo_cuenta', 'gestion_tienda'),
    adminSupabase.from('perfiles').select('*', { count: 'exact', head: true }).eq('rol', 'usuario').eq('tipo_cuenta', 'gestion'),
    adminSupabase.from('mp_conexiones').select('*', { count: 'exact', head: true }).eq('conectado', true),
    adminSupabase.from('perfiles').select('*', { count: 'exact', head: true }).eq('rol', 'usuario').gte('created_at', inicioMes),
    adminSupabase.from('perfiles').select('*', { count: 'exact', head: true }).eq('rol', 'usuario').gte('created_at', inicioSemana),
  ]);

  const { data: activosMesData } = await adminSupabase
    .from('logs_actividad').select('user_id').gte('created_at', inicioMes).not('user_id', 'is', null);
  const activosMes = new Set((activosMesData || []).map(a => a.user_id)).size;

  // Solo eventos de plataforma en el dashboard
  const EVENTOS_PLATAFORMA = ['nuevo_registro','usuario_activado','usuario_desactivado','anuncio_publicado','cambio_plan','cron_ejecucion','cambio_password','eliminar_cuenta','reset_password_enviado','usuario_creado_por_admin'];
  const { data: actividadReciente } = await adminSupabase
    .from('logs_actividad').select('accion, detalle, created_at').in('accion', EVENTOS_PLATAFORMA)
    .order('created_at', { ascending: false }).limit(15);

  return json(res, 200, {
    totalUsuarios:    totalUsuarios    || 0,
    activosMes,
    cuentasConTienda: cuentasConTienda || 0,
    cuentasGestion:   cuentasGestion   || 0,
    mpConectados:     mpConectados     || 0,
    nuevosEsteMes:    nuevosEsteMes    || 0,
    nuevosEstaSemana: nuevosEstaSemana || 0,
    actividadReciente: actividadReciente || [],
  });
}

async function handleAdminGetUsuarios(req, res) {
  const { data: perfiles } = await adminSupabase.from('perfiles').select('*').neq('rol', 'admin').order('created_at', { ascending: false });
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
    .select('*')
    .order('created_at', { ascending: false })
    .limit(500);
  if (error) return json(res, 500, { error: error.message });

  const userIds = [...new Set((data || []).map(v => v.user_id).filter(Boolean))];
  let perfilesMap = {};
  if (userIds.length) {
    const { data: perfiles } = await adminSupabase
      .from('perfiles').select('id, nombre').in('id', userIds);
    (perfiles || []).forEach(p => { perfilesMap[p.id] = p; });
  }

  const result = (data || []).map(v => ({
    ...v,
    perfiles: perfilesMap[v.user_id] || null,
    cuenta: v.perfiles?.nombre || '—',
    comprador: (v.items?.[0]?.nombre || '').slice(0, 30),
    monto: (v.items || []).reduce((s, i) => s + (i.precio * i.cantidad), 0),
  }));
  return json(res, 200, result);
}

const ACTIVIDAD_EXCLUIR = new Set([
  'login_exitoso', 'login_fallido', 'session_check', 'page_view', 'token_refresh',
  'api_tienda_acceso',
  // Eventos privados de negocio del usuario (nunca visibles para el admin)
  'venta', 'venta_registrada', 'venta_eliminada', 'pago', 'pago_registrado', 'pago_eliminado',
  'gasto', 'gasto_registrado', 'gasto_eliminado', 'cliente', 'cliente_creado', 'cliente_editado',
  'producto', 'cuota', 'descuento', 'devolucion_registrada',
]);

async function handleAdminActividad(req, res) {
  const { data: logs } = await adminSupabase
    .from('logs_actividad')
    .select('accion, detalle, created_at, ip')
    .order('created_at', { ascending: false })
    .limit(500);

  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const rows = (logs || [])
    .filter(l => !ACTIVIDAD_EXCLUIR.has(l.accion))
    .slice(0, 200)
    .map(l => {
      const partes = (l.detalle || '').split(' — ');
      const tieneEmail = partes.length > 1 && EMAIL_RE.test(partes[0]);
      const email  = tieneEmail ? partes[0] : '—';
      const detalle = tieneEmail ? partes.slice(1).join(' — ') : (l.detalle || '');
      return { accion: l.accion, email, detalle, createdAt: l.created_at, ip: l.ip || '' };
    });

  return json(res, 200, rows);
}

// ── PAGOS (CUENTA CORRIENTE) ──────────────────────────────────────────────────
async function handlePostPago(req, res, user) {
  const body = await parseBody(req);
  const monto = parseFloat(body.monto);
  if (!monto || monto <= 0) return json(res, 400, { error: 'El monto debe ser mayor a 0' });

  const medios = ['efectivo','transferencia','tarjeta','otro'];
  const medioPago = medios.includes(body.medioPago) ? body.medioPago : 'efectivo';
  const fecha = body.fecha || new Date().toISOString().split('T')[0];
  const nota = (body.nota || '').trim().slice(0, 200);

  // Validar que el cliente pertenece al usuario
  const { data: cliente } = await adminSupabase
    .from('clientes').select('id').eq('id', body.clienteId).eq('user_id', user.userId).single();
  if (!cliente) return json(res, 403, { error: 'Cliente no encontrado o sin acceso' });

  // Rate limit: 30 req/min
  const allowed = await rateLimit(`pagos:${user.userId}`, 30, 60000);
  if (!allowed) return json(res, 429, { error: 'Demasiadas solicitudes' });

  const { data, error } = await adminSupabase.from('pagos').insert({
    user_id:    user.userId,
    cliente_id: body.clienteId,
    monto,
    fecha,
    medio_pago: medioPago,
    nota
  }).select().single();
  if (error) return json(res, 500, { error: error.message });

  await logActividad(user.userId, user.email, 'pago_registrado', `cliente: ${body.clienteId}, monto: ${monto}`);

  // Retornar pago + nuevo saldo del cliente
  const { data: saldoData } = await adminSupabase
    .from('saldos_clientes').select('saldo, total_comprado, total_pagado')
    .eq('cliente_id', body.clienteId).eq('user_id', user.userId).single();

  return json(res, 201, { pago: toPago(data), saldo: saldoData?.saldo || 0 });
}

async function handleDeletePago(req, res, user, id) {
  const { data: pago } = await adminSupabase
    .from('pagos').select('*').eq('id', id).eq('user_id', user.userId).single();
  if (!pago) return json(res, 404, { error: 'Pago no encontrado' });

  const limite24hs = new Date(Date.now() - 24 * 60 * 60 * 1000);
  if (user.role !== 'admin' && new Date(pago.created_at) < limite24hs) {
    return json(res, 403, { error: 'Solo podés eliminar pagos registrados en las últimas 24 horas' });
  }

  const { error } = await adminSupabase.from('pagos').delete().eq('id', id).eq('user_id', user.userId);
  if (error) return json(res, 500, { error: error.message });

  await logActividad(user.userId, user.email, 'pago_eliminado', `pago_id: ${id}, monto: ${pago.monto}`);
  return json(res, 200, { ok: true });
}

async function handleGetCuentaCorriente(req, res, user, clienteId) {
  // Verificar que el cliente pertenece al usuario
  const { data: cliente } = await adminSupabase
    .from('clientes').select('*').eq('id', clienteId).eq('user_id', user.userId).single();
  if (!cliente) return json(res, 403, { error: 'Cliente no encontrado' });

  const [ventasRes, pagosRes, saldoRes, devolucionesRes] = await Promise.all([
    adminSupabase.from('ventas').select('*')
      .eq('cliente_id', clienteId).eq('user_id', user.userId)
      .order('fecha_compra', { ascending: false }),
    adminSupabase.from('pagos').select('*')
      .eq('cliente_id', clienteId).eq('user_id', user.userId)
      .order('fecha', { ascending: false }),
    adminSupabase.from('saldos_clientes').select('saldo, total_comprado, total_pagado')
      .eq('cliente_id', clienteId).eq('user_id', user.userId).single(),
    adminSupabase.from('devoluciones').select('*')
      .eq('cliente_id', clienteId).eq('user_id', user.userId)
      .order('fecha', { ascending: false }),
  ]);

  const totalDevuelto = (devolucionesRes.data || []).reduce((s, d) => s + parseFloat(d.monto || 0), 0);
  const saldoBase = parseFloat(saldoRes.data?.saldo || 0);

  return json(res, 200, {
    cliente: toCliente(cliente),
    ventas:  (ventasRes.data || []).map(toVenta),
    pagos:   (pagosRes.data || []).map(toPago),
    devoluciones: devolucionesRes.data || [],
    saldo:   saldoBase - totalDevuelto,
    totalComprado: saldoRes.data?.total_comprado || 0,
    totalPagado:   saldoRes.data?.total_pagado || 0,
    totalDevuelto,
  });
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

// ── AVATAR UPLOAD ─────────────────────────────────────────────────────────────
async function handleAvatarUpload(req, res, user) {
  const rl = await rateLimit(`avatar:${user.userId}`, 5, 60 * 60 * 1000);
  if (!rl) return json(res, 429, { error: 'Demasiados intentos, esperá un momento' });

  const body = await parseBody(req);
  const { data: b64 } = body;
  if (!b64) return json(res, 400, { error: 'Falta el archivo' });

  let buffer;
  try { buffer = Buffer.from(b64, 'base64'); }
  catch { return json(res, 400, { error: 'Datos de imagen inválidos' }); }

  if (buffer.length > 3 * 1024 * 1024) return json(res, 413, { error: 'El archivo no puede superar 2MB' });

  // Validar magic bytes
  const isJpeg = buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;
  const isPng  = buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47;
  const isWebp = buffer.slice(0,4).toString('ascii') === 'RIFF' && buffer.slice(8,12).toString('ascii') === 'WEBP';
  if (!isJpeg && !isPng && !isWebp) return json(res, 400, { error: 'Formato de archivo no permitido. Usá JPG, PNG o WebP.' });

  let safeBuffer;
  try {
    const sharp = require('sharp');
    const image = sharp(buffer);
    const meta  = await image.metadata();
    if (!meta.width || meta.width < 50 || meta.height < 50)
      return json(res, 400, { error: 'La imagen es demasiado pequeña (mínimo 50×50px)' });
    if (meta.width > 4000 || meta.height > 4000)
      return json(res, 400, { error: 'La imagen es demasiado grande (máximo 4000×4000px)' });
    safeBuffer = await sharp(buffer)
      .resize(400, 400, { fit: 'cover', position: 'centre' })
      .jpeg({ quality: 85 })
      .withMetadata(false)
      .toBuffer();
  } catch(e) {
    return json(res, 400, { error: 'No se pudo procesar la imagen: ' + e.message });
  }

  const path = `avatars/${user.userId}/avatar.jpg`;
  const { error: uploadErr } = await adminSupabase.storage
    .from('avatars').upload(path, safeBuffer, { contentType: 'image/jpeg', upsert: true });
  if (uploadErr) return json(res, 500, { error: 'Error al guardar la imagen: ' + uploadErr.message });

  const { data: urlData } = adminSupabase.storage.from('avatars').getPublicUrl(path);
  const avatarUrl = urlData.publicUrl;
  await adminSupabase.from('perfiles').update({ avatar_url: avatarUrl }).eq('id', user.userId);

  return json(res, 200, { ok: true, avatarUrl: avatarUrl + '?t=' + Date.now() });
}

async function handleAvatarDelete(req, res, user) {
  await adminSupabase.storage.from('avatars').remove([`avatars/${user.userId}/avatar.jpg`]);
  await adminSupabase.from('perfiles').update({ avatar_url: null }).eq('id', user.userId);
  return json(res, 200, { ok: true });
}

async function handleConfigImgUpload(req, res, user) {
  const rl = await rateLimit(`config-img:${user.userId}`, 20, 60 * 60 * 1000);
  if (!rl) return json(res, 429, { error: 'Demasiados intentos, esperá un momento' });

  const body = await parseBody(req);
  const { data: b64, tipo } = body;
  if (!b64) return json(res, 400, { error: 'Falta el archivo' });
  if (!['logo','banner'].includes(tipo)) return json(res, 400, { error: 'Tipo inválido' });

  let buffer;
  try { buffer = Buffer.from(b64, 'base64'); }
  catch { return json(res, 400, { error: 'Datos de imagen inválidos' }); }

  const maxBytes = tipo === 'banner' ? 6 * 1024 * 1024 : 3 * 1024 * 1024;
  if (buffer.length > maxBytes) return json(res, 413, { error: `El archivo no puede superar ${tipo === 'banner' ? 5 : 2}MB` });

  const isJpeg = buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;
  const isPng  = buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47;
  const isWebp = buffer.slice(0,4).toString('ascii') === 'RIFF' && buffer.slice(8,12).toString('ascii') === 'WEBP';
  if (!isJpeg && !isPng && !isWebp) return json(res, 400, { error: 'Formato no permitido. Usá JPG, PNG o WebP.' });

  let safeBuffer;
  try {
    const sharp = require('sharp');
    const maxW = tipo === 'banner' ? 1400 : 400;
    const maxH = tipo === 'banner' ? 800  : 400;
    safeBuffer = await sharp(buffer)
      .resize(maxW, maxH, { fit: 'inside', withoutEnlargement: true })
      .jpeg({ quality: 85 })
      .withMetadata(false)
      .toBuffer();
  } catch(e) {
    return json(res, 400, { error: 'No se pudo procesar la imagen: ' + e.message });
  }

  const folder = tipo === 'banner' ? 'banners' : 'logos';
  const path = `${folder}/${user.userId}/${tipo}_${Date.now()}.jpg`;
  const { error: uploadErr } = await adminSupabase.storage
    .from('avatars').upload(path, safeBuffer, { contentType: 'image/jpeg', upsert: false });
  if (uploadErr) return json(res, 500, { error: 'Error al guardar: ' + uploadErr.message });

  const { data: urlData } = adminSupabase.storage.from('avatars').getPublicUrl(path);
  return json(res, 200, { ok: true, url: urlData.publicUrl });
}

// ── ANUNCIOS ──────────────────────────────────────────────────────────────────
async function handleGetAnuncioActivo(req, res) {
  const { data } = await adminSupabase
    .from('anuncios').select('id, titulo, mensaje, tipo')
    .eq('activo', true).order('created_at', { ascending: false }).limit(1).single();
  return json(res, 200, data || null);
}

async function handleAdminGetAnuncios(req, res) {
  const { data, error } = await adminSupabase.from('anuncios').select('*').order('created_at', { ascending: false });
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, data || []);
}

async function handleAdminPostAnuncio(req, res) {
  const body = await parseBody(req);
  const { titulo, mensaje, tipo, activo } = body;
  if (!titulo?.trim() || !mensaje?.trim()) return json(res, 400, { error: 'Título y mensaje son requeridos' });
  const tipoVal = ['info','novedad','mantenimiento'].includes(tipo) ? tipo : 'info';
  const { data, error } = await adminSupabase.from('anuncios').insert({
    titulo: titulo.trim().slice(0,60), mensaje: mensaje.trim().slice(0,300), tipo: tipoVal, activo: activo !== false
  }).select().single();
  if (error) return json(res, 500, { error: error.message });
  await logActividad(null, 'admin', 'anuncio_publicado', titulo.slice(0,40));
  return json(res, 201, data);
}

async function handleAdminPutAnuncio(req, res, id) {
  const body = await parseBody(req);
  const updates = {};
  if (body.titulo  !== undefined) updates.titulo  = body.titulo.trim().slice(0,60);
  if (body.mensaje !== undefined) updates.mensaje = body.mensaje.trim().slice(0,300);
  if (['info','novedad','mantenimiento'].includes(body.tipo)) updates.tipo = body.tipo;
  if (body.activo  !== undefined) updates.activo  = !!body.activo;
  const { error } = await adminSupabase.from('anuncios').update(updates).eq('id', id);
  if (error) return json(res, 500, { error: error.message });
  await logActividad(null, 'admin', 'anuncio_editado', `id: ${id}`);
  return json(res, 200, { ok: true });
}

async function handleAdminDeleteAnuncio(req, res, id) {
  const { error } = await adminSupabase.from('anuncios').delete().eq('id', id);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

// ── ESTADO DEL SISTEMA ────────────────────────────────────────────────────────
async function handleAdminSistemaStatus(req, res) {
  const results = {};

  // DB
  try {
    const { error } = await adminSupabase.from('perfiles').select('id').limit(1);
    results.db = error ? { ok: false, label: 'Error de conexión', sublabel: error.message } : { ok: true, label: 'Operativo' };
  } catch(e) { results.db = { ok: false, label: 'Sin conexión', sublabel: e.message }; }

  // MercadoPago
  const mpClientId  = process.env.MP_CLIENT_ID;
  const mpClientSecret = process.env.MP_CLIENT_SECRET;
  if (!mpClientId || !mpClientSecret) {
    results.mp = { ok: 'none', label: 'No configurado', sublabel: 'Configurá MP_CLIENT_ID y MP_CLIENT_SECRET en las variables de entorno.' };
  } else {
    try {
      const r = await fetch('https://api.mercadopago.com/v1/payment_methods',
        { headers: { 'Authorization': `Bearer ${mpClientSecret}` }, signal: AbortSignal.timeout(5000) });
      results.mp = r.ok
        ? { ok: true, label: 'Operativo' }
        : { ok: false, label: `Error ${r.status}`, sublabel: r.status === 401 ? 'Credenciales inválidas. Verificá MP_CLIENT_ID y MP_CLIENT_SECRET.' : 'La API de MercadoPago devolvió un error inesperado.' };
    } catch { results.mp = { ok: false, label: 'Sin respuesta', sublabel: 'No se pudo contactar la API de MercadoPago.' }; }
  }

  // Email / Brevo
  const brevoKey = process.env.BREVO_SMTP_PASS || process.env.BREVO_SMTP_KEY;
  if (!brevoKey) {
    results.email = { ok: 'none', label: 'No configurado', sublabel: 'Configurá BREVO_SMTP_PASS en las variables de entorno.' };
  } else {
    results.email = { ok: true, label: 'Configurado' };
  }

  try {
    const { data } = await adminSupabase.from('logs_actividad')
      .select('created_at').eq('accion', 'cron_ejecucion')
      .order('created_at', { ascending: false }).limit(1).single();
    if (data) {
      const hrs = (Date.now() - new Date(data.created_at).getTime()) / 3600000;
      results.cron = hrs < 25
        ? { ok: true, label: `Último: ${new Date(data.created_at).toLocaleString('es-AR',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})}` }
        : { ok: 'warn', label: `Hace ${Math.round(hrs)}h — Revisar` };
    } else { results.cron = { ok: 'none', label: 'Sin datos' }; }
  } catch { results.cron = { ok: 'none', label: 'Sin datos' }; }

  return json(res, 200, results);
}

// ── IMPORTAR CLIENTES ─────────────────────────────────────────────────────────
async function handleImportarClientes(req, res, user) {
  const body = await parseBody(req);
  const rows = body.clientes;
  if (!Array.isArray(rows) || !rows.length) return json(res, 400, { error: 'Sin datos para importar' });
  if (rows.length > 500) return json(res, 400, { error: 'Máximo 500 clientes por importación' });

  const { data: existentes } = await adminSupabase.from('clientes').select('nombre').eq('user_id', user.userId);
  const nombresSet = new Set((existentes || []).map(c => c.nombre.toLowerCase()));

  const nuevos = [];
  let saltados = 0;
  for (const row of rows) {
    const nombre = (row.nombre || '').trim();
    if (!nombre) continue;
    if (nombresSet.has(nombre.toLowerCase())) { saltados++; continue; }
    nuevos.push({ user_id: user.userId, nombre, telefono: (row.telefono||'').trim().slice(0,30), notas: (row.notas||'').trim().slice(0,500) });
    nombresSet.add(nombre.toLowerCase());
  }

  if (!nuevos.length) return json(res, 200, { importados: 0, saltados });
  const { error } = await adminSupabase.from('clientes').insert(nuevos);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { importados: nuevos.length, saltados });
}

// ── EXPORTAR DATOS ────────────────────────────────────────────────────────────
async function handleExportarDatos(req, res, user) {
  const rl = await rateLimit(`export:${user.userId}`, 3, 24 * 60 * 60 * 1000);
  if (!rl) return json(res, 429, { error: 'Máximo 3 exportaciones por día' });

  let XLSX;
  try { XLSX = require('xlsx'); } catch { return json(res, 500, { error: 'Módulo de exportación no disponible' }); }

  const [clRaw, vRaw, pRaw, gRaw] = await Promise.all([
    adminSupabase.from('saldos_clientes').select('nombre, saldo, total_comprado, total_pagado').eq('user_id', user.userId),
    adminSupabase.from('ventas').select('fecha_compra, prenda, precio_venta, descuento, pagado, adeuda, notas, clientes(nombre)').eq('user_id', user.userId).order('fecha_compra', { ascending: false }),
    adminSupabase.from('pagos').select('fecha, monto, medio_pago, nota, clientes(nombre)').eq('user_id', user.userId).order('fecha', { ascending: false }),
    adminSupabase.from('gastos').select('fecha, descripcion, categoria, monto, notas').eq('user_id', user.userId).order('fecha', { ascending: false }),
  ]);

  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(
    (clRaw.data||[]).map(c => ({ Nombre: c.nombre, 'Total comprado': c.total_comprado||0, 'Total pagado': c.total_pagado||0, Saldo: c.saldo||0 }))
  ), 'Clientes');
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(
    (vRaw.data||[]).map(v => ({ Fecha: v.fecha_compra||'', Cliente: v.clientes?.nombre||'—', Producto: v.prenda||'', 'Precio venta': v.precio_venta||0, Descuento: v.descuento||0, Pagado: v.pagado||0, Adeuda: v.adeuda||0, Notas: v.notas||'' }))
  ), 'Ventas');
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(
    (pRaw.data||[]).map(p => ({ Fecha: p.fecha||'', Cliente: p.clientes?.nombre||'—', Monto: p.monto||0, 'Medio de pago': p.medio_pago||'', Nota: p.nota||'' }))
  ), 'Pagos');
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(
    (gRaw.data||[]).map(g => ({ Fecha: g.fecha||'', Descripción: g.descripcion||'', Categoría: g.categoria||'', Monto: g.monto||0, Notas: g.notas||'' }))
  ), 'Gastos');

  const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  const fecha = new Date().toISOString().split('T')[0];
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="enorden-backup-${fecha}.xlsx"`);
  res.status(200).send(buf);
}

// ── DEVOLUCIONES ──────────────────────────────────────────────────────────────
async function handleGetDevoluciones(req, res, user) {
  const clienteId = new URL(req.url, 'http://x').searchParams.get('clienteId');
  let q = adminSupabase.from('devoluciones').select('*').eq('user_id', user.userId).order('fecha', { ascending: false });
  if (clienteId) q = q.eq('cliente_id', clienteId);
  const { data, error } = await q;
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, data || []);
}

async function handlePostDevolucion(req, res, user) {
  const body = await parseBody(req);
  const monto = parseFloat(body.monto);
  if (!body.clienteId) return json(res, 400, { error: 'clienteId es requerido' });
  if (!monto || monto <= 0) return json(res, 400, { error: 'El monto debe ser mayor a 0' });

  const { data: cliente } = await adminSupabase.from('clientes').select('id')
    .eq('id', body.clienteId).eq('user_id', user.userId).single();
  if (!cliente) return json(res, 403, { error: 'Cliente no encontrado' });

  const { data, error } = await adminSupabase.from('devoluciones').insert({
    user_id: user.userId, cliente_id: body.clienteId,
    venta_id: body.ventaId || null,
    monto, motivo: (body.motivo||'').trim().slice(0,300),
    fecha: body.fecha || new Date().toISOString().split('T')[0],
  }).select().single();
  if (error) return json(res, 500, { error: error.message });

  await logActividad(user.userId, user.email, 'devolucion_registrada', `cliente: ${body.clienteId}, monto: ${monto}`);
  return json(res, 201, data);
}

// ── REPORTE MENSUAL CRON ──────────────────────────────────────────────────────
async function handleCronReporteMensual(req, res) {
  const secret = process.env.CRON_SECRET;
  const auth   = req.headers['authorization'] || '';
  if (secret && auth !== `Bearer ${secret}`) return json(res, 401, { error: 'Unauthorized' });

  try {
    const result = await doReporteMensual();
    return json(res, 200, { ok: true, ...result });
  } catch(err) {
    return json(res, 500, { error: err.message });
  }
}

async function doReporteMensual() {
  const now  = new Date();
  const mesAnterior = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const inicioMes = mesAnterior.toISOString().split('T')[0];
  const finMes    = new Date(now.getFullYear(), now.getMonth(), 0).toISOString().split('T')[0];
  const nombreMes = mesAnterior.toLocaleString('es-AR', { month: 'long', year: 'numeric' });

  const { data: perfiles } = await adminSupabase.from('perfiles').select('id, nombre, alertas_email').eq('activo', true).eq('rol', 'usuario');
  const { data: authUsers } = await adminSupabase.auth.admin.listUsers({ perPage: 1000 });
  const emailMap = {};
  (authUsers?.users || []).forEach(u => { emailMap[u.id] = u.email; });

  let enviados = 0;
  for (const perfil of (perfiles || [])) {
    if (perfil.alertas_email === false) continue;
    const email = emailMap[perfil.id];
    if (!email) continue;

    const [ventasRes, pagosRes, gastosRes, saldoRes] = await Promise.all([
      adminSupabase.from('ventas').select('precio_venta, cantidad, pagado').eq('user_id', perfil.id).gte('fecha_compra', inicioMes).lte('fecha_compra', finMes),
      adminSupabase.from('pagos').select('monto').eq('user_id', perfil.id).gte('fecha', inicioMes).lte('fecha', finMes),
      adminSupabase.from('gastos').select('monto').eq('user_id', perfil.id).gte('fecha', inicioMes).lte('fecha', finMes),
      adminSupabase.from('saldos_clientes').select('saldo').eq('user_id', perfil.id),
    ]);

    const totalVendido = (ventasRes.data||[]).reduce((s,v) => s + (parseFloat(v.precio_venta)||0), 0);
    const totalCobrado = (pagosRes.data||[]).reduce((s,p) => s + (parseFloat(p.monto)||0), 0);
    const totalGastado = (gastosRes.data||[]).reduce((s,g) => s + (parseFloat(g.monto)||0), 0);
    const ganancia = totalVendido - totalGastado;
    const cantVentas = ventasRes.data?.length || 0;
    const deudaTotal = (saldoRes.data||[]).filter(s => s.saldo > 0).reduce((s,c) => s + c.saldo, 0);

    const fmt = (n) => n.toLocaleString('es-AR', { style:'currency', currency:'ARS', minimumFractionDigits:0, maximumFractionDigits:0 });
    const appUrl = APP_URL;

    const html = `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<style>body{font-family:Inter,Arial,sans-serif;background:#f5f5f5;margin:0;padding:0}
.wrap{max-width:520px;margin:32px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.07)}
.hdr{background:#111;padding:24px 28px;text-align:center;color:#fff;font-size:18px;font-weight:600}
.body{padding:24px 28px}
.body p{color:#444;font-size:14px;line-height:1.6;margin:0 0 16px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:16px 0}
.card{background:#f9f9f9;border-radius:8px;padding:12px 14px}
.card .lbl{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.05em}
.card .val{font-size:18px;font-weight:700;color:#111;margin-top:4px}
.card .val.green{color:#2d6635}.card .val.red{color:#8b2020}
.btn{display:inline-block;background:#111;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;font-size:14px;font-weight:600;margin:8px 0 20px}
.foot{background:#f9f9f9;padding:14px 28px;text-align:center;color:#999;font-size:12px;line-height:1.6}
</style></head><body>
<div class="wrap">
  <div class="hdr">En Orden — Resumen de ${nombreMes}</div>
  <div class="body">
    <p>Hola <strong>${perfil.nombre || email.split('@')[0]}</strong>, este fue tu mes en EnOrden:</p>
    <div class="grid">
      <div class="card"><div class="lbl">Vendiste</div><div class="val">${fmt(totalVendido)}</div></div>
      <div class="card"><div class="lbl">Cobraste</div><div class="val green">${fmt(totalCobrado)}</div></div>
      <div class="card"><div class="lbl">Gastaste</div><div class="val red">${fmt(totalGastado)}</div></div>
      <div class="card"><div class="lbl">Ganancia neta</div><div class="val ${ganancia >= 0 ? 'green':'red'}">${fmt(ganancia)}</div></div>
    </div>
    <div class="card" style="margin-bottom:16px"><div class="lbl">Ventas realizadas</div><div class="val">${cantVentas}</div></div>
    ${deudaTotal > 0 ? `<p style="color:#8b2020;font-size:13px">Tenés <strong>${fmt(deudaTotal)}</strong> en deuda pendiente de tus clientas.</p>` : ''}
    <a href="${appUrl}" class="btn">Ver detalle en EnOrden →</a>
  </div>
  <div class="foot">Configurá tus notificaciones en Configuración → Notificaciones<br>EnOrden · Gestión de ventas</div>
</div>
</body></html>`;

    try {
      await mailer.sendMail({ from: '"En Orden" <tomipieri@hotmail.com>', to: email, subject: `Tu resumen de ${nombreMes} — EnOrden`, html });
      enviados++;
    } catch {}
  }

  await logActividad(null, 'system', 'cron_ejecucion', `reporte_mensual: ${enviados} emails enviados`);
  return { enviados };
}

// ── MIGRATION V5 ──────────────────────────────────────────────────────────────
async function handleMigrationV5(req, res) {
  const secret = process.env.CRON_SECRET;
  const auth = req.headers['authorization'] || '';
  if (!secret || auth !== `Bearer ${secret}`) return json(res, 401, { error: 'Unauthorized' });

  const steps = [];
  async function exec(label, sql) {
    try {
      const { error } = await adminSupabase.rpc('exec_sql', { sql });
      if (error) throw error;
      steps.push({ ok: true, label });
    } catch(e) { steps.push({ ok: false, label, error: e.message }); }
  }

  await exec('avatar_url en perfiles', `ALTER TABLE perfiles ADD COLUMN IF NOT EXISTS avatar_url TEXT DEFAULT NULL`);
  await exec('tags en clientes', `ALTER TABLE clientes ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}'`);
  await exec('alertas_email en perfiles', `ALTER TABLE perfiles ADD COLUMN IF NOT EXISTS alertas_email BOOLEAN DEFAULT true`);
  await exec('CREATE TABLE anuncios', `CREATE TABLE IF NOT EXISTS anuncios (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    titulo TEXT NOT NULL, mensaje TEXT NOT NULL,
    tipo TEXT DEFAULT 'info' CHECK (tipo IN ('info','novedad','mantenimiento')),
    activo BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await exec('CREATE TABLE devoluciones', `CREATE TABLE IF NOT EXISTS devoluciones (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) NOT NULL,
    cliente_id UUID REFERENCES clientes(id) NOT NULL,
    venta_id UUID REFERENCES ventas(id),
    monto NUMERIC(12,2) NOT NULL CHECK (monto > 0),
    motivo TEXT DEFAULT '',
    fecha DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await exec('RLS devoluciones', `ALTER TABLE devoluciones ENABLE ROW LEVEL SECURITY`);
  await exec('Policy devoluciones', `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='devoluciones' AND policyname='own_data') THEN CREATE POLICY "own_data" ON devoluciones USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid()); END IF; END $$`);
  await exec('CREATE BUCKET avatars', `SELECT 1`); // bucket se crea vía adminSupabase.storage

  // Crear bucket avatars via Storage API
  try {
    await adminSupabase.storage.createBucket('avatars', { public: true });
    steps.push({ ok: true, label: 'Bucket avatars creado' });
  } catch(e) {
    steps.push({ ok: false, label: 'Bucket avatars (ya existe o error)', error: e.message });
  }

  // Crear bucket productos via Storage API
  try {
    await adminSupabase.storage.createBucket('productos', {
      public: true,
      fileSizeLimit: 5 * 1024 * 1024,
      allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp']
    });
    steps.push({ ok: true, label: 'Bucket productos creado' });
  } catch(e) {
    steps.push({ ok: false, label: 'Bucket productos (ya existe o error)', error: e.message });
  }

  // Políticas RLS para storage.objects bucket productos
  await exec('Storage RLS SELECT public', `
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='objects' AND schemaname='storage' AND policyname='productos_public_read') THEN
        CREATE POLICY "productos_public_read" ON storage.objects FOR SELECT USING (bucket_id = 'productos');
      END IF;
    END $$`);
  await exec('Storage RLS INSERT own folder', `
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='objects' AND schemaname='storage' AND policyname='productos_owner_insert') THEN
        CREATE POLICY "productos_owner_insert" ON storage.objects FOR INSERT WITH CHECK (
          bucket_id = 'productos' AND auth.uid()::text = (storage.foldername(name))[1]
        );
      END IF;
    END $$`);
  await exec('Storage RLS DELETE own folder', `
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='objects' AND schemaname='storage' AND policyname='productos_owner_delete') THEN
        CREATE POLICY "productos_owner_delete" ON storage.objects FOR DELETE USING (
          bucket_id = 'productos' AND auth.uid()::text = (storage.foldername(name))[1]
        );
      END IF;
    END $$`);

  return json(res, 200, { ok: true, steps });
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

// ── MIGRACIÓN V6 — tienda_config + promociones ────────────────────────────────
async function handleMigrationV6(req, res) {
  const secret = process.env.CRON_SECRET;
  const auth = req.headers['authorization'] || '';
  if (!secret || auth !== `Bearer ${secret}`) return json(res, 401, { error: 'Unauthorized' });

  const steps = [];
  async function exec(label, sql) {
    try {
      const { error } = await adminSupabase.rpc('exec_sql', { sql });
      if (error) throw error;
      steps.push({ ok: true, label });
    } catch(e) { steps.push({ ok: false, label, error: e.message }); }
  }

  await exec('CREATE tienda_config', `CREATE TABLE IF NOT EXISTS tienda_config (
    id                  UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id             UUID REFERENCES auth.users(id) NOT NULL UNIQUE,
    nombre_tienda       TEXT DEFAULT '',
    descripcion         TEXT DEFAULT '',
    logo_url            TEXT DEFAULT NULL,
    color_primario      TEXT DEFAULT '#A88671',
    banner_imagen_url   TEXT DEFAULT NULL,
    banner_titulo       TEXT DEFAULT '',
    banner_subtitulo    TEXT DEFAULT '',
    banner_boton_texto  TEXT DEFAULT 'Ver coleccion',
    banner_boton_url    TEXT DEFAULT '/productos',
    secciones           JSONB DEFAULT '[]',
    franja_texto        TEXT DEFAULT '',
    franja_activa       BOOLEAN DEFAULT false,
    instagram_url       TEXT DEFAULT '',
    whatsapp_numero     TEXT DEFAULT '',
    envio_gratis_desde  NUMERIC(12,2) DEFAULT NULL,
    marquee_items       JSONB DEFAULT '[]',
    updated_at          TIMESTAMPTZ DEFAULT NOW()
  )`);
  await exec('RLS tienda_config', `ALTER TABLE tienda_config ENABLE ROW LEVEL SECURITY`);
  await exec('POLICY tienda_config', `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='tienda_config' AND policyname='usuario gestiona su config') THEN CREATE POLICY "usuario gestiona su config" ON tienda_config FOR ALL USING (auth.uid() = user_id); END IF; END $$`);

  await exec('CREATE promociones', `CREATE TABLE IF NOT EXISTS promociones (
    id               UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id          UUID REFERENCES auth.users(id) NOT NULL,
    nombre           TEXT NOT NULL,
    tipo             TEXT NOT NULL DEFAULT 'codigo',
    codigo           TEXT DEFAULT NULL,
    descuento_tipo   TEXT DEFAULT 'porcentaje',
    descuento_valor  NUMERIC(10,2) DEFAULT 0,
    monto_minimo     NUMERIC(12,2) DEFAULT NULL,
    aplica_a         TEXT DEFAULT 'todo',
    aplica_a_valor   TEXT DEFAULT NULL,
    usos_max         INTEGER DEFAULT NULL,
    usos_actuales    INTEGER DEFAULT 0,
    activa           BOOLEAN DEFAULT true,
    fecha_inicio     DATE DEFAULT NULL,
    fecha_fin        DATE DEFAULT NULL,
    created_at       TIMESTAMPTZ DEFAULT NOW()
  )`);
  await exec('RLS promociones', `ALTER TABLE promociones ENABLE ROW LEVEL SECURITY`);
  await exec('POLICY promociones', `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='promociones' AND policyname='usuario gestiona sus promos') THEN CREATE POLICY "usuario gestiona sus promos" ON promociones FOR ALL USING (auth.uid() = user_id); END IF; END $$`);
  await exec('INDEX promociones_codigo', `CREATE UNIQUE INDEX IF NOT EXISTS promociones_codigo_unique ON promociones (user_id, codigo) WHERE codigo IS NOT NULL AND activa = true`);

  await exec('CREATE notificaciones', `CREATE TABLE IF NOT EXISTS notificaciones (
    id         UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id    UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    tipo       TEXT DEFAULT 'venta',
    titulo     TEXT DEFAULT '',
    mensaje    TEXT DEFAULT '',
    leida      BOOLEAN DEFAULT false,
    meta       JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await exec('RLS notificaciones', `ALTER TABLE notificaciones ENABLE ROW LEVEL SECURITY`);
  await exec('POLICY notificaciones', `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='notificaciones' AND policyname='own_data') THEN CREATE POLICY "own_data" ON notificaciones FOR ALL USING (auth.uid() = user_id); END IF; END $$`);

  await exec('tienda_public_id en perfiles', `ALTER TABLE perfiles ADD COLUMN IF NOT EXISTS tienda_public_id TEXT DEFAULT NULL`);
  await exec('carritos table check', `SELECT 1 FROM information_schema.tables WHERE table_name='carritos'`);

  return json(res, 200, { steps });
}

// ── MIGRACIÓN V4 — descuentos en ventas ───────────────────────────────────────
async function handleMigrationV4(req, res) {
  const secret = process.env.CRON_SECRET;
  const auth = req.headers['authorization'] || '';
  if (!secret || auth !== `Bearer ${secret}`) return json(res, 401, { error: 'Unauthorized' });

  const steps = [];
  async function exec(label, sql) {
    try {
      const { error } = await adminSupabase.rpc('exec_sql', { sql });
      if (error) throw error;
      steps.push({ ok: true, label });
    } catch(e) {
      steps.push({ ok: false, label, error: e.message });
    }
  }

  await exec('ADD descuento', `ALTER TABLE ventas ADD COLUMN IF NOT EXISTS descuento NUMERIC(12,2) DEFAULT 0`);
  await exec('ADD tipo_descuento', `ALTER TABLE ventas ADD COLUMN IF NOT EXISTS tipo_descuento TEXT DEFAULT 'fijo' CHECK (tipo_descuento IN ('fijo','porcentaje'))`);

  // Actualizar la view para usar precio_final (con descuento aplicado)
  await exec('UPDATE VIEW saldos_clientes', `CREATE OR REPLACE VIEW saldos_clientes AS
    SELECT
      c.id          AS cliente_id,
      c.user_id,
      c.nombre,
      c.telefono,
      COALESCE(SUM(
        CASE
          WHEN v.tipo_descuento = 'porcentaje'
            THEN v.precio_venta * (1 - COALESCE(v.descuento,0)/100)
          ELSE v.precio_venta - COALESCE(v.descuento,0)
        END * COALESCE(v.cantidad,1)
      ), 0) AS total_comprado,
      COALESCE(SUM(p.monto), 0) AS total_pagado,
      COALESCE(SUM(
        CASE
          WHEN v.tipo_descuento = 'porcentaje'
            THEN v.precio_venta * (1 - COALESCE(v.descuento,0)/100)
          ELSE v.precio_venta - COALESCE(v.descuento,0)
        END * COALESCE(v.cantidad,1)
      ), 0) - COALESCE(SUM(p.monto), 0) AS saldo,
      COUNT(DISTINCT v.id)          AS cant_compras,
      MAX(v.fecha_compra)           AS ultima_compra,
      MAX(p.fecha)                  AS ultimo_pago
    FROM clientes c
    LEFT JOIN ventas v ON v.cliente_id = c.id AND v.user_id = c.user_id
    LEFT JOIN pagos  p ON p.cliente_id = c.id AND p.user_id = c.user_id
    GROUP BY c.id, c.user_id, c.nombre, c.telefono`);

  return json(res, 200, { ok: true, steps });
}

// ── MIGRACIÓN V3 (endpoint temporal) ─────────────────────────────────────────
async function handleMigrationV3(req, res) {
  const secret = process.env.CRON_SECRET;
  const auth = req.headers['authorization'] || '';
  if (!secret || auth !== `Bearer ${secret}`) return json(res, 401, { error: 'Unauthorized' });

  const steps = [];
  async function exec(label, sql) {
    try {
      const { error } = await adminSupabase.rpc('exec_sql', { sql });
      if (error) throw error;
      steps.push({ ok: true, label });
    } catch(e) {
      steps.push({ ok: false, label, error: e.message });
    }
  }

  // Ejecutar cada ALTER de forma independiente para evitar que un fallo bloquee todo
  const sqls = [
    ['CREATE TABLE pagos', `CREATE TABLE IF NOT EXISTS pagos (
      id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
      user_id UUID REFERENCES auth.users(id) NOT NULL,
      cliente_id UUID REFERENCES clientes(id) NOT NULL,
      monto NUMERIC(12,2) NOT NULL CHECK (monto > 0),
      fecha DATE NOT NULL DEFAULT CURRENT_DATE,
      medio_pago TEXT DEFAULT 'efectivo' CHECK (medio_pago IN ('efectivo','transferencia','tarjeta','otro')),
      nota TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`],
    ['Enable RLS pagos', `ALTER TABLE pagos ENABLE ROW LEVEL SECURITY`],
    ['RLS policy pagos', `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='pagos' AND policyname='own_data') THEN CREATE POLICY "own_data" ON pagos USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid()); END IF; END $$`],
    ['ALTER stock_minimo', `ALTER TABLE producto_variantes ADD COLUMN IF NOT EXISTS stock_minimo INTEGER DEFAULT 0`],
    ['ALTER meta_mensual', `ALTER TABLE perfiles ADD COLUMN IF NOT EXISTS meta_mensual NUMERIC(12,2) DEFAULT NULL`],
    ['ALTER gastos categoria', `ALTER TABLE gastos ADD COLUMN IF NOT EXISTS categoria TEXT DEFAULT 'otros'`],
    ['CREATE VIEW saldos_clientes', `CREATE OR REPLACE VIEW saldos_clientes AS SELECT c.id AS cliente_id, c.user_id, c.nombre, c.telefono, COALESCE(SUM(v.precio_venta * COALESCE(v.cantidad, 1)), 0) AS total_comprado, COALESCE(SUM(p.monto), 0) AS total_pagado, COALESCE(SUM(v.precio_venta * COALESCE(v.cantidad, 1)), 0) - COALESCE(SUM(p.monto), 0) AS saldo FROM clientes c LEFT JOIN ventas v ON v.cliente_id = c.id AND v.user_id = c.user_id LEFT JOIN pagos p ON p.cliente_id = c.id AND p.user_id = c.user_id GROUP BY c.id, c.user_id, c.nombre, c.telefono`],
    ['MIGRATE pagos existentes', `INSERT INTO pagos (user_id, cliente_id, monto, fecha, medio_pago, nota) SELECT v.user_id, v.cliente_id, (v.precio_venta * COALESCE(v.cantidad, 1)) - COALESCE(v.adeuda, 0), COALESCE(v.fecha_compra, v.created_at::date), 'efectivo', 'Pago migrado desde sistema anterior (venta ID: ' || v.id || ')' FROM ventas v WHERE v.cliente_id IS NOT NULL AND ((v.precio_venta * COALESCE(v.cantidad, 1)) - COALESCE(v.adeuda, 0)) > 0 AND NOT EXISTS (SELECT 1 FROM pagos p WHERE p.nota = 'Pago migrado desde sistema anterior (venta ID: ' || v.id || ')')`],
  ];

  for (const [label, sql] of sqls) await exec(label, sql);

  return json(res, 200, { ok: true, steps });
}

// ── Exportar función de chequeo de cuotas (usada por cron) ───────────────────
module.exports.checkCuotasVencimiento = async function () {
  const hoy        = new Date().toISOString().split('T')[0];
  const dias        = 3;
  const limiteStr   = new Date(Date.now() + dias * 86400000).toISOString().split('T')[0];

  // Obtener todas las ventas con cuota vencida o próxima, no notificadas hoy
  const { data: ventas } = await adminSupabase
    .from('ventas')
    .select('id, prenda, adeuda, prox_cuota, notificado_at, user_id, clientes(id, nombre, telefono)')
    .gt('adeuda', 0)
    .not('prox_cuota', 'is', null)
    .lte('prox_cuota', limiteStr)
    .neq('notificado_at', hoy);

  if (!ventas?.length) return { notificados: 0 };

  // Agrupar por user_id
  const porUsuario = {};
  for (const v of ventas) {
    if (!porUsuario[v.user_id]) porUsuario[v.user_id] = [];
    porUsuario[v.user_id].push(v);
  }

  let totalNotificados = 0;

  for (const [userId, ventasUser] of Object.entries(porUsuario)) {
    // Agrupar por cliente
    const porCliente = {};
    for (const v of ventasUser) {
      const cid = v.clientes?.id || v.user_id;
      if (!porCliente[cid]) {
        porCliente[cid] = {
          nombre:      v.clientes?.nombre || 'Sin nombre',
          totalAdeuda: 0,
          proxCuota:   v.prox_cuota,
          ids:         [],
        };
      }
      porCliente[cid].totalAdeuda += parseFloat(v.adeuda) || 0;
      if (v.prox_cuota < porCliente[cid].proxCuota) porCliente[cid].proxCuota = v.prox_cuota;
      porCliente[cid].ids.push(v.id);
    }

    const lineasVencidas = [];
    const lineasProximas = [];

    for (const datos of Object.values(porCliente)) {
      const [ay, am, ad] = datos.proxCuota.split('-');
      const fechaFmt = `${ad}/${am}/${ay}`;
      const monto = `$${datos.totalAdeuda.toLocaleString('es-AR', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
      if (datos.proxCuota < hoy) {
        lineasVencidas.push(`• ${datos.nombre}: ${monto} (venció el ${fechaFmt})`);
      } else {
        lineasProximas.push(`• ${datos.nombre}: ${monto} (vence el ${fechaFmt})`);
      }
    }

    let msg = '';
    if (lineasVencidas.length) msg += `⚠️ CUOTAS VENCIDAS:\n${lineasVencidas.join('\n')}`;
    if (lineasProximas.length) {
      if (msg) msg += '\n\n';
      msg += `📅 CUOTAS PRÓXIMAS (${dias} días):\n${lineasProximas.join('\n')}`;
    }
    if (!msg) continue;

    // Enviar email (global, solo para cuentas de sanlatorre)
    if (userId === (await getUserIdByEmail('sanlatorre@hotmail.com'))) {
      await sendEmail(
        `⚠️ Cuotas — ${hoy}`,
        `<pre style="font-family:monospace">${msg}</pre>`
      );
    }

    // Telegram: primero intentar config per-user, luego env vars globales
    const { data: perfil } = await adminSupabase
      .from('perfiles').select('telegram_config').eq('id', userId).single();

    let tgSent = false;
    if (perfil?.telegram_config?.token && perfil?.telegram_config?.chat_id && perfil?.telegram_config?.activo !== false) {
      try {
        let token = '';
        try { token = decrypt(perfil.telegram_config.token); } catch {}
        if (token) {
          await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: perfil.telegram_config.chat_id, text: msg })
          });
          tgSent = true;
        }
      } catch {}
    }

    // Fallback: env vars globales (para sanlatorre mientras no configure bot propio)
    if (!tgSent) await sendTelegram(msg);

    // Marcar notificadas
    for (const v of ventasUser) {
      await adminSupabase.from('ventas').update({ notificado_at: hoy }).eq('id', v.id);
    }
    totalNotificados += ventasUser.length;
  }

  return { notificados: totalNotificados };
};

// Helper: obtener UUID de usuario por email (con caché simple)
let _emailUuidCache = {};
async function getUserIdByEmail(email) {
  if (_emailUuidCache[email]) return _emailUuidCache[email];
  try {
    const { data: { users } } = await adminSupabase.auth.admin.listUsers({ perPage: 200 });
    const u = users.find(x => x.email === email);
    if (u) _emailUuidCache[email] = u.id;
    return u?.id || null;
  } catch { return null; }
}

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

// ══════════════════════════════════════════════════════════════════════════════
// TIENDA V2 — ENDPOINTS PÚBLICOS Y DE GESTIÓN
// ══════════════════════════════════════════════════════════════════════════════

const TIENDA_ALLOWED_ORIGINS = [
  ALLOWED_ORIGIN,
  'https://project-hqeig.vercel.app',
  'http://localhost:3000',
  'http://localhost:5500',
];

function tiendaCorsHeaders(res, req) {
  const origin = (req && req.headers.origin) || '';
  const allowOrigin = TIENDA_ALLOWED_ORIGINS.includes(origin) ? origin : TIENDA_ALLOWED_ORIGINS[0];
  res.setHeader('Access-Control-Allow-Origin', allowOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

async function resolveTiendaUser(rawPublicId) {
  if (!/^[a-f0-9]{32}$/.test(rawPublicId)) return null;
  const { data: perfil } = await adminSupabase
    .from('perfiles').select('id, activo')
    .eq('tienda_public_id', rawPublicId).eq('activo', true).single();
  return perfil || null;
}

// ── GET /api/tienda/[publicId]/config ─────────────────────────────────────────
async function handleTiendaGetConfig(req, res, rawPublicId) {
  tiendaCorsHeaders(res, req);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return json(res, 405, { error: 'Método no permitido' });
  const perfil = await resolveTiendaUser(rawPublicId);
  if (!perfil) return json(res, 404, { error: 'Tienda no encontrada' });
  res.setHeader('Cache-Control', 'public, max-age=60, s-maxage=60');
  const { data: cfg } = await adminSupabase
    .from('tienda_config').select('*').eq('user_id', perfil.id).single();
  if (!cfg) return json(res, 404, { error: 'Configuración no encontrada' });
  return json(res, 200, {
    nombre_tienda:        cfg.nombre_tienda || '',
    descripcion:          cfg.descripcion || '',
    logo_url:             cfg.logo_url || null,
    color_primario:       cfg.color_primario || '#A88671',
    banner_imagen_url:    cfg.banner_imagen_url || null,
    banner_titulo:        cfg.banner_titulo || '',
    banner_subtitulo:     cfg.banner_subtitulo || '',
    banner_boton_texto:   cfg.banner_boton_texto || 'Ver colección',
    banner_boton_url:     cfg.banner_boton_url || '/productos',
    secciones:            cfg.secciones || [],
    franja_texto:         cfg.franja_texto || '',
    franja_activa:        cfg.franja_activa || false,
    instagram_url:        cfg.instagram_url || '',
    whatsapp_numero:      cfg.whatsapp_numero || '',
    envio_gratis_desde:   cfg.envio_gratis_desde ? parseFloat(cfg.envio_gratis_desde) : null,
  });
}

// ── GET /api/tienda/[publicId]/promociones/activas ────────────────────────────
async function handleTiendaPromosActivas(req, res, rawPublicId) {
  tiendaCorsHeaders(res, req);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return json(res, 405, { error: 'Método no permitido' });
  const perfil = await resolveTiendaUser(rawPublicId);
  if (!perfil) return json(res, 404, { error: 'Tienda no encontrada' });
  res.setHeader('Cache-Control', 'public, max-age=300, s-maxage=300');
  const hoy = new Date().toISOString().slice(0, 10);
  const { data: promos } = await adminSupabase
    .from('promociones')
    .select('id, nombre, descuento_tipo, descuento_valor, monto_minimo, aplica_a, aplica_a_valor')
    .eq('user_id', perfil.id)
    .eq('tipo', 'descuento_automatico')
    .eq('activa', true)
    .lte('fecha_inicio', hoy)
    .or(`fecha_fin.is.null,fecha_fin.gte.${hoy}`);
  return json(res, 200, { promociones: promos || [] });
}

// ── POST /api/tienda/[publicId]/validar-codigo ────────────────────────────────
async function handleTiendaValidarCodigo(req, res, rawPublicId) {
  tiendaCorsHeaders(res, req);
  if (req.method === 'OPTIONS') return res.status(204).end();
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  const ipHash = 'vc_' + crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16);
  if (!await rateLimit(ipHash, 10, 3600000)) {
    res.setHeader('Retry-After', '3600');
    return json(res, 429, { valido: false, mensaje: 'Demasiados intentos. Intentá más tarde.' });
  }
  const perfil = await resolveTiendaUser(rawPublicId);
  if (!perfil) return json(res, 404, { valido: false, mensaje: 'Tienda no encontrada' });
  const body = await parseBody(req);
  const codigo = (body.codigo || '').trim().toUpperCase();
  const montoTotal = parseFloat(body.monto_total) || 0;
  if (!codigo) return json(res, 400, { valido: false, mensaje: 'Código requerido' });
  const hoy = new Date().toISOString().slice(0, 10);
  const { data: promo } = await adminSupabase
    .from('promociones')
    .select('id, descuento_tipo, descuento_valor, monto_minimo, usos_maximos, usos_actuales, aplica_a, aplica_a_valor')
    .eq('user_id', perfil.id)
    .eq('tipo', 'codigo_descuento')
    .eq('activa', true)
    .eq('codigo', codigo)
    .lte('fecha_inicio', hoy)
    .or(`fecha_fin.is.null,fecha_fin.gte.${hoy}`)
    .single();
  if (!promo) return json(res, 200, { valido: false, mensaje: 'Código inválido o vencido' });
  if (promo.usos_maximos !== null && promo.usos_actuales >= promo.usos_maximos)
    return json(res, 200, { valido: false, mensaje: 'Código inválido o vencido' });
  if (promo.monto_minimo && montoTotal < parseFloat(promo.monto_minimo))
    return json(res, 200, { valido: false, mensaje: `Monto mínimo: $${promo.monto_minimo}` });
  const desc = promo.descuento_tipo === 'porcentaje'
    ? `${promo.descuento_valor}% de descuento`
    : `$${promo.descuento_valor} de descuento`;
  return json(res, 200, {
    valido: true,
    descuento_tipo:  promo.descuento_tipo,
    descuento_valor: parseFloat(promo.descuento_valor),
    descripcion:     desc,
    promo_id:        promo.id,
  });
}

// ── POST /api/tienda/[publicId]/checkout ──────────────────────────────────────
async function handleTiendaCheckout(req, res, rawPublicId) {
  tiendaCorsHeaders(res, req);
  if (req.method === 'OPTIONS') return res.status(204).end();
  try {
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  const ipHash = 'co_' + crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16);
  if (!await rateLimit(ipHash, 5, 600000)) {
    res.setHeader('Retry-After', '600');
    return json(res, 429, { error: 'Demasiados intentos. Esperá 10 minutos.' });
  }
  const perfil = await resolveTiendaUser(rawPublicId);
  if (!perfil) return json(res, 404, { error: 'Tienda no encontrada' });

  const { data: mp } = await adminSupabase
    .from('mp_conexiones').select('access_token_encrypted, conectado, tienda_url')
    .eq('user_id', perfil.id).single();

  let accessToken;
  if (mp?.conectado && mp?.access_token_encrypted) {
    try { accessToken = decrypt(mp.access_token_encrypted); }
    catch { return json(res, 500, { error: 'Error de configuración de pagos.' }); }
  } else if (process.env.MP_ACCESS_TOKEN) {
    accessToken = process.env.MP_ACCESS_TOKEN;
  } else {
    return json(res, 400, { error: 'Esta tienda no acepta pagos online en este momento.' });
  }

  const body = await parseBody(req);
  const items = body.items;
  const cliente = body.cliente || {};
  const emailComprador = (body.email_comprador || '').trim().toLowerCase();
  const codigoDescuento = (body.codigo_descuento || '').trim().toUpperCase() || null;
  const carritoId = (body.carrito_id || '').trim();
  const envioInfo = body.envio || null;

  if (!Array.isArray(items) || !items.length) return json(res, 400, { error: 'Sin items' });
  if (!emailComprador || !emailComprador.includes('@')) return json(res, 400, { error: 'Email requerido' });

  // Verificar precios reales desde Supabase — NUNCA confiar en el frontend
  const varianteIds = items.map(i => i.varianteId).filter(Boolean);
  const { data: variantes } = await adminSupabase
    .from('producto_variantes')
    .select('id, producto_id, nombre, tipo')
    .in('id', varianteIds);
  if (!variantes?.length) return json(res, 400, { error: 'Productos no encontrados' });

  const productoIds = [...new Set(variantes.map(v => v.producto_id))];
  const { data: productosBD } = await adminSupabase
    .from('productos')
    .select('id, nombre, precio, activo')
    .in('id', productoIds)
    .eq('user_id', perfil.id)
    .eq('activo', true);
  if (!productosBD?.length) return json(res, 400, { error: 'Productos no disponibles' });

  const prodMap = Object.fromEntries(productosBD.map(p => [p.id, p]));
  const varMap = Object.fromEntries(variantes.map(v => [v.id, v]));

  // Construir items con precios reales
  let subtotal = 0;
  const mpItems = [];
  for (const item of items) {
    const variante = varMap[item.varianteId];
    if (!variante) return json(res, 400, { error: `Variante ${item.varianteId} no encontrada` });
    const producto = prodMap[variante.producto_id];
    if (!producto) return json(res, 400, { error: 'Producto no disponible' });
    const cantidad = Math.max(1, parseInt(item.cantidad) || 1);
    subtotal += producto.precio * cantidad;
    mpItems.push({
      id:          producto.id,
      title:       `${producto.nombre} — ${variante.tipo}: ${variante.nombre}`,
      quantity:    cantidad,
      unit_price:  parseFloat(producto.precio),
      currency_id: 'ARS',
    });
  }

  // Aplicar descuento si hay código
  let descuentoAplicado = 0;
  let promoIdUsado = null;
  if (codigoDescuento) {
    const hoy = new Date().toISOString().slice(0, 10);
    const { data: promo } = await adminSupabase
      .from('promociones')
      .select('id, descuento_tipo, descuento_valor, usos_maximos, usos_actuales, monto_minimo')
      .eq('user_id', perfil.id).eq('tipo', 'codigo_descuento').eq('activa', true)
      .eq('codigo', codigoDescuento).lte('fecha_inicio', hoy)
      .or(`fecha_fin.is.null,fecha_fin.gte.${hoy}`).single();
    if (promo && (promo.usos_maximos === null || promo.usos_actuales < promo.usos_maximos)) {
      if (!promo.monto_minimo || subtotal >= parseFloat(promo.monto_minimo)) {
        descuentoAplicado = promo.descuento_tipo === 'porcentaje'
          ? Math.round(subtotal * parseFloat(promo.descuento_valor) / 100)
          : Math.min(parseFloat(promo.descuento_valor), subtotal);
        promoIdUsado = promo.id;
      }
    }
  }

  // Agregar envío si corresponde
  const envioPrice = envioInfo && parseFloat(envioInfo.precio) > 0 ? parseFloat(envioInfo.precio) : 0;
  if (envioPrice > 0 && envioPrice <= 50000) {
    mpItems.push({
      id: 'envio',
      title: 'Costo de envío',
      quantity: 1,
      unit_price: envioPrice,
      currency_id: 'ARS',
    });
    subtotal += envioPrice;
  }

  const total = Math.max(0, subtotal - descuentoAplicado);
  const tiendaUrl = (mp.tienda_url || 'https://chanaindumentaria.vercel.app/').replace(/\/?$/, '/');

  // Crear preferencia en MP con el token del usuario
  const prefBody = {
    items: mpItems,
    payer: { email: emailComprador, name: cliente.nombre, surname: cliente.apellido },
    back_urls: {
      success: `${tiendaUrl}gracias.html?status=aprobado&carrito_id=${carritoId}`,
      failure: `${tiendaUrl}checkout.html?error=1`,
      pending: `${tiendaUrl}gracias.html?status=pendiente&carrito_id=${carritoId}`,
    },
    auto_return: 'approved',
    external_reference: carritoId || crypto.randomBytes(8).toString('hex'),
    metadata: { carrito_id: carritoId, user_id: perfil.id },
    notification_url: `${APP_URL}/api/tienda/${rawPublicId}/webhook-mp`,
  };
  if (descuentoAplicado > 0) {
    prefBody.items.push({
      id: 'descuento', title: `Descuento ${codigoDescuento}`,
      quantity: 1, unit_price: -descuentoAplicado, currency_id: 'ARS',
    });
  }

  let initPoint;
  try {
    const mpRes = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(prefBody),
      signal: AbortSignal.timeout(10000),
    });
    const mpData = await mpRes.json();
    if (!mpRes.ok || !mpData.init_point)
      return json(res, 502, { error: 'Error al crear el pago. Intentá de nuevo o contactá por WhatsApp.' });
    initPoint = mpData.init_point;
  } catch { return json(res, 502, { error: 'No se pudo conectar con MercadoPago.' }); }

  // Incrementar usos del código
  if (promoIdUsado) {
    adminSupabase.from('promociones')
      .update({ usos_actuales: adminSupabase.rpc ? undefined : undefined })
      .eq('id', promoIdUsado)
      .then(() => {})
      .catch(() => {});
    // incremento manual con select primero
    adminSupabase.from('promociones').select('usos_actuales').eq('id', promoIdUsado).single()
      .then(({ data: p }) => {
        if (p) adminSupabase.from('promociones')
          .update({ usos_actuales: (p.usos_actuales || 0) + 1 })
          .eq('id', promoIdUsado).then(() => {}).catch(() => {});
      }).catch(() => {});
  }

  // Persistir / actualizar carrito
  if (carritoId) {
    adminSupabase.from('carritos').upsert({
      id:              carritoId,
      user_id:         perfil.id,
      items,
      email_comprador: emailComprador,
      cliente,
      estado:          'activo',
      paso_actual:     'checkout',
      updated_at:      new Date().toISOString(),
    }).then(() => {}).catch(() => {});
  }

  // Registrar analytics
  adminSupabase.from('analytics_eventos').insert({
    user_id:     perfil.id, tipo: 'inicio_checkout',
    carrito_id:  carritoId || null, monto_total: total,
  }).then(() => {}).catch(() => {});

  return json(res, 200, { init_point: initPoint });
  } catch (err) {
    console.error('[checkout]', err.message, err.stack);
    return json(res, 500, { error: 'Error interno. Intentá de nuevo o contactá por WhatsApp.' });
  }
}

// ── POST /api/tienda/[publicId]/analytics ─────────────────────────────────────
async function handleTiendaAnalytics(req, res, rawPublicId) {
  tiendaCorsHeaders(res, req);
  if (req.method === 'OPTIONS') return res.status(204).end();
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  const ipHash = 'an_' + crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16);
  if (!await rateLimit(ipHash, 100, 3600000)) return res.status(429).end();
  const perfil = await resolveTiendaUser(rawPublicId);
  if (!perfil) return res.status(204).end();
  const body = await parseBody(req);
  const tiposValidos = ['vista_producto','agregar_carrito','inicio_checkout','compra_completada','abandono_carrito','aplicar_codigo'];
  const tipo = (body.tipo || '').trim();
  if (!tiposValidos.includes(tipo)) return res.status(204).end();
  const evento = {
    user_id:         perfil.id,
    tipo,
    producto_id:     String(body.producto_id || '').slice(0, 100) || null,
    producto_nombre: String(body.producto_nombre || '').slice(0, 200) || null,
    carrito_id:      String(body.carrito_id || '').slice(0, 100) || null,
    monto_total:     body.monto_total ? parseFloat(body.monto_total) : null,
    paso_abandono:   String(body.paso_abandono || '').slice(0, 50) || null,
  };
  adminSupabase.from('analytics_eventos').insert(evento).then(() => {}).catch(() => {});
  return res.status(204).end();
}

// ── POST/GET /api/tienda/[publicId]/webhook-mp ────────────────────────────────
async function handleTiendaWebhookMP(req, res, rawPublicId) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method === 'GET') return json(res, 200, { ok: true });
  if (req.method !== 'POST') return json(res, 405, { error: 'Método no permitido' });

  const perfil = await resolveTiendaUser(rawPublicId);
  if (!perfil) return json(res, 404, { error: 'Tienda no encontrada' });

  const body = await parseBody(req);
  if (body.type !== 'payment' || !body.data?.id) return json(res, 200, { ok: true });
  const paymentId = body.data.id;

  // 2A. Access token con fallback
  const { data: mpConn } = await adminSupabase
    .from('mp_conexiones').select('access_token_encrypted').eq('user_id', perfil.id).single();
  let accessToken;
  if (mpConn?.access_token_encrypted) {
    try { accessToken = decrypt(mpConn.access_token_encrypted); }
    catch { accessToken = process.env.MP_ACCESS_TOKEN; }
  } else {
    accessToken = process.env.MP_ACCESS_TOKEN;
  }
  if (!accessToken) return json(res, 200, { ok: true });

  // 2B. Idempotencia
  const { data: yaExiste } = await adminSupabase
    .from('ventas').select('id').eq('user_id', perfil.id).eq('mp_payment_id', String(paymentId)).maybeSingle();
  if (yaExiste) return json(res, 200, { ok: true });

  // 2C. Obtener pago desde MP
  let pago;
  try {
    const payRes = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(8000),
    });
    if (!payRes.ok) return json(res, 200, { ok: true });
    pago = await payRes.json();
  } catch { return json(res, 200, { ok: true }); }
  if (pago.status !== 'approved') return json(res, 200, { ok: true });

  try {
    // 2D. Obtener carrito
    const carritoId = pago.external_reference || pago.metadata?.carrito_id;
    let carritoItems = [];
    let clienteData = {};
    if (carritoId) {
      const { data: carrito } = await adminSupabase
        .from('carritos').select('items, cliente, email_comprador')
        .eq('id', carritoId).eq('user_id', perfil.id).maybeSingle();
      if (carrito) {
        carritoItems = carrito.items || [];
        clienteData  = carrito.cliente || {};
        if (!clienteData.email) clienteData.email = carrito.email_comprador;
      }
    }
    if (!clienteData.nombre) {
      clienteData.nombre   = pago.payer?.first_name || '';
      clienteData.apellido = pago.payer?.last_name  || '';
      clienteData.email    = pago.payer?.email      || '';
    }

    // 2E. Crear o encontrar cliente
    let clienteId = null;
    const nombreCompleto = `${clienteData.nombre || ''} ${clienteData.apellido || ''}`.trim()
      || clienteData.email || 'Cliente Online';

    if (clienteData.dni) {
      const { data: existente } = await adminSupabase
        .from('clientes').select('id').eq('user_id', perfil.id).eq('dni', clienteData.dni).maybeSingle();
      if (existente) clienteId = existente.id;
    }
    if (!clienteId && clienteData.email) {
      const { data: porEmail } = await adminSupabase
        .from('clientes').select('id').eq('user_id', perfil.id).ilike('notas', `%${clienteData.email}%`).maybeSingle();
      if (porEmail) clienteId = porEmail.id;
    }
    if (!clienteId) {
      const notas = [
        clienteData.email,
        clienteData.dni     ? `DNI: ${clienteData.dni}` : null,
        clienteData.direccion, clienteData.ciudad, clienteData.provincia,
      ].filter(Boolean).join(' | ');
      const { data: nuevo } = await adminSupabase.from('clientes').insert({
        user_id:  perfil.id,
        nombre:   nombreCompleto,
        telefono: clienteData.telefono || '',
        notas,
        dni:      clienteData.dni || null,
      }).select('id').single();
      if (nuevo) clienteId = nuevo.id;
    }

    // 2F. Crear ventas y descontar stock
    const fecha = new Date().toISOString().slice(0, 10);
    for (const item of carritoItems) {
      if (!item.varianteId) continue;
      const { data: variante } = await adminSupabase
        .from('producto_variantes').select('producto_id, nombre, tipo, cantidad').eq('id', item.varianteId).maybeSingle();
      if (!variante) continue;
      const { data: producto } = await adminSupabase
        .from('productos').select('nombre, precio, costo').eq('id', variante.producto_id).eq('user_id', perfil.id).maybeSingle();
      if (!producto) continue;
      const cantidad = parseInt(item.cantidad) || 1;
      const pv = parseFloat(producto.precio) || 0;
      const co = parseFloat(producto.costo)  || 0;

      await adminSupabase.from('ventas').insert({
        user_id:         perfil.id,
        cliente_id:      clienteId,
        prenda:          `${producto.nombre} — ${variante.nombre}`,
        precio_venta:    pv * cantidad,
        precio_unitario: pv,
        costo:           co * cantidad,
        costo_unitario:  co,
        cantidad,
        fecha_compra:    fecha,
        pagado:          pv * cantidad,
        adeuda:          0,
        notas:           `Venta online MP#${paymentId}`,
        mp_payment_id:   String(paymentId),
        origen:          'tienda_online',
        medio_pago:      'mercadopago',
      });

      const nuevaCantidad = Math.max(0, (variante.cantidad || 0) - cantidad);
      await adminSupabase.from('producto_variantes').update({ cantidad: nuevaCantidad }).eq('id', item.varianteId);
    }

    // 2G. Marcar carrito completado
    if (carritoId) {
      await adminSupabase.from('carritos')
        .update({ estado: 'completado', updated_at: new Date().toISOString() })
        .eq('id', carritoId).eq('user_id', perfil.id);
    }

    // 2H. Crear notificación
    await adminSupabase.from('notificaciones').insert({
      user_id:  perfil.id,
      tipo:     'venta_online',
      titulo:   'Nueva venta online',
      mensaje:  `${nombreCompleto} — $${(pago.transaction_amount || 0).toLocaleString('es-AR')}`,
      leida:    false,
      metadata: {
        mp_payment_id: String(paymentId),
        cliente:       nombreCompleto,
        monto:         pago.transaction_amount || 0,
        carrito_id:    carritoId,
      },
    });

    // Analytics
    adminSupabase.from('analytics_eventos').insert({
      user_id:    perfil.id,
      tipo:       'compra_completada',
      carrito_id: carritoId || null,
      monto_total: pago.transaction_amount || null,
    }).then(() => {}).catch(() => {});

  } catch (err) {
    console.error('[webhook-mp]', err.message);
  }

  return json(res, 200, { ok: true });
}

// ── GET /api/tienda/[publicId]/analytics-resumen ──────────────────────────────
async function handleTiendaAnalyticsResumen(req, res, user, rawPublicId) {
  const perfil = await resolveTiendaUser(rawPublicId);
  if (!perfil || perfil.id !== user.userId) return json(res, 403, { error: 'Sin permiso' });
  const periodo = new URL(req.url, 'http://l').searchParams.get('periodo') || 'semana';
  const diasMap = { hoy: 1, semana: 7, mes: 30 };
  const dias = diasMap[periodo] || 7;
  const desde = new Date(Date.now() - dias * 86400000).toISOString();

  const { data: eventos } = await adminSupabase
    .from('analytics_eventos').select('tipo, producto_id, producto_nombre, carrito_id, monto_total, paso_abandono')
    .eq('user_id', user.userId).gte('created_at', desde);
  const ev = eventos || [];

  // Funnel
  const funnel = {
    vistas:    ev.filter(e => e.tipo === 'vista_producto').length,
    carritos:  ev.filter(e => e.tipo === 'agregar_carrito').length,
    checkouts: ev.filter(e => e.tipo === 'inicio_checkout').length,
    compras:   ev.filter(e => e.tipo === 'compra_completada').length,
  };

  // Por producto
  const prodMap = {};
  ev.forEach(e => {
    if (!e.producto_id) return;
    if (!prodMap[e.producto_id]) prodMap[e.producto_id] = { nombre: e.producto_nombre || '(producto eliminado)', vistas: 0, carritos: 0 };
    if (e.tipo === 'vista_producto') prodMap[e.producto_id].vistas++;
    if (e.tipo === 'agregar_carrito') prodMap[e.producto_id].carritos++;
  });
  // Resolver nombres reales desde la tabla productos
  const productoIds = Object.keys(prodMap);
  if (productoIds.length > 0) {
    const { data: prods } = await adminSupabase
      .from('productos').select('id, nombre').in('id', productoIds).eq('user_id', user.userId);
    (prods || []).forEach(p => { if (prodMap[p.id]) prodMap[p.id].nombre = p.nombre; });
  }
  const porProducto = Object.values(prodMap).map(p => ({
    ...p, tasa: p.vistas ? Math.round(p.carritos / p.vistas * 100) : 0,
  })).sort((a, b) => b.vistas - a.vistas).slice(0, 20);

  // Abandonos
  const abandonos = { carrito: 0, checkout: 0, pago: 0 };
  ev.filter(e => e.tipo === 'abandono_carrito').forEach(e => {
    const paso = e.paso_abandono || 'carrito';
    if (abandonos[paso] !== undefined) abandonos[paso]++;
  });

  // Ventas recientes online + ingresos
  const { data: ventasOnline } = await adminSupabase
    .from('ventas').select('id, prenda, precio_venta, cantidad, fecha_compra, created_at, cliente_id, clientes(nombre)')
    .eq('user_id', user.userId).eq('origen', 'tienda_online')
    .gte('created_at', desde)
    .order('created_at', { ascending: false }).limit(10);
  const vr = ventasOnline || [];
  const ingresos_total = vr.reduce((acc, v) => acc + (parseFloat(v.precio_venta) || 0), 0);

  return json(res, 200, {
    periodo, funnel, porProducto, abandonos,
    ventas_recientes: vr.map(v => ({
      id:          v.id,
      prenda:      v.prenda,
      monto:       v.precio_venta,
      fecha:       v.fecha_compra,
      cliente:     v.clientes?.nombre || null,
      cliente_id:  v.cliente_id,
    })),
    ingresos_total,
  });
}

// ── GET/PUT /api/tienda-config ────────────────────────────────────────────────
async function handleGetMiTiendaConfig(req, res, user) {
  let { data: cfg } = await adminSupabase
    .from('tienda_config').select('*').eq('user_id', user.userId).maybeSingle();
  if (!cfg) {
    const { data: nuevo } = await adminSupabase
      .from('tienda_config').insert({ user_id: user.userId }).select('*').single();
    cfg = nuevo;
  }
  if (!cfg) return json(res, 500, { error: 'No se pudo obtener la configuración' });
  return json(res, 200, { config: cfg });
}

const ALLOWED_CONFIG_FIELDS = [
  'nombre_tienda','descripcion','logo_url','color_primario',
  'banner_imagen_url','banner_titulo','banner_subtitulo',
  'banner_boton_texto','banner_boton_url','secciones',
  'franja_texto','franja_activa','instagram_url',
  'whatsapp_numero','envio_gratis_desde','marquee_items',
];

function sanitizeText(v, maxLen = 500) {
  if (typeof v !== 'string') return '';
  return v.replace(/<[^>]*>/g, '').trim().slice(0, maxLen);
}

function isValidUrl(v) {
  if (!v) return true;
  return v.startsWith('https://') || v.startsWith('/');
}

async function handlePutMiTiendaConfig(req, res, user) {
  const body = await parseBody(req);
  const updates = {};

  for (const field of ALLOWED_CONFIG_FIELDS) {
    if (!(field in body)) continue;
    const v = body[field];

    if (field === 'color_primario') {
      if (!/^#[0-9A-Fa-f]{6}$/.test(v)) return json(res, 400, { error: 'Color inválido' });
      updates[field] = v;
    } else if (['logo_url','banner_imagen_url'].includes(field)) {
      if (v && !isValidUrl(v)) return json(res, 400, { error: `URL inválida: ${field}` });
      updates[field] = v || null;
    } else if (['banner_boton_url','instagram_url'].includes(field)) {
      if (v && !isValidUrl(v)) return json(res, 400, { error: `URL inválida: ${field}` });
      updates[field] = sanitizeText(v, 300);
    } else if (['secciones','marquee_items'].includes(field)) {
      if (!Array.isArray(v)) return json(res, 400, { error: `${field} debe ser un array` });
      updates[field] = v.slice(0, 20);
    } else if (field === 'franja_activa') {
      updates[field] = !!v;
    } else if (field === 'envio_gratis_desde') {
      updates[field] = v === null ? null : Math.max(0, parseFloat(v) || 0);
    } else {
      updates[field] = sanitizeText(v, field === 'descripcion' ? 1000 : 200);
    }
  }

  updates.updated_at = new Date().toISOString();
  const { error } = await adminSupabase
    .from('tienda_config').upsert({ user_id: user.userId, ...updates }, { onConflict: 'user_id' });
  if (error) return json(res, 500, { error: 'Error al guardar: ' + error.message });
  return json(res, 200, { ok: true });
}

// ── PROMOCIONES CRUD ──────────────────────────────────────────────────────────
async function handleGetPromociones(req, res, user) {
  const { data, error } = await adminSupabase
    .from('promociones').select('*').eq('user_id', user.userId).order('created_at', { ascending: false });
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { promociones: data || [] });
}

async function handlePostPromocion(req, res, user) {
  const body = await parseBody(req);
  const nombre = sanitizeText(body.nombre || '', 100);
  if (!nombre) return json(res, 400, { error: 'Nombre requerido' });

  const tipo = ['codigo','descuento_automatico','envio_gratis'].includes(body.tipo)
    ? body.tipo : 'codigo';
  const codigo = tipo === 'codigo'
    ? (sanitizeText(body.codigo || '', 50).toUpperCase() || null)
    : null;
  const descuentoTipo = ['porcentaje','fijo'].includes(body.descuento_tipo)
    ? body.descuento_tipo : 'porcentaje';
  const descuentoValor = Math.max(0, parseFloat(body.descuento_valor) || 0);
  if (descuentoTipo === 'porcentaje' && descuentoValor > 100)
    return json(res, 400, { error: 'El porcentaje no puede superar 100' });

  const promo = {
    user_id:         user.userId,
    nombre,
    tipo,
    codigo,
    descuento_tipo:  descuentoTipo,
    descuento_valor: descuentoValor,
    monto_minimo:    body.monto_minimo ? parseFloat(body.monto_minimo) : null,
    aplica_a:        ['todo','categoria','producto'].includes(body.aplica_a) ? body.aplica_a : 'todo',
    aplica_a_valor:  sanitizeText(body.aplica_a_valor || '', 100) || null,
    usos_max:        body.usos_max ? parseInt(body.usos_max) : null,
    activa:          body.activa !== false,
    fecha_inicio:    body.fecha_inicio || null,
    fecha_fin:       body.fecha_fin || null,
  };
  const { data, error } = await adminSupabase.from('promociones').insert(promo).select('*').single();
  if (error) {
    if (error.code === '23505') return json(res, 400, { error: 'Ya existe un código activo con ese nombre' });
    return json(res, 500, { error: error.message });
  }
  return json(res, 201, { promocion: data });
}

async function handlePutPromocion(req, res, user, id) {
  const body = await parseBody(req);
  const allowed = ['nombre','descuento_tipo','descuento_valor','codigo','usos_maximos',
    'monto_minimo','aplica_a','aplica_a_valor','fecha_inicio','fecha_fin','activa'];
  const updates = {};
  for (const key of allowed) {
    if (body[key] !== undefined) updates[key] = body[key];
  }
  const { error } = await adminSupabase.from('promociones')
    .update(updates).eq('id', id).eq('user_id', user.userId);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

async function handleDeletePromocion(req, res, user, id) {
  const { error } = await adminSupabase.from('promociones')
    .delete().eq('id', id).eq('user_id', user.userId);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}

// ── PATCH /api/productos/[id] — destacado y orden ─────────────────────────────
async function handlePatchProducto(req, res, user, id) {
  const body = await parseBody(req);
  const updates = {};
  if (body.destacado !== undefined) updates.destacado = !!body.destacado;
  if (body.orden !== undefined) updates.orden = parseInt(body.orden) || 0;
  if (!Object.keys(updates).length) return json(res, 400, { error: 'Sin campos para actualizar' });
  const { error } = await adminSupabase.from('productos')
    .update(updates).eq('id', id).eq('user_id', user.userId);
  if (error) return json(res, 500, { error: error.message });
  return json(res, 200, { ok: true });
}
