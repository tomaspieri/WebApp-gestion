'use strict';
/**
 * api/cron/sync-mp.js
 * Cron: cada 15 minutos.
 * Sincroniza pagos de MercadoPago de todos los usuarios con MP conectado.
 * Protegido por CRON_SECRET.
 */

const { createClient } = require('@supabase/supabase-js');
const { doMpSync }     = require('../[...route]');

const adminSupabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { persistSession: false } }
);

module.exports = async function handler(req, res) {
  const secret = process.env.CRON_SECRET;
  const auth   = req.headers['authorization'] || '';

  if (secret && auth !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Obtener todos los usuarios con MP conectado
  const { data: conexiones, error } = await adminSupabase
    .from('mp_conexiones')
    .select('user_id')
    .eq('conectado', true);

  if (error) {
    console.error('[cron/sync-mp] Error consultando conexiones:', error.message);
    return res.status(500).json({ error: error.message });
  }

  if (!conexiones?.length) {
    return res.status(200).json({ ok: true, message: 'Sin usuarios con MP conectado' });
  }

  const results = [];
  for (const { user_id } of conexiones) {
    try {
      const r = await doMpSync(user_id);
      results.push({ user_id, ...r });
      console.log(`[cron/sync-mp] user=${user_id}`, r);
    } catch (err) {
      console.error(`[cron/sync-mp] ERROR user=${user_id}:`, err.message);
      results.push({ user_id, error: err.message });
    }
  }

  return res.status(200).json({ ok: true, results });
};
