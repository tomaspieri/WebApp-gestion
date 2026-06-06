'use strict';
/**
 * api/cron/check-cuotas.js
 * Cron: todos los días a las 9 AM Argentina (12:00 UTC).
 * Verifica cuotas que vencen en los próximos 3 días y envía notificaciones.
 * Protegido por CRON_SECRET (Vercel lo envía en Authorization: Bearer).
 */

const { checkCuotasVencimiento } = require('../[...route]');

module.exports = async function handler(req, res) {
  const secret = process.env.CRON_SECRET;
  const auth   = req.headers['authorization'] || '';

  if (secret && auth !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const result = await checkCuotasVencimiento();
    console.log('[cron/check-cuotas]', result);
    return res.status(200).json({ ok: true, ...result });
  } catch (err) {
    console.error('[cron/check-cuotas] ERROR:', err.message);
    return res.status(500).json({ error: err.message });
  }
};
