# Deploy — Chana Gestión en Vercel + Supabase

## Arquitectura

```
chana-gestion.vercel.app  (Vercel — serverless)
       │
       ├── / ─────────────── index.html (app de gestión)
       └── /api/* ─────────── api/[...route].js (handler Node.js)
                               ├── api/cron/check-cuotas.js
                               └── api/cron/sync-mp.js
                                         │
                               Supabase (PostgreSQL + Auth)
```

---

## Paso 1 — Schema en Supabase

1. Ir a [supabase.com](https://supabase.com) → proyecto **GestionVentas**
2. SQL Editor → New query
3. Pegar el contenido completo de `supabase-schema.sql`
4. Ejecutar (▶ Run)
5. Verificar que las tablas aparezcan en Table Editor

> Si ya corriste una versión anterior del schema, el script empieza con `DROP TABLE IF EXISTS ... CASCADE` — es seguro volver a ejecutar.

---

## Paso 2 — Variables de entorno en Vercel

En Vercel Dashboard → tu proyecto → Settings → Environment Variables, agregar:

| Variable | Valor | Notas |
|---|---|---|
| `SUPABASE_URL` | `https://glchuwpwzpcukqonumuw.supabase.co` | |
| `SUPABASE_ANON_KEY` | `eyJ...` | Supabase → Settings → API |
| `SUPABASE_SERVICE_KEY` | `eyJ...` | Supabase → Settings → API |
| `ENCRYPTION_KEY` | (64 chars hex) | `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `APP_URL` | `https://chana-gestion.vercel.app` | URL final del proyecto |
| `ALLOWED_ORIGIN` | `https://chanaindumentaria.vercel.app` | |
| `MP_CLIENT_ID` | (de MP) | mercadopago.com.ar → Tus integraciones → Credenciales |
| `MP_CLIENT_SECRET` | (de MP) | ídem |
| `MP_REDIRECT_URI` | `https://chana-gestion.vercel.app/api/mp/callback` | |
| `BREVO_SMTP_PASS` | (de Brevo) | app.brevo.com → SMTP & API → SMTP |
| `CRON_SECRET` | (string aleatorio) | `node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"` |
| `TELEGRAM_TOKEN` | (opcional) | BotFather en Telegram |
| `TELEGRAM_CHAT_ID` | (opcional) | ID del chat a notificar |
| `CORREO_ARG_USER` | (opcional) | micorreo.correoargentino.com.ar |
| `CORREO_ARG_PASS` | (opcional) | ídem |

---

## Paso 3 — Deploy en Vercel

```bash
# En la carpeta gestion-ventas/
npm install
npx vercel --prod
```

O conectar el repositorio GitHub desde Vercel Dashboard → New Project.

> La carpeta raíz del proyecto debe ser `gestion-ventas/` (no la raíz del mono-repo).

---

## Paso 4 — Migrar datos desde ventas.db

Si tenés datos en el SQLite local:

```bash
CHANA_USER_ID=920a408f-79b7-4fb1-945f-c99eb301b257 node migrate-to-supabase.js
```

El script lee `ventas.db` en modo READ-ONLY. Nunca lo modifica.

---

## Paso 5 — Configurar la tienda

1. Abrir `https://chana-gestion.vercel.app`
2. Iniciar sesión con `sanlatorre@hotmail.com`
3. Ir a ⚙️ Configuración
4. Completar:
   - **URL de la tienda**: `https://chanaindumentaria.vercel.app`
   - **Nombre de la tienda**: `Chana Indumentaria`
   - **Vercel Deploy Hook**: obtener en Vercel → proyecto tienda → Settings → Git → Deploy Hooks

---

## Paso 6 — Conectar MercadoPago

1. En ⚙️ Configuración → hacer clic en **Conectar MercadoPago**
2. Autorizar la app en la pantalla de MP
3. Una vez conectado, el sync se ejecuta automáticamente cada 15 minutos

---

## Cron jobs

| Job | Schedule | Qué hace |
|---|---|---|
| `/api/cron/check-cuotas` | Diario 9 AM (AR) | Envía email/Telegram si hay cuotas por vencer en 3 días |
| `/api/cron/sync-mp` | Cada 15 min | Sincroniza pagos aprobados de MP |

Los cron jobs solo funcionan en el plan **Hobby o superior** de Vercel. En el plan Free se pueden disparar manualmente con:

```bash
curl -X POST https://chana-gestion.vercel.app/api/cron/sync-mp \
  -H "Authorization: Bearer TU_CRON_SECRET"
```

---

## Usuarios

| Email | Contraseña | Rol |
|---|---|---|
| `tomaspieri@outlook.com` | (ver .env) | admin — ve todos los datos |
| `sanlatorre@hotmail.com` | (ver .env) | usuario — ve solo sus datos |

> Cambiar contraseñas después del primer login en Supabase Dashboard → Authentication → Users.

---

## Solución de problemas

**"No autorizado"** al abrir la app:
→ Revisar que las variables de entorno estén cargadas en Vercel (redeploy después de agregarlas).

**Deploy hook no funciona**:
→ Verificar que la URL del hook sea correcta en ⚙️ Configuración.
→ El hook corresponde al proyecto de la tienda (`chanaindumentaria`), no al de gestión.

**MP no conecta**:
→ Verificar que `MP_REDIRECT_URI` en Vercel coincida exactamente con la URL registrada en la app de MercadoPago.

**Error de CORS**:
→ Verificar que `ALLOWED_ORIGIN` sea la URL exacta de la tienda (sin barra final).
