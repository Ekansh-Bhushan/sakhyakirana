'use strict';

const { Pool } = require('pg');

const connectionString = (process.env.DATABASE_URL || '').trim();
if (!connectionString) {
  throw new Error('DATABASE_URL is not set. Copy .env.example to .env and fill it in, or set it in your host\'s environment variables.');
}

// Managed Postgres providers (Neon, Supabase, Railway, Render, RDS, ...) require
// TLS but commonly present a cert chain `pg` won't validate by default — disabling
// strict verification is the standard escape hatch for those hosted setups.
// Set PGSSL=disable only for a local/self-hosted Postgres with no TLS at all.
const pool = new Pool({
  connectionString,
  ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false },
  // Serverless Postgres (Neon, etc.) on a free tier can take a few seconds to
  // wake from idle-suspend — the default ~1s connect timeout in `pg` is too
  // tight for that and turns a cold start into a hard failure.
  connectionTimeoutMillis: 10_000,
  idleTimeoutMillis: 30_000,
  max: 5,
});

// Idle clients in the pool can throw on a connection blip; without this handler
// that crashes the whole process instead of just recycling the client.
pool.on('error', (err) => {
  console.error('[db] Unexpected error on idle Postgres client', err);
});

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Retries with backoff so a slow cold-start Postgres (or a brief network blip)
// doesn't take down startup — see the retry loop this feeds in server.js.
async function ensureSchema(attempts = 5) {
  let lastErr;
  for (let i = 1; i <= attempts; i++) {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS submissions (
          id UUID PRIMARY KEY,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          iv TEXT NOT NULL,
          auth_tag TEXT NOT NULL,
          ciphertext TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS page_views (
          id BIGSERIAL PRIMARY KEY,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          visitor_id UUID NOT NULL,
          path TEXT NOT NULL,
          is_new_visitor BOOLEAN NOT NULL DEFAULT false,
          referrer_host TEXT,
          device TEXT
        );

        CREATE INDEX IF NOT EXISTS page_views_created_at_idx ON page_views (created_at DESC);
        CREATE INDEX IF NOT EXISTS page_views_visitor_id_idx ON page_views (visitor_id);
      `);
      return;
    } catch (err) {
      lastErr = err;
      console.warn(`[db] Schema check failed (attempt ${i}/${attempts}): ${err.message}`);
      if (i < attempts) await wait(1000 * i);
    }
  }
  throw lastErr;
}

async function insertSubmission(record) {
  await pool.query(
    'INSERT INTO submissions (id, created_at, iv, auth_tag, ciphertext) VALUES ($1, $2, $3, $4, $5)',
    [record.id, record.createdAt, record.iv, record.authTag, record.ciphertext]
  );
}

async function listSubmissions() {
  const { rows } = await pool.query(
    'SELECT id, created_at, iv, auth_tag, ciphertext FROM submissions ORDER BY created_at DESC'
  );
  return rows.map((r) => ({
    id: r.id,
    createdAt: r.created_at.toISOString(),
    iv: r.iv,
    authTag: r.auth_tag,
    ciphertext: r.ciphertext,
  }));
}

async function recordPageView(view) {
  await pool.query(
    `INSERT INTO page_views (visitor_id, path, is_new_visitor, referrer_host, device)
     VALUES ($1, $2, $3, $4, $5)`,
    [view.visitorId, view.path, view.isNewVisitor, view.referrerHost || null, view.device || null]
  );
}

// All day-boundary maths happens in the caller's timezone rather than UTC, so
// "today" in the admin panel means today where the site's audience actually is.
async function getAnalytics(timeZone = 'UTC', days = 30) {
  const [totals, series, sources, devices] = await Promise.all([
    pool.query(
      `SELECT
         COUNT(*)::int AS total_views,
         COUNT(DISTINCT visitor_id)::int AS total_visitors,
         COUNT(*) FILTER (
           WHERE (created_at AT TIME ZONE $1::text)::date = (now() AT TIME ZONE $1::text)::date
         )::int AS views_today,
         COUNT(DISTINCT visitor_id) FILTER (
           WHERE (created_at AT TIME ZONE $1::text)::date = (now() AT TIME ZONE $1::text)::date
         )::int AS visitors_today,
         COUNT(*) FILTER (WHERE created_at >= now() - interval '7 days')::int AS views_7d,
         COUNT(DISTINCT visitor_id) FILTER (WHERE created_at >= now() - interval '7 days')::int AS visitors_7d,
         COUNT(DISTINCT visitor_id) FILTER (WHERE created_at >= now() - interval '5 minutes')::int AS visitors_active,
         COUNT(DISTINCT visitor_id) FILTER (WHERE is_new_visitor)::int AS first_time_visitors,
         MAX(created_at) AS last_view_at
       FROM page_views`,
      [timeZone]
    ),
    pool.query(
      `SELECT
         to_char(d::date, 'YYYY-MM-DD') AS day,
         COALESCE(v.views, 0)::int AS views,
         COALESCE(v.visitors, 0)::int AS visitors
       FROM generate_series(
              (now() AT TIME ZONE $1::text)::date - make_interval(days => $2::int - 1),
              (now() AT TIME ZONE $1::text)::date,
              interval '1 day'
            ) AS d
       LEFT JOIN (
         SELECT
           (created_at AT TIME ZONE $1::text)::date AS day,
           COUNT(*) AS views,
           COUNT(DISTINCT visitor_id) AS visitors
         FROM page_views
         GROUP BY 1
       ) AS v ON v.day = d::date
       ORDER BY d`,
      [timeZone, days]
    ),
    pool.query(
      `SELECT
         COALESCE(NULLIF(referrer_host, ''), 'Direct / typed in') AS source,
         COUNT(*)::int AS views,
         COUNT(DISTINCT visitor_id)::int AS visitors
       FROM page_views
       GROUP BY 1
       ORDER BY visitors DESC, views DESC
       LIMIT 10`
    ),
    pool.query(
      `SELECT
         COALESCE(NULLIF(device, ''), 'unknown') AS device,
         COUNT(DISTINCT visitor_id)::int AS visitors
       FROM page_views
       GROUP BY 1
       ORDER BY visitors DESC`
    ),
  ]);

  const t = totals.rows[0] || {};
  return {
    totals: {
      totalViews: t.total_views || 0,
      totalVisitors: t.total_visitors || 0,
      viewsToday: t.views_today || 0,
      visitorsToday: t.visitors_today || 0,
      views7d: t.views_7d || 0,
      visitors7d: t.visitors_7d || 0,
      visitorsActive: t.visitors_active || 0,
      firstTimeVisitors: t.first_time_visitors || 0,
      lastViewAt: t.last_view_at ? t.last_view_at.toISOString() : null,
    },
    daily: series.rows,
    sources: sources.rows,
    devices: devices.rows,
  };
}

module.exports = {
  pool,
  ensureSchema,
  insertSubmission,
  listSubmissions,
  recordPageView,
  getAnalytics,
};
