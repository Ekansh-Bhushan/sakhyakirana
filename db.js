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
});

// Idle clients in the pool can throw on a connection blip; without this handler
// that crashes the whole process instead of just recycling the client.
pool.on('error', (err) => {
  console.error('[db] Unexpected error on idle Postgres client', err);
});

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS submissions (
      id UUID PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      ciphertext TEXT NOT NULL
    );
  `);
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

module.exports = { pool, ensureSchema, insertSubmission, listSubmissions };
