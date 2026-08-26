'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const KEY_FILE = path.join(DATA_DIR, '.encryption-key');
const SESSION_SECRET_FILE = path.join(DATA_DIR, '.session-secret');

const PORT = process.env.PORT || 3000;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// KEY_FILE / SESSION_SECRET_FILE below are a local-dev convenience only — most
// cloud hosts wipe the filesystem on every redeploy, which would silently
// rotate these and (for the encryption key) make already-stored rows
// undecryptable. Always set SUBMISSIONS_ENCRYPTION_KEY and SESSION_SECRET as
// real environment variables once this is deployed anywhere.
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- base64url helpers (avoid relying on Buffer's 'base64url' encoding for wider Node compat) ----------
function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromBase64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

// ---------- Encryption key (AES-256-GCM) ----------
function loadOrCreateEncryptionKey() {
  const envKey = process.env.SUBMISSIONS_ENCRYPTION_KEY;
  if (envKey) {
    const buf = Buffer.from(envKey, 'hex');
    if (buf.length !== 32) {
      throw new Error('SUBMISSIONS_ENCRYPTION_KEY must be a 64-character hex string (32 bytes).');
    }
    return buf;
  }
  if (fs.existsSync(KEY_FILE)) {
    return Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'hex');
  }
  const key = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE, key.toString('hex'), { mode: 0o600 });
  console.warn('[sakhyakirana] Generated a new encryption key at data/.encryption-key (gitignored).');
  console.warn('[sakhyakirana] Set SUBMISSIONS_ENCRYPTION_KEY in your environment to keep it stable across redeploys, and back it up securely — losing it makes existing submissions unrecoverable.');
  return key;
}

const ENCRYPTION_KEY = loadOrCreateEncryptionKey();

function encrypt(plainObj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const plaintext = Buffer.from(JSON.stringify(plainObj), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
  };
}

function decrypt(record) {
  const iv = Buffer.from(record.iv, 'hex');
  const authTag = Buffer.from(record.authTag, 'hex');
  const ciphertext = Buffer.from(record.ciphertext, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

// ---------- Admin auth ----------
function loadOrCreateSessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  if (fs.existsSync(SESSION_SECRET_FILE)) return fs.readFileSync(SESSION_SECRET_FILE, 'utf8').trim();
  const secret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SESSION_SECRET_FILE, secret, { mode: 0o600 });
  return secret;
}
const SESSION_SECRET = loadOrCreateSessionSecret();

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, salt, 64);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

let ADMIN_PASSWORD_HASH;
if (process.env.ADMIN_PASSWORD) {
  ADMIN_PASSWORD_HASH = hashPassword(process.env.ADMIN_PASSWORD);
} else {
  const generated = base64url(crypto.randomBytes(9));
  ADMIN_PASSWORD_HASH = hashPassword(generated);
  console.warn('=================================================');
  console.warn('[sakhyakirana] No ADMIN_PASSWORD set in the environment.');
  console.warn(`[sakhyakirana] Generated admin password for THIS run only: ${generated}`);
  console.warn('[sakhyakirana] Set ADMIN_PASSWORD in your environment for a password that survives restarts.');
  console.warn('=================================================');
}

function createSessionToken() {
  const payload = JSON.stringify({ exp: Date.now() + SESSION_TTL_MS });
  const payloadB64 = base64url(Buffer.from(payload, 'utf8'));
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payloadB64).digest();
  return `${payloadB64}.${base64url(sig)}`;
}

function verifySessionToken(token) {
  if (!token || !token.includes('.')) return false;
  const [payloadB64, sigB64] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(payloadB64).digest();
  let actualSig;
  try {
    actualSig = fromBase64url(sigB64);
  } catch {
    return false;
  }
  if (actualSig.length !== expectedSig.length || !crypto.timingSafeEqual(actualSig, expectedSig)) return false;
  try {
    const payload = JSON.parse(fromBase64url(payloadB64).toString('utf8'));
    return typeof payload.exp === 'number' && payload.exp > Date.now();
  } catch {
    return false;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie;
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    cookies[key] = decodeURIComponent(value);
  });
  return cookies;
}

function isAuthedAdmin(req) {
  const cookies = parseCookies(req);
  return verifySessionToken(cookies.admin_session);
}

function sessionCookie(token, maxAgeSeconds) {
  const parts = [
    `admin_session=${token}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (IS_PRODUCTION) parts.push('Secure');
  return parts.join('; ');
}

// ---------- Rate limiting (in-memory, best-effort for a single-process prototype) ----------
const submissionHits = new Map();
const loginHits = new Map();

function rateLimited(map, key, max, windowMs) {
  const now = Date.now();
  const hits = (map.get(key) || []).filter((t) => now - t < windowMs);
  hits.push(now);
  map.set(key, hits);
  return hits.length > max;
}

function clientIp(req) {
  return req.socket.remoteAddress || 'unknown';
}

// ---------- Body parsing ----------
function readJsonBody(req, maxBytes = 100 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

const VALID_ROLES = ['shopkeeper', 'customer', 'other'];
const VALID_CITIES = ['Delhi', 'Gurugram', 'Bahadurgarh', 'Dehradun', 'Other'];

function sanitizeString(value, maxLen) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

function validateSubmission(body) {
  const problem = sanitizeString(body.problem, 3000);
  if (!problem) return { error: 'Please describe the problem you are facing.' };

  const role = VALID_ROLES.includes(body.role) ? body.role : 'other';
  const city = VALID_CITIES.includes(body.city) ? body.city : 'Other';
  const cityOther = city === 'Other' ? sanitizeString(body.cityOther, 100) : '';
  const name = sanitizeString(body.name, 120);
  const contact = sanitizeString(body.contact, 150);
  const interested = Boolean(body.interested);

  return { value: { name, contact, role, city, cityOther, problem, interested } };
}

// ---------- HTTP helpers ----------
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function sendFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': contentType,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (req.method === 'GET' && url.pathname === '/') {
      return sendFile(res, path.join(ROOT, 'index.html'), 'text/html; charset=utf-8');
    }

    if (req.method === 'GET' && url.pathname === '/admin') {
      return sendFile(res, path.join(ROOT, 'admin.html'), 'text/html; charset=utf-8');
    }

    if (req.method === 'POST' && url.pathname === '/api/submissions') {
      if (rateLimited(submissionHits, clientIp(req), 10, 60 * 60 * 1000)) {
        return sendJson(res, 429, { error: 'Too many submissions from this connection. Please try again later.' });
      }
      const body = await readJsonBody(req);
      const { error, value } = validateSubmission(body);
      if (error) return sendJson(res, 400, { error });

      const record = {
        id: crypto.randomUUID(),
        createdAt: new Date().toISOString(),
        ...encrypt(value),
      };
      await db.insertSubmission(record);
      return sendJson(res, 201, { ok: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/login') {
      if (rateLimited(loginHits, clientIp(req), 8, 15 * 60 * 1000)) {
        return sendJson(res, 429, { error: 'Too many login attempts. Try again later.' });
      }
      const body = await readJsonBody(req);
      const password = typeof body.password === 'string' ? body.password : '';
      const ok = Boolean(password) && verifyPassword(password, ADMIN_PASSWORD_HASH);
      if (!ok) {
        await new Promise((r) => setTimeout(r, 400));
        return sendJson(res, 401, { error: 'Incorrect password.' });
      }
      const token = createSessionToken();
      res.setHeader('Set-Cookie', sessionCookie(token, SESSION_TTL_MS / 1000));
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/logout') {
      res.setHeader('Set-Cookie', sessionCookie('', 0));
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'GET' && url.pathname === '/api/admin/session') {
      return sendJson(res, 200, { authenticated: isAuthedAdmin(req) });
    }

    if (req.method === 'GET' && url.pathname === '/api/submissions') {
      if (!isAuthedAdmin(req)) return sendJson(res, 401, { error: 'Not authenticated.' });
      const list = await db.listSubmissions();
      const decrypted = list.map((r) => {
        try {
          return { id: r.id, createdAt: r.createdAt, ...decrypt(r) };
        } catch {
          return { id: r.id, createdAt: r.createdAt, error: 'Could not decrypt this record.' };
        }
      });
      return sendJson(res, 200, { submissions: decrypted });
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  } catch (err) {
    console.error(err);
    sendJson(res, 500, { error: 'Something went wrong.' });
  }
});

db.ensureSchema()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`SakhyaKirana server running at http://localhost:${PORT}`);
      console.log(`Admin panel:                   http://localhost:${PORT}/admin`);
    });
  })
  .catch((err) => {
    console.error('[sakhyakirana] Could not connect to Postgres / create the submissions table.');
    console.error(err);
    process.exit(1);
  });
