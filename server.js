'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');
const geoip = require('geoip-lite');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const KEY_FILE = path.join(DATA_DIR, '.encryption-key');
const SESSION_SECRET_FILE = path.join(DATA_DIR, '.session-secret');

const PORT = process.env.PORT || 3000;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Chrome caps cookie lifetime at 400 days, so anything longer is silently
// clamped — a returning visitor is only recognised as "returning" this long.
const VISITOR_COOKIE_TTL_SECONDS = 400 * 24 * 60 * 60;
// Day boundaries for "today" in the admin panel are computed in this zone.
const ANALYTICS_TIMEZONE = (process.env.ANALYTICS_TIMEZONE || 'Asia/Kolkata').trim();

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
  const envKey = (process.env.SUBMISSIONS_ENCRYPTION_KEY || '').trim();
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
  const envSecret = (process.env.SESSION_SECRET || '').trim();
  if (envSecret) return envSecret;
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
// .trim() guards against the trailing newline/space that copy-pasting into a
// cloud host's env var UI commonly introduces — without it, a value that looks
// identical on screen silently fails to match on login.
const envAdminPassword = (process.env.ADMIN_PASSWORD || '').trim();
if (envAdminPassword) {
  ADMIN_PASSWORD_HASH = hashPassword(envAdminPassword);
  console.log(`[sakhyakirana] Using ADMIN_PASSWORD from environment (${envAdminPassword.length} characters).`);
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

// ---------- Visitor tracking ----------
// Opaque visitor cookie, referring host, device class, client IP, and a
// coarse GeoIP region (country / city). No user-agent strings are stored and
// nothing is sent to a third-party analytics vendor.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BOT_UA_RE = /(bot|crawler|crawl|spider|slurp|headless|phantom|monitor|uptime|pingdom|lighthouse|curl|wget|python-requests|axios|okhttp|go-http-client|facebookexternalhit|whatsapp|telegram|preview|semrush|ahrefs|mj12|dataprovider)/i;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-f:]+$/i;

let countryNames;
try {
  countryNames = new Intl.DisplayNames(['en'], { type: 'region' });
} catch {
  countryNames = null;
}

function visitorCookie(id) {
  const parts = [
    `sk_vid=${id}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${VISITOR_COOKIE_TTL_SECONDS}`,
  ];
  if (IS_PRODUCTION) parts.push('Secure');
  return parts.join('; ');
}

function looksLikeBot(userAgent) {
  return !userAgent || BOT_UA_RE.test(userAgent);
}

function deviceClass(userAgent) {
  if (/ipad|tablet|playbook|silk|(android(?!.*mobile))/i.test(userAgent)) return 'tablet';
  if (/mobi|iphone|ipod|windows phone|blackberry/i.test(userAgent)) return 'mobile';
  return 'desktop';
}

// The admin panel is excluded so the owner checking their own stats doesn't
// inflate the visitor numbers they're reading.
function trackablePath(value) {
  if (typeof value !== 'string' || !value.startsWith('/')) return '';
  const clean = value.split('?')[0].split('#')[0].slice(0, 200);
  if (clean.startsWith('/admin')) return '';
  return clean;
}

function referrerHost(value, ownHost) {
  if (typeof value !== 'string' || !value) return '';
  try {
    const host = new URL(value).hostname.replace(/^www\./, '');
    // Navigation within the site isn't a traffic source.
    if (!host || host === String(ownHost || '').split(':')[0].replace(/^www\./, '')) return '';
    return host.slice(0, 120);
  } catch {
    return '';
  }
}

// ---------- Rate limiting (in-memory, best-effort for a single-process prototype) ----------
const submissionHits = new Map();
const loginHits = new Map();
const trackHits = new Map();

function rateLimited(map, key, max, windowMs) {
  const now = Date.now();
  const hits = (map.get(key) || []).filter((t) => now - t < windowMs);
  hits.push(now);
  map.set(key, hits);
  return hits.length > max;
}

function clientIp(req) {
  const candidates = [
    req.headers['cf-connecting-ip'],
    req.headers['true-client-ip'],
    req.headers['x-real-ip'],
    typeof req.headers['x-forwarded-for'] === 'string'
      ? req.headers['x-forwarded-for'].split(',')[0]
      : '',
    req.socket && req.socket.remoteAddress,
  ];
  for (const raw of candidates) {
    const ip = normalizeIp(raw);
    if (ip) return ip;
  }
  return '';
}

function normalizeIp(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return '';
  let ip = raw.trim().replace(/^\[|\]$/g, '');
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  // IPv4-with-port shows up on some proxies ("1.2.3.4:12345").
  if (IPV4_RE.test(ip.split(':')[0]) && ip.includes(':') && ip.indexOf(':') === ip.lastIndexOf(':')) {
    ip = ip.split(':')[0];
  }
  if (IPV4_RE.test(ip) || (ip.includes(':') && IPV6_RE.test(ip))) return ip.slice(0, 45);
  return '';
}

function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip === '::1' || ip === '127.0.0.1') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  if (ip.startsWith('fc') || ip.startsWith('fd') || ip.toLowerCase().startsWith('fe80:')) return true;
  return false;
}

function countryName(code) {
  if (!code || code === 'Unknown') return '';
  try {
    return (countryNames && countryNames.of(code)) || code;
  } catch {
    return code;
  }
}

function formatLocation(city, country) {
  const name = countryName(country);
  const parts = [city, name].filter(Boolean);
  return parts.join(', ');
}

function lookupGeo(ip) {
  if (!ip || isPrivateIp(ip)) {
    return { country: '', region: '', city: ip ? 'Local / private network' : '' };
  }
  const hit = geoip.lookup(ip);
  if (!hit) return { country: '', region: '', city: '' };
  return {
    country: (hit.country || '').slice(0, 8),
    region: (hit.region || '').slice(0, 8),
    city: (hit.city || '').slice(0, 80),
  };
}

// Without this the maps grow one entry per IP forever. /api/track is hit by
// every page load, so it's the one that would actually add up over time.
const RATE_LIMIT_SWEEP_MS = 30 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  [submissionHits, loginHits, trackHits].forEach((map) => {
    map.forEach((hits, key) => {
      if (!hits.some((t) => now - t < RATE_LIMIT_SWEEP_MS)) map.delete(key);
    });
  });
}, RATE_LIMIT_SWEEP_MS).unref();

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

  if (interested && (!name || !contact)) {
    return { error: 'Please share your name and a phone number or email so we can follow up about setup help.' };
  }

  return { value: { name, contact, role, city, cityOther, problem, interested } };
}

// ---------- HTTP helpers ----------
// HEAD must be accepted anywhere GET is — uptime monitors (UptimeRobot
// included) commonly send HEAD instead of GET for lighter checks. Per HTTP
// semantics a HEAD response carries the same headers as GET but no body.
function isGettable(method) {
  return method === 'GET' || method === 'HEAD';
}

function sendJson(res, status, obj, method) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(method === 'HEAD' ? undefined : body);
}

function sendNoContent(res) {
  res.writeHead(204, { 'X-Content-Type-Options': 'nosniff' });
  res.end();
}

function sendFile(res, filePath, contentType, method) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end(method === 'HEAD' ? undefined : 'Not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': Buffer.byteLength(data),
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    });
    res.end(method === 'HEAD' ? undefined : data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (isGettable(req.method) && url.pathname === '/') {
      return sendFile(res, path.join(ROOT, 'index.html'), 'text/html; charset=utf-8', req.method);
    }

    if (isGettable(req.method) && url.pathname === '/admin') {
      return sendFile(res, path.join(ROOT, 'admin.html'), 'text/html; charset=utf-8', req.method);
    }

    if (isGettable(req.method) && url.pathname === '/health') {
      // Always 200 if the process is alive and answering HTTP — the site is
      // designed to keep serving pages even when Postgres is unreachable, so
      // a DB outage shouldn't read as "the app is down" to an uptime monitor.
      // `db` here is what actually tells you whether submissions will work.
      // Reports the cached status rather than probing live, so this stays a
      // fast, cheap endpoint safe to poll frequently — the DB-backed routes
      // already self-heal and retry on their own (see isDbReady above them).
      return sendJson(res, 200, {
        status: 'ok',
        db: dbReady ? 'connected' : 'unreachable',
        uptimeSeconds: Math.round(process.uptime()),
        timestamp: new Date().toISOString(),
      }, req.method);
    }

    if (req.method === 'POST' && url.pathname === '/api/submissions') {
      if (rateLimited(submissionHits, clientIp(req), 10, 60 * 60 * 1000)) {
        return sendJson(res, 429, { error: 'Too many submissions from this connection. Please try again later.' });
      }
      if (!(await isDbReady())) {
        return sendJson(res, 503, { error: 'Database is warming up, please try again in a few seconds.' });
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

    // Always answers 204, even when it records nothing — a visitor's page must
    // never show an error or slow down because analytics had a bad day.
    if (req.method === 'POST' && url.pathname === '/api/track') {
      const userAgent = req.headers['user-agent'] || '';
      let body = {};
      try {
        body = await readJsonBody(req, 4 * 1024);
      } catch {
        body = {};
      }

      if (looksLikeBot(userAgent) || rateLimited(trackHits, clientIp(req), 40, 10 * 60 * 1000)) {
        return sendNoContent(res);
      }

      const cookies = parseCookies(req);
      const knownVisitor = UUID_RE.test(cookies.sk_vid || '');
      const visitorId = knownVisitor ? cookies.sk_vid : crypto.randomUUID();
      if (!knownVisitor) res.setHeader('Set-Cookie', visitorCookie(visitorId));

      const viewPath = trackablePath(body.path);
      if (viewPath && (await isDbReady())) {
        try {
          const ip = clientIp(req);
          const geo = lookupGeo(ip);
          await db.recordPageView({
            visitorId,
            path: viewPath,
            isNewVisitor: !knownVisitor,
            referrerHost: referrerHost(body.referrer, req.headers.host),
            device: deviceClass(userAgent),
            ip,
            country: geo.country,
            region: geo.region,
            city: geo.city,
          });
        } catch (err) {
          console.error('[sakhyakirana] Could not record a page view:', err.message);
        }
      }
      return sendNoContent(res);
    }

    if (isGettable(req.method) && url.pathname === '/api/admin/analytics') {
      if (!isAuthedAdmin(req)) return sendJson(res, 401, { error: 'Not authenticated.' }, req.method);
      if (!(await isDbReady())) {
        return sendJson(res, 503, { error: 'Database is warming up, please try again in a few seconds.' }, req.method);
      }
      const analytics = await db.getAnalytics(ANALYTICS_TIMEZONE);
      analytics.regions = (analytics.regions || []).map((row) => ({
        location: formatLocation(row.city, row.country) || 'Unknown',
        visitors: row.visitors,
        views: row.views,
      }));
      analytics.recent = (analytics.recent || []).map((row) => ({
        ...row,
        location: row.city === 'Local / private network'
          ? 'Local / private network'
          : (formatLocation(row.city, row.country) || 'Unknown'),
      }));
      return sendJson(res, 200, { ...analytics, timezone: ANALYTICS_TIMEZONE }, req.method);
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/login') {
      if (rateLimited(loginHits, clientIp(req), 8, 15 * 60 * 1000)) {
        return sendJson(res, 429, { error: 'Too many login attempts. Try again later.' });
      }
      const body = await readJsonBody(req);
      const password = typeof body.password === 'string' ? body.password.trim() : '';
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

    if (isGettable(req.method) && url.pathname === '/api/admin/session') {
      return sendJson(res, 200, { authenticated: isAuthedAdmin(req) }, req.method);
    }

    if (isGettable(req.method) && url.pathname === '/api/submissions') {
      if (!isAuthedAdmin(req)) return sendJson(res, 401, { error: 'Not authenticated.' }, req.method);
      if (!(await isDbReady())) {
        return sendJson(res, 503, { error: 'Database is warming up, please try again in a few seconds.' }, req.method);
      }
      const list = await db.listSubmissions();
      const decrypted = list.map((r) => {
        try {
          return { id: r.id, createdAt: r.createdAt, ...decrypt(r) };
        } catch {
          return { id: r.id, createdAt: r.createdAt, error: 'Could not decrypt this record.' };
        }
      });
      return sendJson(res, 200, { submissions: decrypted }, req.method);
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end(req.method === 'HEAD' ? undefined : 'Not found');
  } catch (err) {
    console.error(err);
    sendJson(res, 500, { error: 'Something went wrong.' });
  }
});

// The HTTP server starts unconditionally — the public page and the admin
// shell must stay reachable even if Postgres is slow to wake (common on
// free-tier serverless Postgres) or briefly unreachable. Only the DB-backed
// routes depend on this succeeding; see dbReady below.
let dbReady = false;
db.ensureSchema()
  .then(() => {
    dbReady = true;
    console.log('[sakhyakirana] Connected to Postgres and verified the submissions table.');
  })
  .catch((err) => {
    console.error('[sakhyakirana] Could not connect to Postgres / create the submissions table. Submissions and the admin panel will return errors until this is fixed — the rest of the site still works.');
    console.error(err);
  });

// Self-heals a stale dbReady=false: if the initial connect attempt gave up
// (see ensureSchema's retry count in db.js) but Postgres has since become
// reachable — e.g. a serverless DB finished waking up — this lets the next
// request succeed instead of staying stuck on the earlier failure forever.
async function isDbReady() {
  if (dbReady) return true;
  try {
    await db.ensureSchema(1);
    dbReady = true;
  } catch {
    dbReady = false;
  }
  return dbReady;
}

server.listen(PORT, () => {
  console.log(`SakhyaKirana server running at http://localhost:${PORT}`);
  console.log(`Admin panel:                   http://localhost:${PORT}/admin`);
});
