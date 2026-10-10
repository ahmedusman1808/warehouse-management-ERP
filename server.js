const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');

const app = express();
const port = Number(process.env.PORT || 3000);
const cookieName = 'warehouse_session';
const sessionMs = 12 * 60 * 60 * 1000;
const publicDir = __dirname;
const ssl = process.env.PGSSL === 'true'
  ? process.env.PGSSL_ROOT_CERT
    ? { ca: fs.readFileSync(path.resolve(__dirname, process.env.PGSSL_ROOT_CERT), 'utf8') }
    : {}
  : undefined;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl
});
const randomId = () => crypto.randomUUID();
const hashToken = value => crypto.createHash('sha256').update(value).digest('hex');
const hashPassword = password => new Promise((resolve, reject) => {
  const salt = crypto.randomBytes(16);
  crypto.scrypt(password, salt, 64, (error, key) => {
    if (error) return reject(error);
    resolve({ salt: salt.toString('hex'), hash: key.toString('hex') });
  });
});
const verifyPassword = (password, salt, expected) => new Promise((resolve, reject) => {
  crypto.scrypt(password, Buffer.from(salt, 'hex'), 64, (error, key) => {
    if (error) return reject(error);
    const expectedBytes = Buffer.from(expected, 'hex');
    resolve(expectedBytes.length === key.length && crypto.timingSafeEqual(key, expectedBytes));
  });
});

const collections = ['workers', 'customers', 'suppliers', 'products', 'expenseCats', 'attendance', 'production', 'stock', 'sales', 'purchases', 'expenses'];
const emptyState = () => Object.fromEntries(collections.map(name => [name, []]));
const allowedPermissions = new Set(['dashboard', 'attendance', 'production', 'inventory', 'sales', 'purchases', 'expenses', 'masters', 'reports']);
const writeCollections = {
  attendance: ['attendance'],
  production: ['production'],
  inventory: ['stock'],
  sales: ['sales'],
  purchases: ['purchases'],
  expenses: ['expenses'],
  masters: ['workers', 'customers', 'suppliers', 'products', 'expenseCats']
};
const readCollections = {
  attendance: ['attendance', 'workers'],
  production: ['production', 'products'],
  inventory: ['stock', 'products', 'production', 'purchases', 'sales'],
  sales: ['sales', 'customers', 'products'],
  purchases: ['purchases', 'suppliers', 'products'],
  expenses: ['expenses', 'expenseCats'],
  masters: ['workers', 'customers', 'suppliers', 'products', 'expenseCats']
};
const adminPermissions = [...allowedPermissions, 'access'];

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '8mb' }));
app.use(cookieParser());

async function initializeDatabase() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required.');
  await pool.query(`CREATE TABLE IF NOT EXISTS erp_accounts (
      id text PRIMARY KEY,
      name text NOT NULL,
      username text NOT NULL UNIQUE,
      role text NOT NULL CHECK (role IN ('admin', 'caretaker')),
      password_salt text NOT NULL,
      password_hash text NOT NULL,
      permissions jsonb NOT NULL DEFAULT '[]'::jsonb,
      active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now()
    )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS erp_sessions (
      token_hash text PRIMARY KEY,
      account_id text NOT NULL REFERENCES erp_accounts(id) ON DELETE CASCADE,
      expires_at timestamptz NOT NULL
    )`);
  await pool.query('CREATE INDEX IF NOT EXISTS erp_sessions_expiry_idx ON erp_sessions (expires_at)');
  await pool.query(`CREATE TABLE IF NOT EXISTS erp_state (
      id integer PRIMARY KEY CHECK (id = 1),
      revision bigint NOT NULL DEFAULT 0,
      payload jsonb NOT NULL
    )`);
  await pool.query('INSERT INTO erp_state (id, revision, payload) VALUES (1, 0, $1::jsonb) ON CONFLICT (id) DO NOTHING', [JSON.stringify(emptyState())]);
}

function publicAccount(row) {
  return {
    id: row.id,
    name: row.name,
    username: row.username,
    role: row.role,
    permissions: row.role === 'admin' ? adminPermissions : row.permissions,
    active: row.active
  };
}

function setSessionCookie(res, token, secure) {
  res.cookie(cookieName, token, {
    httpOnly: true,
    secure,
    sameSite: 'strict',
    path: '/',
    maxAge: sessionMs
  });
}

async function createSession(req, res, row) {
  const token = crypto.randomBytes(32).toString('base64url');
  await pool.query('INSERT INTO erp_sessions (token_hash, account_id, expires_at) VALUES ($1, $2, now() + interval \'12 hours\')', [hashToken(token), row.id]);
  setSessionCookie(res, token, process.env.NODE_ENV === 'production' || req.secure);
  return publicAccount(row);
}

async function requireSession(req, res, next) {
  try {
    const token = req.cookies[cookieName];
    if (!token) return res.status(401).json({ error: 'Sign in required.' });
    const result = await pool.query(`
      SELECT a.*, s.expires_at FROM erp_sessions s
      JOIN erp_accounts a ON a.id = s.account_id
      WHERE s.token_hash = $1 AND s.expires_at > now() AND a.active = true
    `, [hashToken(token)]);
    if (!result.rowCount) return res.status(401).json({ error: 'Session expired. Sign in again.' });
    req.account = publicAccount(result.rows[0]);
    next();
  } catch (error) {
    next(error);
  }
}

function sameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin && new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'Cross-origin request rejected.' });
  next();
}

function requireAdmin(req, res, next) {
  if (req.account.role !== 'admin') return res.status(403).json({ error: 'Administrator access required.' });
  next();
}

async function getSnapshot(account) {
  const [{ rows: stateRows }, { rows: accountRows }] = await Promise.all([
    pool.query('SELECT revision, payload FROM erp_state WHERE id = 1'),
    account.role === 'admin'
      ? pool.query("SELECT * FROM erp_accounts ORDER BY role, name")
      : Promise.resolve({ rows: [] })
  ]);
  const payload = emptyState();
  const source = stateRows[0].payload;
  const readable = new Set();
  if (account.role === 'admin' || account.permissions.includes('reports')) {
    collections.forEach(name => readable.add(name));
  } else {
    account.permissions.forEach(permission => (readCollections[permission] || []).forEach(name => readable.add(name)));
  }
  for (const name of readable) payload[name] = Array.isArray(source[name]) ? source[name] : [];
  payload.users = account.role === 'admin' ? accountRows.map(publicAccount) : [];
  payload.dashboard = makeDashboard(source);
  return { revision: Number(stateRows[0].revision), payload };
}

function makeDashboard(source) {
  const summary = {};
  const get = date => summary[date] ||= { production: 0, sales: 0, purchases: 0, expenses: 0, present: 0 };
  source.production.forEach(row => { get(row.date).production += Number(row.quantity) || 0; });
  source.sales.forEach(row => { get(row.date).sales += (Number(row.qty) || 0) * (Number(row.rate) || 0); });
  source.purchases.forEach(row => { get(row.date).purchases += (Number(row.qty) || 0) * (Number(row.rate) || 0); });
  source.expenses.forEach(row => { get(row.date).expenses += Number(row.amount) || 0; });
  source.attendance.forEach(row => { if (row.status === 'present') get(row.date).present++; });
  return { dates: summary, activeWorkers: source.workers.filter(worker => worker.active).length };
}

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-7', legacyHeaders: false });
app.get('/api/status', async (req, res, next) => {
  try {
    const result = await pool.query("SELECT EXISTS (SELECT 1 FROM erp_accounts WHERE role = 'admin') AS admin_exists");
    res.json({ adminExists: result.rows[0].admin_exists });
  } catch (error) { next(error); }
});

app.post('/api/setup', sameOrigin, authLimiter, async (req, res, next) => {
  const name = String(req.body.name || '').trim();
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!name || !/^[a-z0-9._-]{3,40}$/.test(username) || password.length < 8) {
    return res.status(400).json({ error: 'Enter a name, a username (3-40 letters or ._-), and a password of at least 8 characters.' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT pg_advisory_xact_lock(hashtext('warehouse-erp-first-admin'))");
    const existing = await client.query("SELECT 1 FROM erp_accounts WHERE role = 'admin' LIMIT 1");
    if (existing.rowCount) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Administrator setup has already been completed.' });
    }
    const credential = await hashPassword(password);
    const inserted = await client.query(`
      INSERT INTO erp_accounts (id, name, username, role, password_salt, password_hash, permissions)
      VALUES ($1, $2, $3, 'admin', $4, $5, $6::jsonb) RETURNING *
    `, [randomId(), name, username, credential.salt, credential.hash, JSON.stringify(adminPermissions)]);
    await client.query('COMMIT');
    const user = await createSession(req, res, inserted.rows[0]);
    res.status(201).json({ user });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    next(error);
  } finally { client.release(); }
});

app.post('/api/login', sameOrigin, authLimiter, async (req, res, next) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const role = String(req.body.role || '');
    if (!['admin', 'caretaker'].includes(role)) return res.status(400).json({ error: 'Choose Admin or Caretaker before signing in.' });
    const result = await pool.query('SELECT * FROM erp_accounts WHERE username = $1 AND active = true', [username]);
    if (!result.rowCount || result.rows[0].role !== role || !(await verifyPassword(password, result.rows[0].password_salt, result.rows[0].password_hash))) {
      return res.status(401).json({ error: 'Username or password is incorrect.' });
    }
    const user = await createSession(req, res, result.rows[0]);
    res.json({ user });
  } catch (error) { next(error); }
});

app.get('/api/session', requireSession, (req, res) => res.json({ user: req.account }));
app.post('/api/logout', sameOrigin, requireSession, async (req, res, next) => {
  try {
    const token = req.cookies[cookieName];
    await pool.query('DELETE FROM erp_sessions WHERE token_hash = $1', [hashToken(token)]);
    res.clearCookie(cookieName, { httpOnly: true, secure: process.env.NODE_ENV === 'production' || req.secure, sameSite: 'strict', path: '/' });
    res.status(204).end();
  } catch (error) { next(error); }
});

app.get('/api/state', requireSession, async (req, res, next) => {
  try { res.json(await getSnapshot(req.account)); } catch (error) { next(error); }
});

app.put('/api/state', sameOrigin, requireSession, async (req, res, next) => {
  const revision = Number(req.body.revision);
  const incoming = req.body.payload;
  if (!Number.isSafeInteger(revision) || !incoming || typeof incoming !== 'object') return res.status(400).json({ error: 'Invalid state update.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = await client.query('SELECT revision, payload FROM erp_state WHERE id = 1 FOR UPDATE');
    if (Number(current.rows[0].revision) !== revision) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Data changed on another device. Reload to get the latest copy.', revision: Number(current.rows[0].revision) });
    }
    const allowed = new Set();
    if (req.account.role === 'admin') collections.forEach(name => allowed.add(name));
    else req.account.permissions.forEach(permission => (writeCollections[permission] || []).forEach(name => allowed.add(name)));
    const next = { ...current.rows[0].payload };
    for (const name of allowed) {
      if (!Array.isArray(incoming[name])) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `Invalid collection: ${name}` });
      }
      if (req.account.role === 'caretaker') {
        const retained = new Set(incoming[name].map(row => row && row.id).filter(Boolean));
        const removed = (Array.isArray(next[name]) ? next[name] : []).some(row => row && row.id && !retained.has(row.id));
        if (removed) {
          await client.query('ROLLBACK');
          return res.status(403).json({ error: 'Caretakers cannot delete shared records. Ask an administrator to remove them.' });
        }
      }
      next[name] = incoming[name];
    }
    const updated = await client.query('UPDATE erp_state SET payload = $1::jsonb, revision = revision + 1 WHERE id = 1 RETURNING revision', [JSON.stringify(next)]);
    await client.query('COMMIT');
    res.json({ revision: Number(updated.rows[0].revision) });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    next(error);
  } finally { client.release(); }
});

app.post('/api/state/import', sameOrigin, requireSession, requireAdmin, async (req, res, next) => {
  try {
    const revision = Number(req.body.revision);
    if (revision !== 0 || !req.body.payload || typeof req.body.payload !== 'object') return res.status(409).json({ error: 'Initial import is available only for an empty server database.' });
    const result = await pool.query('UPDATE erp_state SET payload = $1::jsonb, revision = revision + 1 WHERE id = 1 AND revision = 0 RETURNING revision', [JSON.stringify(Object.fromEntries(collections.map(name => [name, Array.isArray(req.body.payload[name]) ? req.body.payload[name] : []])))]);
    if (!result.rowCount) return res.status(409).json({ error: 'Server data already exists; import was not applied.' });
    res.json({ revision: Number(result.rows[0].revision) });
  } catch (error) { next(error); }
});

app.post('/api/state/merge-import', sameOrigin, requireSession, requireAdmin, async (req, res, next) => {
  const revision = Number(req.body.revision);
  const incoming = req.body.payload;
  if (!Number.isSafeInteger(revision) || !incoming || typeof incoming !== 'object') return res.status(400).json({ error: 'Invalid import data.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = await client.query('SELECT revision, payload FROM erp_state WHERE id = 1 FOR UPDATE');
    if (Number(current.rows[0].revision) !== revision) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Shared data changed. Reload before importing browser records.' });
    }
    const merged = { ...current.rows[0].payload };
    for (const name of collections) {
      if (!Array.isArray(incoming[name])) continue;
      const rows = Array.isArray(merged[name]) ? merged[name] : [];
      const known = new Set(rows.map(row => row && row.id).filter(Boolean));
      const missing = incoming[name].filter(row => {
        if (!row || !row.id || known.has(row.id)) return false;
        known.add(row.id);
        return true;
      });
      merged[name] = rows.concat(missing);
    }
    const updated = await client.query('UPDATE erp_state SET payload = $1::jsonb, revision = revision + 1 WHERE id = 1 RETURNING revision', [JSON.stringify(merged)]);
    await client.query('COMMIT');
    res.json({ revision: Number(updated.rows[0].revision) });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    next(error);
  } finally { client.release(); }
});

app.post('/api/state/reset', sameOrigin, requireSession, requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query('UPDATE erp_state SET payload = $1::jsonb, revision = revision + 1 WHERE id = 1 RETURNING revision', [JSON.stringify(emptyState())]);
    res.json({ revision: Number(result.rows[0].revision) });
  } catch (error) { next(error); }
});

app.post('/api/accounts', sameOrigin, requireSession, requireAdmin, async (req, res, next) => {
  const { name, username, password } = req.body;
  const safeName = String(name || '').trim();
  const safeUsername = String(username || '').trim().toLowerCase();
  const permissions = [...new Set(Array.isArray(req.body.permissions) ? req.body.permissions : [])];
  if (!safeName || !/^[a-z0-9._-]{3,40}$/.test(safeUsername) || String(password || '').length < 8 || !permissions.length || permissions.some(item => !allowedPermissions.has(item))) {
    return res.status(400).json({ error: 'Enter valid account details, a password of at least 8 characters, and one or more valid permissions.' });
  }
  try {
    const credential = await hashPassword(password);
    const result = await pool.query(`
      INSERT INTO erp_accounts (id, name, username, role, password_salt, password_hash, permissions)
      VALUES ($1, $2, $3, 'caretaker', $4, $5, $6::jsonb) RETURNING *
    `, [randomId(), safeName, safeUsername, credential.salt, credential.hash, JSON.stringify(permissions)]);
    res.status(201).json({ user: publicAccount(result.rows[0]) });
  } catch (error) { next(error); }
});

app.patch('/api/accounts/:id', sameOrigin, requireSession, requireAdmin, async (req, res, next) => {
  const current = await pool.query("SELECT * FROM erp_accounts WHERE id = $1 AND role = 'caretaker'", [req.params.id]);
  if (!current.rowCount) return res.status(404).json({ error: 'Caretaker account not found.' });
  const old = current.rows[0];
  const name = req.body.name === undefined ? old.name : String(req.body.name).trim();
  const username = req.body.username === undefined ? old.username : String(req.body.username).trim().toLowerCase();
  const active = req.body.active === undefined ? old.active : req.body.active;
  const requestedPermissions = req.body.permissions === undefined ? old.permissions : req.body.permissions;
  const permissions = Array.isArray(requestedPermissions) ? [...new Set(requestedPermissions)] : [];
  if (!name || typeof active !== 'boolean' || !/^[a-z0-9._-]{3,40}$/.test(username) || !permissions.length || permissions.some(item => !allowedPermissions.has(item))) {
    return res.status(400).json({ error: 'Invalid caretaker details or permissions.' });
  }
  try {
    let credential = { salt: old.password_salt, hash: old.password_hash };
    if (req.body.password) {
      if (String(req.body.password).length < 8) return res.status(400).json({ error: 'Password must have at least 8 characters.' });
      credential = await hashPassword(String(req.body.password));
    }
    const result = await pool.query(`
      UPDATE erp_accounts SET name = $2, username = $3, active = $4, permissions = $5::jsonb,
        password_salt = $6, password_hash = $7 WHERE id = $1 RETURNING *
    `, [req.params.id, name, username, active, JSON.stringify(permissions), credential.salt, credential.hash]);
    if (!active) await pool.query('DELETE FROM erp_sessions WHERE account_id = $1', [req.params.id]);
    res.json({ user: publicAccount(result.rows[0]) });
  } catch (error) { next(error); }
});

app.get('/', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));
app.use((error, req, res, next) => {
  if (error.code === '23505') return res.status(409).json({ error: 'That username is already in use.' });
  console.error(error);
  res.status(500).json({ error: 'Server error. Check server logs.' });
});

initializeDatabase().then(() => {
  app.listen(port, '0.0.0.0', () => console.log(`Warehouse ERP listening on port ${port}`));
}).catch(error => {
  console.error('Unable to start Warehouse ERP:', error.message);
  process.exit(1);
});
