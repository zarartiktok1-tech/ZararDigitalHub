const express = require('express');
const cookieSession = require('cookie-session');
const rateLimit = require('express-rate-limit');
const { MongoClient } = require('mongodb');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(cookieSession({
  name: 'sdh_session',
  keys: [process.env.SESSION_SECRET || 'development-only-change-this-secret-before-deploying'],
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 7 * 24 * 60 * 60 * 1000
}));
app.use('/api/access', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false }));

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const randomCode = () => 'SDH-' + crypto.randomBytes(6).toString('hex').toUpperCase();
let codes;

function requireLogin(req, res, next) {
  if (!req.session || !req.session.codeId) return res.status(401).json({ error: 'Please enter your access code first.' });
  next();
}
function requireAdmin(req, res, next) {
  const key = req.get('x-admin-key');
  const supplied = Buffer.from(String(key || ''));
  const expected = Buffer.from(String(process.env.ADMIN_KEY || ''));
  if (!process.env.ADMIN_KEY || supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  next();
}

app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.post('/api/access', async (req, res) => {
  try {
    const code = String(req.body.code || '').trim().toUpperCase();
    if (!/^[A-Z0-9-]{6,40}$/.test(code)) return res.status(400).json({ error: 'Enter a valid access code.' });
    const record = await codes.findOne({ codeHash: sha(code), revoked: { $ne: true } });
    if (!record) return res.status(403).json({ error: 'Incorrect or disabled code.' });
    if (record.expiresAt && record.expiresAt <= new Date()) return res.status(403).json({ error: 'This code has expired.' });
    if (record.maxUses && record.uses >= record.maxUses) return res.status(403).json({ error: 'This code has reached its usage limit.' });
    await codes.updateOne({ _id: record._id }, { $inc: { uses: 1 }, $set: { lastUsedAt: new Date() } });
    req.session.codeId = record._id.toString();
    req.session.label = record.label || 'Guest';
    res.json({ ok: true, label: req.session.label });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Try again later.' }); }
});

app.post('/api/logout', (req, res) => { req.session = null; res.json({ ok: true }); });
app.get('/api/content', requireLogin, async (req, res) => {
  const record = await codes.findOne({ _id: new (require('mongodb').ObjectId)(req.session.codeId), revoked: { $ne: true } });
  if (!record || (record.expiresAt && record.expiresAt <= new Date())) { req.session = null; return res.status(401).json({ error: 'Code is no longer valid. Sign in again.' }); }
  res.json({ ok: true, label: req.session.label || 'Guest', modules: [
    { title: 'HTML Tools', icon: '</>', description: 'Your HTML tools will appear here.' },
    { title: 'APKs & Web Apps', icon: '◈', description: 'Add links to apps you are authorized to distribute.' },
    { title: 'Courses', icon: '✦', description: 'Your learning resources.' },
    { title: 'Profile', icon: '●', description: 'Access granted.' },
    { title: 'Premium', icon: '♛', description: 'Premium resources.' }
  ] });
});

// Create one or more unique codes. Keep ADMIN_KEY private. Example request:
// POST /api/admin/codes  x-admin-key: YOUR_ADMIN_KEY
// JSON: {"count":3,"label":"Customer","expiresInDays":30,"maxUses":1}
app.post('/api/admin/codes', requireAdmin, async (req, res) => {
  try {
    const count = Math.max(1, Math.min(50, Number.parseInt(req.body.count, 10) || 1));
    const label = String(req.body.label || 'Guest').slice(0, 80);
    const maxUses = Math.max(1, Math.min(100000, Number.parseInt(req.body.maxUses, 10) || 1));
    const days = Number.parseInt(req.body.expiresInDays, 10);
    const expiresAt = Number.isFinite(days) && days > 0 ? new Date(Date.now() + days * 86400000) : null;
    const created = [];
    for (let i = 0; i < count; i++) {
      const code = randomCode();
      const doc = { codeHash: sha(code), label, uses: 0, maxUses, revoked: false, createdAt: new Date(), ...(expiresAt ? { expiresAt } : {}) };
      await codes.insertOne(doc);
      created.push({ code, label, maxUses, expiresAt });
    }
    res.json({ ok: true, note: 'Copy these codes now. They are not stored in readable form and cannot be shown again.', codes: created });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not create code(s).' }); }
});

// Revoke a code by sending its plaintext code in the body (the database stores only its hash).
app.post('/api/admin/revoke', requireAdmin, async (req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase();
  if (!code) return res.status(400).json({ error: 'Code is required.' });
  const result = await codes.updateOne({ codeHash: sha(code) }, { $set: { revoked: true, revokedAt: new Date() } });
  res.json({ ok: result.modifiedCount === 1, message: result.modifiedCount === 1 ? 'Code revoked.' : 'Code not found or already revoked.' });
});

app.use(express.static('public'));
app.get('*path', (_req, res) => res.sendFile(require('path').join(__dirname, 'public', 'index.html')));

async function start() {
  if (!process.env.MONGODB_URI) throw new Error('Missing MONGODB_URI environment variable.');
  if (process.env.NODE_ENV === 'production' && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) throw new Error('Set SESSION_SECRET to a random string of at least 32 characters.');
  if (process.env.NODE_ENV === 'production' && !process.env.ADMIN_KEY) throw new Error('Set ADMIN_KEY before deploying.');
  const client = new MongoClient(process.env.MONGODB_URI);
  await client.connect();
  const db = client.db(process.env.DB_NAME || 'zarar_hub');
  codes = db.collection('access_codes');
  await codes.createIndex({ codeHash: 1 }, { unique: true });
  app.listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('Zarar Digital Hub is running.'));
}
start().catch(err => { console.error(err); process.exit(1); });
