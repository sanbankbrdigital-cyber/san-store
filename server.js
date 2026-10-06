require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { MongoClient } = require('mongodb');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scryptAsync = promisify(crypto.scrypt);

const required = ['MONGODB_URI', 'APP_PUBLISH_KEY'];
const missing = required.filter((key) => !process.env[key]);
if (missing.length) {
  console.error(`Missing required environment variables: ${missing.join(', ')}`);
  process.exit(1);
}

const app = express();
const port = Number(process.env.PORT || 3000);
const client = new MongoClient(process.env.MONGODB_URI);
let appsCollection;
let usersCollection;
let sessionsCollection;
let dummyPasswordHash;
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
}));
app.use(express.json({ limit: '20kb' }));
const readLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 180, standardHeaders: 'draft-8', legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false });
const publishLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });

function validHttpsUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try { return new URL(value).protocol === 'https:'; } catch { return false; }
}
function safeEqual(a, b) {
  const crypto = require('crypto');
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function publishAuth(req, res, next) {
  const match = /^Bearer\s+(.+)$/i.exec(req.get('authorization') || '');
  if (!match || !safeEqual(match[1], process.env.APP_PUBLISH_KEY)) {
    return res.status(401).json({ error: 'Chave de publicação inválida.' });
  }
  next();
}

const ACCOUNT_PATTERN = /^[a-z0-9][a-z0-9._-]{2,19}$/;
const EMAIL_PATTERN = /^[a-z0-9][a-z0-9._+-]{0,63}@sanstore\.com$/;
const PASSWORD_PATTERN = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,10}$/;
const PASSWORD_SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };

function normalizeAccount(value) { return typeof value === 'string' ? value.trim().toLowerCase() : ''; }
function normalizeEmail(value) { return typeof value === 'string' ? value.trim().toLowerCase() : ''; }
function validPassword(value) { return typeof value === 'string' && PASSWORD_PATTERN.test(value); }
function tokenDigest(token) { return crypto.createHash('sha256').update(token).digest('hex'); }

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scryptAsync(password, salt, 64, PASSWORD_SCRYPT);
  return `scrypt$16384$8$1$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

async function verifyPassword(password, encoded) {
  try {
    const parts = String(encoded || '').split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt' || parts[1] !== '16384' || parts[2] !== '8' || parts[3] !== '1') return false;
    const salt = Buffer.from(parts[4], 'base64url');
    const expected = Buffer.from(parts[5], 'base64url');
    if (salt.length !== 16 || expected.length !== 64) return false;
    const actual = await scryptAsync(password, salt, expected.length, PASSWORD_SCRYPT);
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  await sessionsCollection.insertOne({ tokenHash: tokenDigest(token), userId, createdAt: now, expiresAt });
  return token;
}

async function requireUser(req, res, next) {
  const match = /^Bearer\s+(.+)$/i.exec(req.get('authorization') || '');
  if (!match) return res.status(401).json({ error: 'Faça login para continuar.' });
  try {
    const tokenHash = tokenDigest(match[1]);
    const session = await sessionsCollection.findOne({ tokenHash, expiresAt: { $gt: new Date() } });
    if (!session) return res.status(401).json({ error: 'Sessão expirada. Entre novamente.' });
    const user = await usersCollection.findOne({ _id: session.userId }, { projection: { account: 1, email: 1 } });
    if (!user) return res.status(401).json({ error: 'Conta indisponível. Entre novamente.' });
    req.authUser = user;
    req.authTokenHash = tokenHash;
    next();
  } catch {
    res.status(503).json({ error: 'Não foi possível validar a sessão agora.' });
  }
}

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const account = normalizeAccount(req.body?.account);
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;
  if (!ACCOUNT_PATTERN.test(account)) return res.status(400).json({ error: 'A conta deve ter de 3 a 20 caracteres: letras, números, ponto, hífen ou sublinhado.' });
  if (!EMAIL_PATTERN.test(email)) return res.status(400).json({ error: 'Use um e-mail terminado em @sanstore.com.' });
  if (!validPassword(password)) return res.status(400).json({ error: 'A senha deve ter 8 a 10 caracteres, com maiúscula, minúscula, número e caractere especial.' });
  try {
    const passwordHash = await hashPassword(password);
    const now = new Date();
    const result = await usersCollection.insertOne({ account, email, passwordHash, createdAt: now });
    const token = await createSession(result.insertedId);
    res.set('Cache-Control', 'no-store');
    return res.status(201).json({ token, user: { account, email } });
  } catch (error) {
    if (error && error.code === 11000) return res.status(409).json({ error: 'Essa conta ou e-mail já está cadastrado.' });
    console.error('Could not register SAN STORE account.');
    return res.status(503).json({ error: 'Não foi possível criar a conta agora. Tente novamente.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const identifier = typeof req.body?.identifier === 'string' ? req.body.identifier.trim().toLowerCase() : '';
  const password = req.body?.password;
  if (!identifier || !validPassword(password)) return res.status(400).json({ error: 'Informe a conta/e-mail e a senha válida.' });
  try {
    const emailLogin = identifier.includes('@');
    const lookup = emailLogin
      ? (EMAIL_PATTERN.test(identifier) ? { email: identifier } : null)
      : (ACCOUNT_PATTERN.test(identifier) ? { account: identifier } : null);
    const user = lookup ? await usersCollection.findOne(lookup) : null;
    const verified = await verifyPassword(password, user ? user.passwordHash : dummyPasswordHash);
    if (!user || !verified) return res.status(401).json({ error: 'Conta/e-mail ou senha inválidos.' });
    const token = await createSession(user._id);
    res.set('Cache-Control', 'no-store');
    return res.json({ token, user: { account: user.account, email: user.email } });
  } catch {
    console.error('Could not sign in to SAN STORE.');
    return res.status(503).json({ error: 'Não foi possível entrar agora. Tente novamente.' });
  }
});

app.get('/api/auth/me', requireUser, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ user: { account: req.authUser.account, email: req.authUser.email } });
});

app.delete('/api/auth/session', requireUser, async (req, res) => {
  try {
    await sessionsCollection.deleteOne({ tokenHash: req.authTokenHash });
    return res.status(204).end();
  } catch {
    return res.status(503).json({ error: 'Não foi possível encerrar a sessão no servidor.' });
  }
});

app.get('/api/health', readLimiter, async (_req, res) => {
  try {
    await client.db(process.env.MONGODB_DB || 'san_store').command({ ping: 1 });
    res.json({ ok: true, database: 'connected' });
  } catch {
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.get('/api/apps', readLimiter, async (_req, res) => {
  try {
    const docs = await appsCollection.find({}, { projection: { slug: 1, name: 1, category: 1, image: 1, apk: 1, description: 1, createdAt: 1, featured: 1 } })
      .sort({ createdAt: -1 }).limit(500).toArray();
    res.set('Cache-Control', 'no-store');
    res.json(docs.map((doc) => ({
      id: doc.slug || doc._id.toString(), name: doc.name, category: doc.category,
      image: doc.image, apk: doc.apk, description: doc.description,
      featured: Boolean(doc.featured),
    })));
  } catch (error) {
    console.error('Could not list apps:', error.message);
    res.status(503).json({ error: 'O catálogo está temporariamente indisponível.' });
  }
});

app.post('/api/apps', publishLimiter, publishAuth, async (req, res) => {
  const { name, category, image, apk, description } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 60 ||
      !['App', 'Game'].includes(category) || !validHttpsUrl(image) || !validHttpsUrl(apk) ||
      typeof description !== 'string' || description.trim().length < 5 || description.trim().length > 350) {
    return res.status(400).json({ error: 'Confira nome, categoria, links HTTPS e descrição.' });
  }
  try {
    const record = {
      name: name.trim(), category,
      image: new URL(image).href, apk: new URL(apk).href,
      description: description.trim(), createdAt: new Date(),
    };
    const result = await appsCollection.insertOne(record);
    res.status(201).json({ id: result.insertedId.toString(), ...record, featured: false });
  } catch (error) {
    console.error('Could not publish app:', error.message);
    res.status(503).json({ error: 'Não foi possível salvar no MongoDB.' });
  }
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], maxAge: '1h' }));
app.get(/.*/, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

async function start() {
  await client.connect();
  const db = client.db(process.env.MONGODB_DB || 'san_store');
  appsCollection = db.collection('apps');
  usersCollection = db.collection('users');
  sessionsCollection = db.collection('sessions');
  dummyPasswordHash = await hashPassword(crypto.randomBytes(32).toString('hex'));
  await Promise.all([
    appsCollection.createIndex({ createdAt: -1 }),
    appsCollection.createIndex({ slug: 1 }, { unique: true, sparse: true }),
    usersCollection.createIndex({ account: 1 }, { unique: true }),
    usersCollection.createIndex({ email: 1 }, { unique: true }),
    sessionsCollection.createIndex({ tokenHash: 1 }, { unique: true }),
    sessionsCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    sessionsCollection.createIndex({ userId: 1 }),
  ]);
  await appsCollection.updateOne(
    { slug: 'sanbank-br-digital' },
    { $setOnInsert: {
      slug: 'sanbank-br-digital', name: 'SANBANK BR DIGITAL', category: 'App',
      image: 'https://i.ibb.co/Ld27J25H/shared-image-3.webp',
      apk: 'https://github.com/sanbankbrdigital-cyber/san-store/raw/refs/heads/main/SANBANK-BR-DIGITAL-NATIVO-COMPLETO-v3.1.51-sem-top-interbank-icon-ANDROID-5.0-A-17.apk',
      description: 'Aplicativo SANBANK BR DIGITAL para Android. Baixe e conheça os recursos do seu banco digital.',
      featured: true, createdAt: new Date(),
    } },
    { upsert: true },
  );
  app.listen(port, '0.0.0.0', () => console.log(`SAN STORE online on port ${port}`));
}
start().catch((error) => {
  console.error('Could not connect to MongoDB:', error.message);
  process.exit(1);
});

async function shutdown() {
  await client.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
