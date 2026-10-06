require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { MongoClient, ObjectId } = require('mongodb');
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
let submissionsCollection;
let settingsCollection;
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
    const user = await usersCollection.findOne({ _id: session.userId }, { projection: { account: 1, email: 1, role: 1, developerStatus: 1, developerName: 1 } });
    if (!user) return res.status(401).json({ error: 'Conta indisponível. Entre novamente.' });
    req.authUser = user;
    req.authTokenHash = tokenHash;
    next();
  } catch {
    res.status(503).json({ error: 'Não foi possível validar a sessão agora.' });
  }
}

function requireAdmin(req, res, next) {
  requireUser(req, res, () => {
    if (req.authUser.role !== 'admin') return res.status(403).json({ error: 'Acesso restrito ao administrador.' });
    next();
  });
}

function requireDeveloper(req, res, next) {
  requireUser(req, res, () => {
    if (req.authUser.developerStatus !== 'active') return res.status(403).json({ error: 'A conta ainda não tem acesso de desenvolvedor aprovado.' });
    next();
  });
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
    const result = await usersCollection.insertOne({ account, email, passwordHash, role: 'user', developerStatus: 'none', createdAt: now });
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
  res.json({ user: { account: req.authUser.account, email: req.authUser.email, role: req.authUser.role || 'user', developerStatus: req.authUser.developerStatus || 'none', developerName: req.authUser.developerName || '' } });
});

app.delete('/api/auth/session', requireUser, async (req, res) => {
  try {
    await sessionsCollection.deleteOne({ tokenHash: req.authTokenHash });
    return res.status(204).end();
  } catch {
    return res.status(503).json({ error: 'Não foi possível encerrar a sessão no servidor.' });
  }
});

app.post('/api/admin/bootstrap', authLimiter, requireUser, async (req, res) => {
  const supplied = typeof req.body?.key === 'string' ? req.body.key : '';
  const expected = process.env.SANSTORE_ADMIN_BOOTSTRAP_KEY || '';
  if (!expected) return res.status(503).json({ error: 'A ativação inicial do administrador não está configurada.' });
  if (!supplied || !safeEqual(supplied, expected)) return res.status(401).json({ error: 'Código de ativação inválido.' });
  try {
    if (await usersCollection.countDocuments({ role: 'admin' }) > 0) return res.status(409).json({ error: 'O administrador inicial já foi ativado.' });
    const claim = await settingsCollection.updateOne(
      { _id: 'admin_bootstrap', claimed: { $ne: true } },
      { $set: { claimed: true, claimedAt: new Date(), claimedBy: req.authUser._id } },
    );
    if (claim.matchedCount !== 1) return res.status(409).json({ error: 'A ativação inicial já foi usada.' });
    const updated = await usersCollection.updateOne({ _id: req.authUser._id, role: { $ne: 'admin' } }, { $set: { role: 'admin', adminGrantedAt: new Date() } });
    if (updated.modifiedCount !== 1) {
      await settingsCollection.updateOne({ _id: 'admin_bootstrap', claimedBy: req.authUser._id }, { $set: { claimed: false }, $unset: { claimedAt: '', claimedBy: '' } });
      return res.status(409).json({ error: 'Não foi possível ativar esta conta como administradora.' });
    }
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, user: { account: req.authUser.account, email: req.authUser.email, role: 'admin' } });
  } catch {
    return res.status(503).json({ error: 'Não foi possível ativar o administrador agora.' });
  }
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ user: { account: req.authUser.account, email: req.authUser.email, role: 'admin' } });
});

app.get('/api/developer/me', requireUser, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ status: req.authUser.developerStatus || 'none', developerName: req.authUser.developerName || '' });
});

app.post('/api/developer/request', authLimiter, requireUser, async (req, res) => {
  try {
    if (req.authUser.developerStatus === 'active') return res.json({ status: 'active' });
    if (req.authUser.developerStatus === 'pending') return res.json({ status: 'pending' });
    await usersCollection.updateOne({ _id: req.authUser._id }, { $set: { developerStatus: 'pending', developerRequestedAt: new Date() } });
    return res.status(202).json({ status: 'pending' });
  } catch {
    return res.status(503).json({ error: 'Não foi possível solicitar acesso agora.' });
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
    const docs = await appsCollection.find({ $or: [{ status: { $exists: false } }, { status: 'approved' }] }, { projection: { slug: 1, name: 1, category: 1, image: 1, apk: 1, description: 1, createdAt: 1, featured: 1 } })
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

app.post('/api/submissions', publishLimiter, requireDeveloper, async (req, res) => {
  const { name, category, image, apk, description } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 60 ||
      !['App', 'Game'].includes(category) || !validHttpsUrl(image) || !validHttpsUrl(apk) ||
      typeof description !== 'string' || description.trim().length < 5 || description.trim().length > 350) {
    return res.status(400).json({ error: 'Confira nome, categoria, links HTTPS e descrição.' });
  }
  try {
    const submission = {
      name: name.trim(), category,
      image: new URL(image).href, apk: new URL(apk).href,
      description: description.trim(), status: 'pending',
      submittedBy: req.authUser._id, developerAccount: req.authUser.account,
      developerName: req.authUser.developerName || req.authUser.account,
      createdAt: new Date(),
    };
    const result = await submissionsCollection.insertOne(submission);
    res.set('Cache-Control', 'no-store');
    return res.status(202).json({ id: result.insertedId.toString(), status: 'pending', message: 'Enviado para aprovação do administrador.' });
  } catch {
    return res.status(503).json({ error: 'Não foi possível enviar para aprovação agora.' });
  }
});

// Legacy web submissions are also queued for review; this route can no longer publish directly.
app.post('/api/apps', publishLimiter, publishAuth, async (req, res) => {
  const { name, category, image, apk, description } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 60 ||
      !['App', 'Game'].includes(category) || !validHttpsUrl(image) || !validHttpsUrl(apk) ||
      typeof description !== 'string' || description.trim().length < 5 || description.trim().length > 350) {
    return res.status(400).json({ error: 'Confira nome, categoria, links HTTPS e descrição.' });
  }
  try {
    const submission = {
      name: name.trim(), category,
      image: new URL(image).href, apk: new URL(apk).href,
      description: description.trim(), status: 'pending',
      submittedBy: null, developerAccount: 'web-publisher', developerName: 'Desenvolvedor da loja',
      createdAt: new Date(), source: 'legacy-web-form',
    };
    const result = await submissionsCollection.insertOne(submission);
    res.set('Cache-Control', 'no-store');
    return res.status(202).json({ id: result.insertedId.toString(), status: 'pending', message: 'Enviado para aprovação do administrador.' });
  } catch {
    return res.status(503).json({ error: 'Não foi possível enviar para aprovação agora.' });
  }
});

function parseObjectId(value) {
  return ObjectId.isValid(value) ? new ObjectId(value) : null;
}

function safeSlug(value, id) {
  const base = String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'app';
  return `${base}-${id.toString()}`;
}

function submissionPayload(body) {
  const { name, category, image, apk, description } = body || {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 60 ||
      !['App', 'Game'].includes(category) || !validHttpsUrl(image) || !validHttpsUrl(apk) ||
      typeof description !== 'string' || description.trim().length < 5 || description.trim().length > 350) return null;
  return { name: name.trim(), category, image: new URL(image).href, apk: new URL(apk).href, description: description.trim() };
}

function submissionJson(doc) {
  return {
    id: doc._id.toString(), name: doc.name, category: doc.category, image: doc.image,
    apk: doc.apk, description: doc.description, status: doc.status,
    developerAccount: doc.developerAccount || 'desenvolvedor-web',
    developerName: doc.developerName || doc.developerAccount || 'Desenvolvedor',
    createdAt: doc.createdAt || null, rejectionReason: doc.rejectionReason || '',
  };
}

app.get('/api/admin/submissions', requireAdmin, async (req, res) => {
  try {
    const requestedStatus = String(req.query.status || 'pending');
    const query = requestedStatus === 'all' ? {} : { status: ['pending', 'approved', 'rejected'].includes(requestedStatus) ? requestedStatus : 'pending' };
    const docs = await submissionsCollection.find(query).sort({ createdAt: -1 }).limit(200).toArray();
    res.set('Cache-Control', 'no-store');
    res.json(docs.map(submissionJson));
  } catch {
    res.status(503).json({ error: 'Não foi possível carregar as publicações.' });
  }
});

app.get('/api/admin/submissions/:id', requireAdmin, async (req, res) => {
  const id = parseObjectId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Identificador inválido.' });
  try {
    const doc = await submissionsCollection.findOne({ _id: id });
    if (!doc) return res.status(404).json({ error: 'Publicação não encontrada.' });
    res.set('Cache-Control', 'no-store');
    res.json(submissionJson(doc));
  } catch {
    res.status(503).json({ error: 'Não foi possível abrir a publicação.' });
  }
});

app.put('/api/admin/submissions/:id', requireAdmin, async (req, res) => {
  const id = parseObjectId(req.params.id);
  const payload = submissionPayload(req.body);
  if (!id) return res.status(400).json({ error: 'Identificador inválido.' });
  if (!payload) return res.status(400).json({ error: 'Confira nome, categoria, links HTTPS e descrição.' });
  try {
    const result = await submissionsCollection.updateOne(
      { _id: id, status: 'pending' },
      { $set: { ...payload, editedAt: new Date(), editedBy: req.authUser._id } },
    );
    if (result.matchedCount !== 1) return res.status(409).json({ error: 'Só é possível editar publicações aguardando análise.' });
    const updated = await submissionsCollection.findOne({ _id: id });
    res.json(submissionJson(updated));
  } catch {
    res.status(503).json({ error: 'Não foi possível salvar as alterações.' });
  }
});

app.post('/api/admin/submissions/:id/approve', requireAdmin, async (req, res) => {
  const id = parseObjectId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Identificador inválido.' });
  try {
    const submission = await submissionsCollection.findOne({ _id: id });
    if (!submission) return res.status(404).json({ error: 'Publicação não encontrada.' });
    if (submission.status === 'rejected') return res.status(409).json({ error: 'Uma publicação recusada não pode ser aprovada.' });
    const fields = submissionPayload(submission);
    if (!fields) return res.status(400).json({ error: 'Os dados da publicação estão incompletos.' });
    const submissionId = id.toString();
    await appsCollection.updateOne(
      { submissionId },
      { $set: { ...fields, slug: safeSlug(fields.name, id), submissionId, status: 'pending_publication', featured: false, developerAccount: submission.developerAccount || 'desenvolvedor-web' }, $setOnInsert: { createdAt: submission.createdAt || new Date() } },
      { upsert: true },
    );
    const publishedDoc = await appsCollection.findOne({ submissionId });
    const reviewedAt = new Date();
    if (submission.status !== 'approved') {
      const result = await submissionsCollection.updateOne(
        { _id: id, status: 'pending' },
        { $set: { status: 'approved', approvedAppId: publishedDoc._id, reviewedAt, reviewedBy: req.authUser._id } },
      );
      if (result.matchedCount !== 1) {
        const latest = await submissionsCollection.findOne({ _id: id });
        if (!latest || latest.status !== 'approved') return res.status(409).json({ error: 'A publicação mudou de estado. Atualize a lista e tente novamente.' });
      }
    }
    await appsCollection.updateOne({ submissionId }, { $set: { status: 'approved', approvedAt: reviewedAt } });
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, status: 'approved', appId: publishedDoc._id.toString() });
  } catch {
    return res.status(503).json({ error: 'Não foi possível aprovar esta publicação agora.' });
  }
});

app.post('/api/admin/submissions/:id/reject', requireAdmin, async (req, res) => {
  const id = parseObjectId(req.params.id);
  const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 300) : '';
  if (!id) return res.status(400).json({ error: 'Identificador inválido.' });
  try {
    const result = await submissionsCollection.updateOne(
      { _id: id, status: 'pending' },
      { $set: { status: 'rejected', rejectionReason: reason, reviewedAt: new Date(), reviewedBy: req.authUser._id } },
    );
    if (result.matchedCount !== 1) return res.status(409).json({ error: 'Só é possível recusar publicações aguardando análise.' });
    return res.json({ ok: true, status: 'rejected' });
  } catch {
    res.status(503).json({ error: 'Não foi possível recusar esta publicação agora.' });
  }
});

app.get('/api/admin/developers', requireAdmin, async (_req, res) => {
  try {
    const docs = await usersCollection.find({}, { projection: { account: 1, email: 1, role: 1, developerStatus: 1, developerName: 1, developerRequestedAt: 1, createdAt: 1 } })
      .sort({ developerRequestedAt: -1, createdAt: -1 }).limit(300).toArray();
    res.set('Cache-Control', 'no-store');
    res.json(docs.map((user) => ({ id: user._id.toString(), account: user.account, email: user.email, role: user.role || 'user', developerStatus: user.developerStatus || 'none', developerName: user.developerName || '', createdAt: user.createdAt || null, requestedAt: user.developerRequestedAt || null })));
  } catch {
    res.status(503).json({ error: 'Não foi possível carregar os desenvolvedores.' });
  }
});

app.put('/api/admin/developers/:id', requireAdmin, async (req, res) => {
  const id = parseObjectId(req.params.id);
  const developerStatus = req.body?.developerStatus;
  const developerNameInput = req.body?.developerName;
  if (!id) return res.status(400).json({ error: 'Identificador inválido.' });
  if (!['none', 'pending', 'active', 'suspended', 'rejected'].includes(developerStatus)) return res.status(400).json({ error: 'Estado de desenvolvedor inválido.' });
  if (typeof developerNameInput !== 'string') return res.status(400).json({ error: 'Informe o nome público, ou deixe-o vazio para removê-lo.' });
  const developerName = developerNameInput.trim();
  if (developerName.length > 80) return res.status(400).json({ error: 'O nome público deve ter até 80 caracteres.' });
  try {
    const existing = await usersCollection.findOne({ _id: id }, { projection: { role: 1 } });
    if (!existing) return res.status(404).json({ error: 'Conta não encontrada.' });
    if (existing.role === 'admin') return res.status(409).json({ error: 'Não é possível alterar o desenvolvedor administrador por esta tela.' });
    const update = { $set: { developerStatus, developerUpdatedAt: new Date(), developerUpdatedBy: req.authUser._id } };
    if (developerName) update.$set.developerName = developerName;
    else update.$unset = { developerName: '' };
    if (developerStatus === 'active') update.$set.developerApprovedAt = new Date();
    const result = await usersCollection.updateOne({ _id: id }, update);
    if (result.matchedCount !== 1) return res.status(404).json({ error: 'Conta não encontrada.' });
    const user = await usersCollection.findOne({ _id: id }, { projection: { account: 1, email: 1, developerStatus: 1, developerName: 1 } });
    return res.json({ id: user._id.toString(), account: user.account, email: user.email, developerStatus: user.developerStatus, developerName: user.developerName || '' });
  } catch {
    res.status(503).json({ error: 'Não foi possível atualizar o desenvolvedor.' });
  }
});

app.use(express.static(__dirname, { extensions: ['html'], maxAge: '1h' }));
app.get(/.*/, (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

async function start() {
  await client.connect();
  const db = client.db(process.env.MONGODB_DB || 'san_store');
  appsCollection = db.collection('apps');
  usersCollection = db.collection('users');
  sessionsCollection = db.collection('sessions');
  submissionsCollection = db.collection('submissions');
  settingsCollection = db.collection('settings');
  dummyPasswordHash = await hashPassword(crypto.randomBytes(32).toString('hex'));
  await Promise.all([
    appsCollection.createIndex({ createdAt: -1 }),
    appsCollection.createIndex({ slug: 1 }, { unique: true, sparse: true }),
    appsCollection.createIndex({ submissionId: 1 }, { unique: true, sparse: true }),
    usersCollection.createIndex({ account: 1 }, { unique: true }),
    usersCollection.createIndex({ email: 1 }, { unique: true }),
    sessionsCollection.createIndex({ tokenHash: 1 }, { unique: true }),
    sessionsCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    sessionsCollection.createIndex({ userId: 1 }),
    submissionsCollection.createIndex({ status: 1, createdAt: -1 }),
    submissionsCollection.createIndex({ submittedBy: 1, createdAt: -1 }),
  ]);
  await settingsCollection.updateOne(
    { _id: 'admin_bootstrap' },
    { $setOnInsert: { claimed: false, createdAt: new Date() } },
    { upsert: true },
  );
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
