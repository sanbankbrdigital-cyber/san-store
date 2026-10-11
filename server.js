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
let reviewsCollection;
let appAppealsCollection;
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
app.use(express.json({ limit: '8mb' }));
const readLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 180, standardHeaders: 'draft-8', legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false });
const publishLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
const APP_SUBCATEGORIES = new Set(['Educação', 'Finanças', 'Ferramentas', 'Redes sociais', 'Entretenimento', 'Saúde', 'Produtividade']);

function validSubcategory(value) {
  return value === '' || APP_SUBCATEGORIES.has(value);
}

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

app.get('/api/admin/apps', requireAdmin, async (_req, res) => {
  try {
    const docs = await appsCollection.find(
      { $or: [{ status: { $exists: false } }, { status: 'approved' }] },
      { projection: { slug: 1, name: 1, category: 1, subcategory: 1, image: 1, developerName: 1, developerAccount: 1, blocked: 1, blockReason: 1, createdAt: 1 } },
    ).sort({ createdAt: -1 }).limit(500).toArray();
    res.set('Cache-Control', 'no-store');
    return res.json(docs.map((doc) => ({
      id: doc.slug || doc._id.toString(), name: doc.name, category: doc.category,
      subcategory: doc.subcategory || '', image: doc.image,
      developerName: doc.developerName || doc.developerAccount || 'Publicador não informado',
      blocked: Boolean(doc.blocked), blockReason: doc.blockReason || '',
    })));
  } catch {
    return res.status(503).json({ error: 'Não foi possível carregar os aplicativos da loja.' });
  }
});

app.get('/api/admin/apps/:appId', requireAdmin, async (req, res) => {
  const appId = String(req.params.appId || '');
  if (!/^[A-Za-z0-9_-]{1,120}$/.test(appId)) return res.status(400).json({ error: 'Identificador do aplicativo inválido.' });
  try {
    const doc = await findPublishedAppByPublicId(appId);
    if (!doc) return res.status(404).json({ error: 'Aplicativo publicado não encontrado.' });
    res.set('Cache-Control', 'no-store');
    return res.json({
      id: doc.slug || doc._id.toString(), name: doc.name, category: doc.category,
      subcategory: doc.subcategory || '', image: doc.image, apk: doc.apk,
      description: doc.description || '', whatsNew: doc.whatsNew || '',
      screenshots: Array.isArray(doc.screenshots) ? doc.screenshots : [],
      developerName: doc.developerName || doc.developerAccount || 'Publicador não informado',
      blocked: Boolean(doc.blocked), blockReason: doc.blockReason || '', featured: Boolean(doc.featured),
    });
  } catch {
    return res.status(503).json({ error: 'Não foi possível carregar os dados do aplicativo.' });
  }
});

app.put('/api/admin/apps/:appId', requireAdmin, async (req, res) => {
  const appId = String(req.params.appId || '');
  const fields = submissionPayload(req.body);
  if (!/^[A-Za-z0-9_-]{1,120}$/.test(appId)) return res.status(400).json({ error: 'Identificador do aplicativo inválido.' });
  if (!fields) return res.status(400).json({ error: 'Confira nome, tipo, categoria, links HTTPS, descrição, novidades e capturas PNG.' });
  try {
    const doc = await findPublishedAppByPublicId(appId);
    if (!doc) return res.status(404).json({ error: 'Aplicativo publicado não encontrado.' });
    const updatedFields = {
      name: fields.name, category: fields.category, subcategory: fields.subcategory,
      image: fields.image, apk: fields.apk, description: fields.description,
      whatsNew: fields.whatsNew, updatedAt: new Date(), updatedBy: req.authUser._id,
      ...(fields.screenshots ? { screenshots: fields.screenshots } : {}),
    };
    const result = await appsCollection.updateOne(
      { _id: doc._id, $or: [{ status: { $exists: false } }, { status: 'approved' }] },
      { $set: updatedFields },
    );
    if (result.matchedCount !== 1) return res.status(409).json({ error: 'O aplicativo mudou de estado. Atualize a lista e tente novamente.' });
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, id: doc.slug || doc._id.toString(), message: 'Alterações salvas no aplicativo publicado.' });
  } catch {
    return res.status(503).json({ error: 'Não foi possível salvar as alterações do aplicativo.' });
  }
});

app.post('/api/admin/apps/:appId/block', requireAdmin, async (req, res) => {
  const appId = String(req.params.appId || '');
  const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : '';
  if (!/^[A-Za-z0-9_-]{1,120}$/.test(appId)) return res.status(400).json({ error: 'Identificador do aplicativo inválido.' });
  if (reason.length > 300) return res.status(400).json({ error: 'O aviso pode ter até 300 caracteres.' });
  try {
    const doc = await findPublishedAppByPublicId(appId);
    if (!doc) return res.status(404).json({ error: 'Aplicativo publicado não encontrado.' });
    const result = await appsCollection.updateOne(
      { _id: doc._id, $or: [{ status: { $exists: false } }, { status: 'approved' }] },
      { $set: { blocked: true, blockReason: reason, blockedAt: new Date(), blockedBy: req.authUser._id } },
    );
    if (result.matchedCount !== 1) return res.status(409).json({ error: 'O aplicativo mudou de estado. Atualize a lista e tente novamente.' });
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, id: doc.slug || doc._id.toString(), blocked: true, blockReason: reason });
  } catch {
    return res.status(503).json({ error: 'Não foi possível bloquear o aplicativo agora.' });
  }
});

app.post('/api/admin/apps/:appId/unblock', requireAdmin, async (req, res) => {
  const appId = String(req.params.appId || '');
  if (!/^[A-Za-z0-9_-]{1,120}$/.test(appId)) return res.status(400).json({ error: 'Identificador do aplicativo inválido.' });
  try {
    const doc = await findPublishedAppByPublicId(appId);
    if (!doc) return res.status(404).json({ error: 'Aplicativo publicado não encontrado.' });
    const result = await appsCollection.updateOne(
      { _id: doc._id, $or: [{ status: { $exists: false } }, { status: 'approved' }] },
      { $set: { blocked: false }, $unset: { blockReason: '', blockedAt: '', blockedBy: '' } },
    );
    if (result.matchedCount !== 1) return res.status(409).json({ error: 'O aplicativo mudou de estado. Atualize a lista e tente novamente.' });
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, id: doc.slug || doc._id.toString(), blocked: false });
  } catch {
    return res.status(503).json({ error: 'Não foi possível liberar o aplicativo agora.' });
  }
});

function appealJson(doc) {
  return {
    id: doc._id.toString(), appId: doc.publicAppId || doc.appId.toString(),
    appName: doc.appName || 'Aplicativo', developerAccount: doc.developerAccount || '',
    developerName: doc.developerName || doc.developerAccount || 'Desenvolvedor',
    message: doc.message || '', status: doc.status || 'pending',
    createdAt: doc.createdAt || null, reviewedAt: doc.reviewedAt || null,
    reviewReason: doc.reviewReason || '',
  };
}

app.get('/api/admin/appeals', requireAdmin, async (req, res) => {
  try {
    const requestedStatus = String(req.query.status || 'pending');
    const query = requestedStatus === 'all' ? {} : { status: ['pending', 'approved', 'rejected'].includes(requestedStatus) ? requestedStatus : 'pending' };
    const docs = await appAppealsCollection.find(query).sort({ createdAt: -1 }).limit(300).toArray();
    res.set('Cache-Control', 'no-store');
    return res.json(docs.map(appealJson));
  } catch {
    return res.status(503).json({ error: 'Não foi possível carregar as apelações.' });
  }
});

app.post('/api/admin/appeals/:id/approve', requireAdmin, async (req, res) => {
  const id = parseObjectId(req.params.id);
  const reviewReason = typeof req.body?.reviewReason === 'string' ? req.body.reviewReason.trim().slice(0, 300) : '';
  if (!id) return res.status(400).json({ error: 'Identificador da apelação inválido.' });
  try {
    const appeal = await appAppealsCollection.findOne({ _id: id, status: 'pending' });
    if (!appeal) return res.status(404).json({ error: 'Apelação pendente não encontrada.' });
    const claim = await appAppealsCollection.updateOne(
      { _id: id, status: 'pending' },
      { $set: { status: 'approved', reviewedAt: new Date(), reviewedBy: req.authUser._id, reviewReason } },
    );
    if (claim.matchedCount !== 1) return res.status(409).json({ error: 'Esta apelação já foi analisada.' });
    const unblocked = await appsCollection.updateOne(
      { _id: appeal.appId, developerAccount: appeal.developerAccount, blocked: true, $or: [{ status: { $exists: false } }, { status: 'approved' }] },
      { $set: { blocked: false }, $unset: { blockReason: '', blockedAt: '', blockedBy: '' } },
    );
    if (unblocked.matchedCount !== 1) {
      await appAppealsCollection.updateOne(
        { _id: id, status: 'approved', reviewedBy: req.authUser._id },
        { $set: { status: 'pending' }, $unset: { reviewedAt: '', reviewedBy: '', reviewReason: '' } },
      );
      return res.status(409).json({ error: 'O app não está mais bloqueado; atualize a lista de apelações.' });
    }
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, status: 'approved', appId: appeal.publicAppId, message: 'Apelação aprovada; downloads liberados.' });
  } catch {
    return res.status(503).json({ error: 'Não foi possível aprovar a apelação agora.' });
  }
});

app.post('/api/admin/appeals/:id/reject', requireAdmin, async (req, res) => {
  const id = parseObjectId(req.params.id);
  const reviewReason = typeof req.body?.reviewReason === 'string' ? req.body.reviewReason.trim().slice(0, 300) : '';
  if (!id) return res.status(400).json({ error: 'Identificador da apelação inválido.' });
  try {
    const appeal = await appAppealsCollection.findOne({ _id: id, status: 'pending' });
    if (!appeal) return res.status(404).json({ error: 'Apelação pendente não encontrada.' });
    const claim = await appAppealsCollection.updateOne(
      { _id: id, status: 'pending' },
      { $set: { status: 'rejected', reviewedAt: new Date(), reviewedBy: req.authUser._id, reviewReason } },
    );
    if (claim.matchedCount !== 1) return res.status(409).json({ error: 'Esta apelação já foi analisada.' });
    const removal = await appsCollection.updateOne(
      { _id: appeal.appId, developerAccount: appeal.developerAccount, blocked: true, $or: [{ status: { $exists: false } }, { status: 'approved' }] },
      { $set: { status: 'removed', blocked: true, removedAt: new Date(), removedBy: req.authUser._id, removalReason: reviewReason || 'Apelação de desbloqueio recusada.' } },
    );
    if (removal.matchedCount !== 1) {
      await appAppealsCollection.updateOne(
        { _id: id, status: 'rejected', reviewedBy: req.authUser._id },
        { $set: { status: 'pending' }, $unset: { reviewedAt: '', reviewedBy: '', reviewReason: '' } },
      );
      return res.status(409).json({ error: 'O app mudou de estado; atualize a lista de apelações.' });
    }
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, status: 'rejected', appId: appeal.publicAppId, removed: true, message: 'Apelação recusada; app removido do catálogo.' });
  } catch {
    return res.status(503).json({ error: 'Não foi possível recusar a apelação agora.' });
  }
});

app.get('/api/developer/me', requireUser, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    status: req.authUser.developerStatus || 'none',
    developerName: req.authUser.developerName || '',
    developerAccount: req.authUser.account || '',
  });
});

app.get('/api/developer/apps', requireDeveloper, async (req, res) => {
  try {
    const docs = await appsCollection.find({
      developerAccount: req.authUser.account,
      $or: [{ status: { $exists: false } }, { status: 'approved' }, { status: 'removed' }],
    }, { projection: { slug: 1, name: 1, category: 1, subcategory: 1, image: 1, apk: 1, description: 1, whatsNew: 1, featured: 1, developerName: 1, status: 1, blocked: 1, blockReason: 1 } })
      .sort({ createdAt: -1 }).limit(200).toArray();
    const ids = docs.map((doc) => doc._id);
    const updates = ids.length
      ? await submissionsCollection.find({ targetAppId: { $in: ids }, submissionType: 'update' }).sort({ createdAt: -1 }).toArray()
      : [];
    const appeals = ids.length
      ? await appAppealsCollection.find({ appId: { $in: ids }, developerAccount: req.authUser.account }).sort({ createdAt: -1 }).toArray()
      : [];
    const latestByApp = new Map();
    for (const update of updates) {
      const key = update.targetAppId.toString();
      if (!latestByApp.has(key)) latestByApp.set(key, update);
    }
    const latestAppealByApp = new Map();
    for (const appeal of appeals) {
      const key = appeal.appId.toString();
      if (!latestAppealByApp.has(key)) latestAppealByApp.set(key, appeal);
    }
    res.set('Cache-Control', 'no-store');
    return res.json(docs.map((doc) => {
      const appKey = doc._id.toString();
      const latest = latestByApp.get(appKey);
      const appeal = latestAppealByApp.get(appKey);
      const removed = doc.status === 'removed';
      return {
        id: doc.slug || appKey, name: doc.name, category: doc.category,
        subcategory: doc.subcategory || '', image: doc.image,
        apk: doc.blocked || removed ? '' : doc.apk, description: doc.description,
        whatsNew: doc.whatsNew || '', featured: Boolean(doc.featured),
        developerName: doc.developerName || req.authUser.developerName || req.authUser.account,
        blocked: Boolean(doc.blocked), blockReason: doc.blockReason || '',
        status: doc.status || 'approved', removed,
        appealStatus: appeal?.status || '', appealId: appeal?._id.toString() || '',
        appealMessage: appeal?.message || '', appealReviewReason: appeal?.reviewReason || '',
        pendingUpdate: Boolean(latest && latest.status === 'pending'),
        latestUpdateStatus: latest?.status || '',
        rejectionReason: latest?.status === 'rejected' ? latest.rejectionReason || '' : '',
      };
    }));
  } catch {
    return res.status(503).json({ error: 'Não foi possível carregar seus aplicativos publicados.' });
  }
});

app.post('/api/developer/apps/:appId/appeal', publishLimiter, requireDeveloper, async (req, res) => {
  const appId = String(req.params.appId || '');
  const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
  if (!/^[A-Za-z0-9_-]{1,120}$/.test(appId)) return res.status(400).json({ error: 'Identificador do aplicativo inválido.' });
  if (message.length < 10 || message.length > 1000) return res.status(400).json({ error: 'Explique o pedido em 10 a 1000 caracteres.' });
  try {
    const storeApp = await findPublishedAppByPublicId(appId);
    if (!storeApp || storeApp.developerAccount !== req.authUser.account) return res.status(404).json({ error: 'Aplicativo bloqueado não encontrado nesta conta.' });
    if (!storeApp.blocked) return res.status(409).json({ error: 'Este aplicativo não está bloqueado; não precisa de apelação.' });
    const pending = await appAppealsCollection.findOne({ appId: storeApp._id, status: 'pending' });
    if (pending) return res.status(409).json({ error: 'Já existe uma apelação aguardando análise para este aplicativo.' });
    const now = new Date();
    const appeal = {
      appId: storeApp._id, publicAppId: storeApp.slug || storeApp._id.toString(),
      appName: storeApp.name, developerAccount: req.authUser.account,
      developerName: storeApp.developerName || req.authUser.developerName || req.authUser.account,
      message, status: 'pending', createdAt: now, submittedBy: req.authUser._id,
    };
    const result = await appAppealsCollection.insertOne(appeal);
    res.set('Cache-Control', 'no-store');
    return res.status(202).json({ id: result.insertedId.toString(), status: 'pending', message: 'Apelação enviada para análise do administrador.' });
  } catch (error) {
    if (error && error.code === 11000) return res.status(409).json({ error: 'Já existe uma apelação aguardando análise para este aplicativo.' });
    return res.status(503).json({ error: 'Não foi possível enviar a apelação agora.' });
  }
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
    const docs = await appsCollection.find({ $or: [{ status: { $exists: false } }, { status: 'approved' }] }, { projection: { slug: 1, name: 1, category: 1, subcategory: 1, image: 1, apk: 1, description: 1, whatsNew: 1, createdAt: 1, featured: 1, developerName: 1, developerAccount: 1, blocked: 1, blockReason: 1 } })
      .sort({ createdAt: -1 }).limit(500).toArray();
    res.set('Cache-Control', 'no-store');
    res.json(docs.map((doc) => ({
      id: doc.slug || doc._id.toString(), name: doc.name, category: doc.category,
      subcategory: doc.subcategory || '', image: doc.image, apk: doc.blocked ? '' : doc.apk, description: doc.description,
      whatsNew: doc.whatsNew || '', featured: Boolean(doc.featured), blocked: Boolean(doc.blocked),
      blockReason: doc.blockReason || '',
      developerName: doc.developerName || doc.developerAccount || 'Publicador não informado',
    })));
  } catch (error) {
    console.error('Could not list apps:', error.message);
    res.status(503).json({ error: 'O catálogo está temporariamente indisponível.' });
  }
});

app.get('/api/apps/:appId/screenshots', readLimiter, async (req, res) => {
  const appId = String(req.params.appId || '');
  if (!/^[A-Za-z0-9_-]{1,120}$/.test(appId)) return res.status(400).json({ error: 'Identificador do aplicativo inválido.' });
  try {
    const storeApp = await findPublishedAppByPublicId(appId);
    if (!storeApp) return res.status(404).json({ error: 'Aplicativo não encontrado na loja.' });
    res.set('Cache-Control', 'no-store');
    return res.json({ appId, screenshots: Array.isArray(storeApp.screenshots) ? storeApp.screenshots : [] });
  } catch {
    return res.status(503).json({ error: 'Não foi possível carregar as capturas de tela.' });
  }
});

app.get('/api/apps/:appId/reviews', readLimiter, async (req, res) => {
  const appId = String(req.params.appId || '');
  if (!/^[A-Za-z0-9_-]{1,120}$/.test(appId)) return res.status(400).json({ error: 'Identificador do aplicativo inválido.' });
  try {
    const storeApp = await findPublishedAppByPublicId(appId);
    if (!storeApp) return res.status(404).json({ error: 'Aplicativo não encontrado na loja.' });
    const [stats] = await reviewsCollection.aggregate([
      { $match: { appId } },
      { $group: { _id: null, averageRating: { $avg: '$rating' }, reviewCount: { $sum: 1 } } },
    ]).toArray();
    const docs = await reviewsCollection.find({ appId })
      .sort({ updatedAt: -1 }).limit(50).toArray();
    res.set('Cache-Control', 'no-store');
    return res.json({
      appId,
      averageRating: stats ? Math.round(stats.averageRating * 10) / 10 : 0,
      reviewCount: stats?.reviewCount || 0,
      reviews: docs.map((review) => ({
        rating: review.rating,
        reviewerName: review.reviewerName || 'Usuário',
        comment: review.comment,
        createdAt: review.updatedAt || review.createdAt || null,
      })),
    });
  } catch {
    return res.status(503).json({ error: 'Não foi possível carregar as avaliações agora.' });
  }
});

app.post('/api/apps/:appId/reviews', publishLimiter, requireUser, async (req, res) => {
  const appId = String(req.params.appId || '');
  const rating = Number(req.body?.rating);
  const comment = typeof req.body?.comment === 'string' ? req.body.comment.trim() : '';
  if (!/^[A-Za-z0-9_-]{1,120}$/.test(appId)) return res.status(400).json({ error: 'Identificador do aplicativo inválido.' });
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).json({ error: 'Escolha uma nota de 1 a 5 estrelas.' });
  if (comment.length < 3 || comment.length > 500) return res.status(400).json({ error: 'A avaliação deve ter de 3 a 500 caracteres.' });
  try {
    const storeApp = await findPublishedAppByPublicId(appId);
    if (!storeApp) return res.status(404).json({ error: 'Aplicativo não encontrado na loja.' });
    const now = new Date();
    await reviewsCollection.updateOne(
      { appId, userId: req.authUser._id },
      { $set: { rating, comment, reviewerName: req.authUser.developerName || req.authUser.account || 'Usuário', updatedAt: now },
        $setOnInsert: { createdAt: now } },
      { upsert: true },
    );
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, message: 'Sua avaliação foi publicada.' });
  } catch {
    return res.status(503).json({ error: 'Não foi possível publicar a avaliação agora.' });
  }
});

app.post('/api/submissions', publishLimiter, requireDeveloper, async (req, res) => {
  const payload = submissionPayload(req.body);
  const requestedAppId = typeof req.body?.appId === 'string' ? req.body.appId.trim() : '';
  if (!payload || (!requestedAppId && !Array.isArray(payload.screenshots))) {
    return res.status(400).json({ error: 'Confira os dados e envie de 2 a 8 capturas PNG válidas (até 512 KB cada).' });
  }
  if (requestedAppId && !/^[A-Za-z0-9_-]{1,120}$/.test(requestedAppId)) {
    return res.status(400).json({ error: 'Identificador do aplicativo inválido.' });
  }
  try {
    let targetApp = null;
    if (requestedAppId) {
      targetApp = await findPublishedAppByPublicId(requestedAppId);
      if (!targetApp || targetApp.developerAccount !== req.authUser.account) {
        return res.status(404).json({ error: 'Aplicativo publicado não encontrado nesta conta de desenvolvedor.' });
      }
      const pendingUpdate = await submissionsCollection.findOne({
        targetAppId: targetApp._id, submissionType: 'update', status: 'pending',
      }, { projection: { _id: 1 } });
      if (pendingUpdate) return res.status(409).json({ error: 'Já existe uma atualização deste aplicativo aguardando aprovação.' });
      payload.name = targetApp.name;
      payload.category = targetApp.category;
      payload.subcategory = targetApp.subcategory || '';
    }
    const submission = {
      ...payload,
      status: 'pending',
      submissionType: targetApp ? 'update' : 'new',
      submittedBy: req.authUser._id,
      developerAccount: req.authUser.account,
      developerName: req.authUser.developerName || req.authUser.account,
      createdAt: new Date(),
    };
    if (targetApp) submission.targetAppId = targetApp._id;
    const result = await submissionsCollection.insertOne(submission);
    res.set('Cache-Control', 'no-store');
    return res.status(202).json({
      id: result.insertedId.toString(), status: 'pending', submissionType: submission.submissionType,
      message: targetApp ? 'Atualização enviada para aprovação do administrador.' : 'Enviado para aprovação do administrador.',
    });
  } catch (error) {
    if (error && error.code === 11000) return res.status(409).json({ error: 'Já existe uma atualização deste aplicativo aguardando aprovação.' });
    return res.status(503).json({ error: 'Não foi possível enviar para aprovação agora.' });
  }
});

// Legacy web submissions are also queued for review; this route can no longer publish directly.
app.post('/api/apps', publishLimiter, publishAuth, async (req, res) => {
  const { name, category, image, apk, description } = req.body || {};
  const subcategory = typeof req.body?.subcategory === 'string' ? req.body.subcategory.trim() : '';
  const whatsNew = typeof req.body?.whatsNew === 'string' ? req.body.whatsNew.trim() : '';
  const developerName = typeof req.body?.developerName === 'string' ? req.body.developerName.trim() : '';
  if (developerName.length > 80 || whatsNew.length > 500) return res.status(400).json({ error: 'O nome do publicador deve ter até 80 caracteres e as novidades até 500.' });
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 60 ||
      !['App', 'Game'].includes(category) || !validSubcategory(subcategory) || !validHttpsUrl(image) || !validHttpsUrl(apk) ||
      typeof description !== 'string' || description.trim().length < 5 || description.trim().length > 350) {
    return res.status(400).json({ error: 'Confira nome, tipo, categoria, links HTTPS e descrição.' });
  }
  try {
    const submission = {
      name: name.trim(), category, subcategory,
      image: new URL(image).href, apk: new URL(apk).href,
      description: description.trim(), whatsNew, status: 'pending', submissionType: 'new',
      submittedBy: null, developerAccount: 'web-publisher', developerName: developerName || 'Desenvolvedor da loja',
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

async function findPublishedAppByPublicId(appId) {
  const identifiers = [{ slug: appId }];
  const objectId = parseObjectId(appId);
  if (objectId) identifiers.push({ _id: objectId });
  return appsCollection.findOne({
    $and: [
      { $or: [{ status: { $exists: false } }, { status: 'approved' }] },
      { $or: identifiers },
    ],
  });
}

function safeSlug(value, id) {
  const base = String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'app';
  return `${base}-${id.toString()}`;
}

const MIN_SCREENSHOTS = 2;
const MAX_SCREENSHOTS = 8;
const MAX_SCREENSHOT_BYTES = 512 * 1024;
const MAX_SCREENSHOTS_TOTAL_BYTES = 4 * 1024 * 1024;

function validateScreenshots(value) {
  if (!Array.isArray(value) || value.length < MIN_SCREENSHOTS || value.length > MAX_SCREENSHOTS) return null;
  const screenshots = [];
  let totalBytes = 0;
  const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  for (const encoded of value) {
    if (typeof encoded !== 'string' || encoded.length > Math.ceil(MAX_SCREENSHOT_BYTES / 3) * 4 || !base64Pattern.test(encoded)) return null;
    const bytes = Buffer.from(encoded, 'base64');
    if (bytes.length < 24 || bytes.length > MAX_SCREENSHOT_BYTES || bytes.toString('base64') !== encoded) return null;
    const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    if (!bytes.subarray(0, 8).equals(pngSignature) || bytes.toString('ascii', 12, 16) !== 'IHDR') return null;
    const width = bytes.readUInt32BE(16);
    const height = bytes.readUInt32BE(20);
    if (width < 1 || height < 1 || width > 5000 || height > 5000 || width * height > 20_000_000) return null;
    totalBytes += bytes.length;
    if (totalBytes > MAX_SCREENSHOTS_TOTAL_BYTES) return null;
    screenshots.push(encoded);
  }
  return screenshots;
}

function submissionPayload(body) {
  const { name, category, image, apk, description } = body || {};
  const subcategory = typeof body?.subcategory === 'string' ? body.subcategory.trim() : '';
  const whatsNew = typeof body?.whatsNew === 'string' ? body.whatsNew.trim() : '';
  const hasScreenshots = Object.prototype.hasOwnProperty.call(body || {}, 'screenshots');
  const screenshots = hasScreenshots ? validateScreenshots(body.screenshots) : undefined;
  if (whatsNew.length > 500 || (hasScreenshots && !screenshots)) return null;
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 60 ||
      !['App', 'Game'].includes(category) || !validSubcategory(subcategory) || !validHttpsUrl(image) || !validHttpsUrl(apk) ||
      typeof description !== 'string' || description.trim().length < 5 || description.trim().length > 350) return null;
  return {
    name: name.trim(), category, subcategory, image: new URL(image).href, apk: new URL(apk).href,
    description: description.trim(), whatsNew, ...(hasScreenshots ? { screenshots } : {}),
  };
}

function submissionJson(doc, includeScreenshots = false) {
  return {
    id: doc._id.toString(), name: doc.name, category: doc.category, subcategory: doc.subcategory || '', image: doc.image,
    apk: doc.apk, description: doc.description, whatsNew: doc.whatsNew || '', status: doc.status,
    submissionType: doc.submissionType || 'new', targetAppId: doc.targetAppId ? doc.targetAppId.toString() : '',
    developerAccount: doc.developerAccount || 'desenvolvedor-web',
    developerName: doc.developerName || doc.developerAccount || 'Desenvolvedor',
    createdAt: doc.createdAt || null, rejectionReason: doc.rejectionReason || '',
    ...(includeScreenshots ? { screenshots: doc.screenshots || [] } : {}),
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
    res.json(submissionJson(doc, true));
  } catch {
    res.status(503).json({ error: 'Não foi possível abrir a publicação.' });
  }
});

app.put('/api/admin/submissions/:id', requireAdmin, async (req, res) => {
  const id = parseObjectId(req.params.id);
  const payload = submissionPayload(req.body);
  if (!id) return res.status(400).json({ error: 'Identificador inválido.' });
  if (!payload) return res.status(400).json({ error: 'Confira nome, tipo, categoria, links HTTPS e descrição.' });
  try {
    const current = await submissionsCollection.findOne({ _id: id, status: 'pending' }, { projection: { subcategory: 1, whatsNew: 1 } });
    if (!current) return res.status(409).json({ error: 'Só é possível editar publicações aguardando análise.' });
    if (typeof req.body?.subcategory !== 'string') payload.subcategory = current.subcategory || '';
    if (typeof req.body?.whatsNew !== 'string') payload.whatsNew = current.whatsNew || '';
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
    const reviewedAt = new Date();

    if (submission.submissionType === 'update') {
      const targetId = submission.targetAppId;
      if (!targetId) return res.status(409).json({ error: 'O aplicativo original desta atualização não foi encontrado.' });
      const target = await appsCollection.findOne({ _id: targetId, developerAccount: submission.developerAccount, $or: [{ status: { $exists: false } }, { status: 'approved' }] });
      if (!target) return res.status(409).json({ error: 'O aplicativo original não está mais publicado nesta conta.' });
      const claim = await submissionsCollection.updateOne(
        { _id: id, status: 'pending' },
        { $set: { status: 'approved', approvedAppId: target._id, reviewedAt, reviewedBy: req.authUser._id } },
      );
      if (claim.matchedCount !== 1) return res.status(409).json({ error: 'A atualização mudou de estado. Atualize a lista e tente novamente.' });
      // Update only listing metadata: _id, public slug, reviews, and featured status remain untouched.
      const updated = await appsCollection.updateOne(
        { _id: target._id, developerAccount: submission.developerAccount, $or: [{ status: { $exists: false } }, { status: 'approved' }] },
        { $set: { image: fields.image, apk: fields.apk, description: fields.description, whatsNew: fields.whatsNew,
          ...(fields.screenshots ? { screenshots: fields.screenshots } : {}), updatedAt: reviewedAt } },
      );
      if (updated.matchedCount !== 1) {
        await submissionsCollection.updateOne({ _id: id, status: 'approved' }, { $set: { status: 'pending' }, $unset: { approvedAppId: '', reviewedAt: '', reviewedBy: '' } });
        return res.status(409).json({ error: 'O aplicativo original mudou de estado; a atualização continua aguardando análise.' });
      }
      res.set('Cache-Control', 'no-store');
      return res.json({ ok: true, status: 'approved', submissionType: 'update', appId: target.slug || target._id.toString() });
    }

    const submissionId = id.toString();
    await appsCollection.updateOne(
      { submissionId },
      { $set: { ...fields, slug: safeSlug(fields.name, id), submissionId, status: 'pending_publication', featured: false, developerAccount: submission.developerAccount || 'desenvolvedor-web', developerName: submission.developerName || submission.developerAccount || 'Publicador não informado' }, $setOnInsert: { createdAt: submission.createdAt || new Date() } },
      { upsert: true },
    );
    const publishedDoc = await appsCollection.findOne({ submissionId });
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
  reviewsCollection = db.collection('app_reviews');
  appAppealsCollection = db.collection('app_appeals');
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
    submissionsCollection.createIndex({ targetAppId: 1 }, { unique: true, partialFilterExpression: { status: 'pending', submissionType: 'update' } }),
    reviewsCollection.createIndex({ appId: 1, userId: 1 }, { unique: true }),
    reviewsCollection.createIndex({ appId: 1, updatedAt: -1 }),
    appAppealsCollection.createIndex({ status: 1, createdAt: -1 }),
    appAppealsCollection.createIndex({ appId: 1, createdAt: -1 }),
    appAppealsCollection.createIndex({ appId: 1 }, { unique: true, partialFilterExpression: { status: 'pending' } }),
  ]);
  await settingsCollection.updateOne(
    { _id: 'admin_bootstrap' },
    { $setOnInsert: { claimed: false, createdAt: new Date() } },
    { upsert: true },
  );
  await appsCollection.updateOne(
    { slug: 'sanbank-br-digital' },
    { $setOnInsert: {
      slug: 'sanbank-br-digital', name: 'SANBANK BR DIGITAL', category: 'App', subcategory: 'Finanças',
      image: 'https://i.ibb.co/Ld27J25H/shared-image-3.webp',
      apk: 'https://github.com/sanbankbrdigital-cyber/san-store/raw/refs/heads/main/SANBANK-BR-DIGITAL-NATIVO-COMPLETO-v3.1.51-sem-top-interbank-icon-ANDROID-5.0-A-17.apk',
      description: 'Aplicativo SANBANK BR DIGITAL para Android. Baixe e conheça os recursos do seu banco digital.',
      featured: true, createdAt: new Date(),
    } },
    { upsert: true },
  );
  await Promise.all([
    appsCollection.updateMany({ category: 'Game', subcategory: { $in: [null, ''] } }, { $set: { subcategory: 'Entretenimento' } }),
    appsCollection.updateMany({ category: 'App', name: /bank/i, subcategory: { $in: [null, ''] } }, { $set: { subcategory: 'Finanças' } }),
    appsCollection.updateMany({ category: 'App', name: /launch/i, subcategory: { $in: [null, ''] } }, { $set: { subcategory: 'Ferramentas' } }),
  ]);
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
