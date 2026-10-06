require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { MongoClient } = require('mongodb');
const path = require('path');

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

app.use(express.static(__dirname, { extensions: ['html'], maxAge: '1h' }));
app.get(/.*/, (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

async function start() {
  await client.connect();
  const db = client.db(process.env.MONGODB_DB || 'san_store');
  appsCollection = db.collection('apps');
  await Promise.all([
    appsCollection.createIndex({ createdAt: -1 }),
    appsCollection.createIndex({ slug: 1 }, { unique: true, sparse: true }),
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
