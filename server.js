const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3457;
const DATA_FILE = path.join(__dirname, 'data', 'wishlists.json');
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── DB helpers ───
function readDB() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) { return {}; }
}
function writeDB(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}
function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) { return {}; }
}
function writeUsers(data) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// ─── Crypto helpers ───
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const hashBuf = crypto.scryptSync(password, salt, 64);
    return crypto.timingSafeEqual(hashBuf, Buffer.from(hash, 'hex'));
  } catch { return false; }
}
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ─── Auth middleware ───
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Non authentifié' });
  }
  const token = auth.slice(7);
  const users = readUsers();
  const user = Object.values(users).find(u => u.token === token);
  if (!user) return res.status(401).json({ error: 'Token invalide ou expiré' });
  req.user = user;
  next();
}

// ─── Affiliate URL helper ───
function buildAffiliateUrl(url) {
  if (!url || !url.includes('amazon.fr')) return url;
  try {
    const u = new URL(url);
    u.searchParams.set('tag', 'thedanyg-21');
    return u.toString();
  } catch (e) {
    return url;
  }
}

// ════════════════════════════════════════
//  AUTH ENDPOINTS
// ════════════════════════════════════════

// POST /api/register — inscription (crée compte + wishlist en une fois)
app.post('/api/register', (req, res) => {
  const { username, displayName, bio, emoji, items, password } = req.body;

  if (!username || !displayName || !password) {
    return res.status(400).json({ error: 'username, displayName et password sont requis' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Mot de passe trop court (6 caractères min)' });
  }

  const slug = username.toLowerCase().replace(/[^a-z0-9_-]/g, '');
  if (!slug) return res.status(400).json({ error: 'username invalide' });

  const db = readDB();
  const users = readUsers();

  if (db[slug]) return res.status(409).json({ error: 'Ce username est déjà pris' });

  // Create wishlist
  const newWishlist = {
    username: slug,
    displayName,
    bio: bio || '',
    emoji: emoji || '🎁',
    items: (items || []).map((item, i) => ({
      id: String(Date.now() + i),
      name: item.name || 'Cadeau mystère',
      url: item.url || '',
      price: item.price || '',
      addedAt: new Date().toISOString().split('T')[0]
    })),
    createdAt: new Date().toISOString().split('T')[0]
  };

  // Create user account
  const token = generateToken();
  users[slug] = {
    username: slug,
    passwordHash: hashPassword(password),
    token,
    createdAt: new Date().toISOString()
  };

  db[slug] = newWishlist;
  writeDB(db);
  writeUsers(users);

  res.status(201).json({ token, username: slug, wishlist: newWishlist });
});

// POST /api/login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username et password requis' });

  const slug = username.toLowerCase().trim();
  const users = readUsers();
  const user = users[slug];

  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

  // Rotate token on login
  user.token = generateToken();
  writeUsers(users);

  res.json({ token: user.token, username: slug });
});

// POST /api/logout
app.post('/api/logout', requireAuth, (req, res) => {
  const users = readUsers();
  users[req.user.username].token = null;
  writeUsers(users);
  res.json({ ok: true });
});

// GET /api/me — current user info
app.get('/api/me', requireAuth, (req, res) => {
  const db = readDB();
  const wishlist = db[req.user.username] || null;
  res.json({ username: req.user.username, wishlist });
});

// ════════════════════════════════════════
//  WISHLIST ENDPOINTS
// ════════════════════════════════════════

// GET /api/wishlists/:username — public
app.get('/api/wishlists/:username', (req, res) => {
  const db = readDB();
  const wishlist = db[req.params.username.toLowerCase()];
  if (!wishlist) return res.status(404).json({ error: 'Wishlist non trouvée' });
  res.json({
    ...wishlist,
    items: wishlist.items.map(item => ({
      ...item,
      affiliateUrl: buildAffiliateUrl(item.url)
    }))
  });
});

// POST /api/wishlists — legacy (kept for compatibility, now use /api/register)
app.post('/api/wishlists', (req, res) => {
  // Redirect to register if password provided, else legacy create
  if (req.body.password) {
    return res.status(301).json({ error: 'Utilise /api/register pour créer un compte', redirect: '/api/register' });
  }
  const { username, displayName, bio, emoji, items } = req.body;
  if (!username || !displayName) return res.status(400).json({ error: 'username et displayName sont requis' });
  const slug = username.toLowerCase().replace(/[^a-z0-9_-]/g, '');
  const db = readDB();
  if (db[slug]) return res.status(409).json({ error: 'Ce username est déjà pris' });
  const newWishlist = {
    username: slug, displayName,
    bio: bio || '', emoji: emoji || '🎁',
    items: (items || []).map((item, i) => ({
      id: String(Date.now() + i),
      name: item.name || 'Cadeau mystère', url: item.url || '', price: item.price || '',
      addedAt: new Date().toISOString().split('T')[0]
    })),
    createdAt: new Date().toISOString().split('T')[0]
  };
  db[slug] = newWishlist;
  writeDB(db);
  res.status(201).json(newWishlist);
});

// PUT /api/wishlists/:username — update wishlist (auth required)
app.put('/api/wishlists/:username', requireAuth, (req, res) => {
  const slug = req.params.username.toLowerCase();
  if (req.user.username !== slug) return res.status(403).json({ error: 'Non autorisé' });

  const db = readDB();
  if (!db[slug]) return res.status(404).json({ error: 'Wishlist non trouvée' });

  const { displayName, bio, emoji } = req.body;
  if (displayName) db[slug].displayName = displayName;
  if (bio !== undefined) db[slug].bio = bio;
  if (emoji) db[slug].emoji = emoji;
  writeDB(db);
  res.json(db[slug]);
});

// POST /api/wishlists/:username/items — add item (auth required)
app.post('/api/wishlists/:username/items', requireAuth, (req, res) => {
  const slug = req.params.username.toLowerCase();
  if (req.user.username !== slug) return res.status(403).json({ error: 'Non autorisé' });

  const db = readDB();
  if (!db[slug]) return res.status(404).json({ error: 'Wishlist non trouvée' });

  const { name, url, price } = req.body;
  const newItem = {
    id: String(Date.now()),
    name: name || 'Cadeau mystère', url: url || '', price: price || '',
    addedAt: new Date().toISOString().split('T')[0]
  };
  db[slug].items.push(newItem);
  writeDB(db);
  res.status(201).json(newItem);
});

// DELETE /api/wishlists/:username/items/:itemId — remove item (auth required)
app.delete('/api/wishlists/:username/items/:itemId', requireAuth, (req, res) => {
  const slug = req.params.username.toLowerCase();
  if (req.user.username !== slug) return res.status(403).json({ error: 'Non autorisé' });

  const db = readDB();
  if (!db[slug]) return res.status(404).json({ error: 'Wishlist non trouvée' });

  db[slug].items = db[slug].items.filter(i => i.id !== req.params.itemId);
  writeDB(db);
  res.json({ ok: true });
});

// ─── SPA fallback ───
app.get('/:username', (req, res) => {
  if (req.params.username.startsWith('api')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🎁 OffreMoi running at http://localhost:${PORT}`);
});
