const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3457;
const DATA_FILE = path.join(__dirname, 'data', 'wishlists.json');
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const ORDERS_FILE = path.join(__dirname, 'data', 'orders.json');

// Encryption key for delivery addresses (32 bytes for AES-256)
const ADDR_KEY = process.env.ADDR_SECRET
  ? Buffer.from(process.env.ADDR_SECRET, 'hex')
  : crypto.scryptSync('offremoi-default-dev-key', 'salt-offremoi', 32);

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
function readOrders() {
  try { return JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8')); } catch (e) { return []; }
}
function writeOrders(data) {
  if (!fs.existsSync(path.dirname(ORDERS_FILE))) fs.mkdirSync(path.dirname(ORDERS_FILE), { recursive: true });
  fs.writeFileSync(ORDERS_FILE, JSON.stringify(data, null, 2), 'utf8');
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

// ─── Address encryption (AES-256-GCM) ───
function encryptAddress(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', ADDR_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + encrypted.toString('hex');
}
function decryptAddress(stored) {
  if (!stored) return null;
  try {
    const [ivHex, tagHex, encHex] = stored.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ADDR_KEY, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    return decipher.update(Buffer.from(encHex, 'hex')) + decipher.final('utf8');
  } catch { return null; }
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

// Admin token check (very simple for concierge MVP)
function requireAdmin(req, res, next) {
  const adminToken = process.env.ADMIN_TOKEN || 'offremoi-admin-dev';
  const token = req.headers['x-admin-token'];
  if (token !== adminToken) return res.status(403).json({ error: 'Accès refusé' });
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

// POST /api/register
app.post('/api/register', (req, res) => {
  const { username, displayName, bio, emoji, items, password, creatorType } = req.body;

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

  const newWishlist = {
    username: slug,
    displayName,
    bio: bio || '',
    emoji: emoji || '🎁',
    creatorType: creatorType || 'autre',
    items: (items || []).map((item, i) => ({
      id: String(Date.now() + i),
      name: item.name || 'Cadeau mystère',
      url: item.url || '',
      price: item.price || '',
      addedAt: new Date().toISOString().split('T')[0]
    })),
    createdAt: new Date().toISOString().split('T')[0]
  };

  const token = generateToken();
  users[slug] = {
    username: slug,
    passwordHash: hashPassword(password),
    token,
    creatorType: creatorType || 'autre',
    deliveryAddressEnc: null,  // set separately via /api/me/address
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

// GET /api/me — current user info (never returns address)
app.get('/api/me', requireAuth, (req, res) => {
  const db = readDB();
  const wishlist = db[req.user.username] || null;
  res.json({
    username: req.user.username,
    creatorType: req.user.creatorType || 'autre',
    hasAddress: !!req.user.deliveryAddressEnc,
    wishlist
  });
});

// PUT /api/me/address — store delivery address (encrypted)
app.put('/api/me/address', requireAuth, (req, res) => {
  const { fullName, line1, line2, postalCode, city, country } = req.body;
  if (!fullName || !line1 || !postalCode || !city) {
    return res.status(400).json({ error: 'Nom, adresse, code postal et ville sont requis' });
  }
  const plaintext = JSON.stringify({ fullName, line1, line2: line2 || '', postalCode, city, country: country || 'FR' });
  const users = readUsers();
  users[req.user.username].deliveryAddressEnc = encryptAddress(plaintext);
  writeUsers(users);
  res.json({ ok: true, hasAddress: true });
});

// DELETE /api/me/address — remove stored address
app.delete('/api/me/address', requireAuth, (req, res) => {
  const users = readUsers();
  users[req.user.username].deliveryAddressEnc = null;
  writeUsers(users);
  res.json({ ok: true, hasAddress: false });
});

// PUT /api/me/profile — update display name, bio, emoji, creatorType
app.put('/api/me/profile', requireAuth, (req, res) => {
  const { displayName, bio, emoji, creatorType } = req.body;
  const slug = req.user.username;
  const db = readDB();
  const users = readUsers();

  if (!db[slug]) return res.status(404).json({ error: 'Wishlist non trouvée' });

  if (displayName) { db[slug].displayName = displayName; }
  if (bio !== undefined) { db[slug].bio = bio; }
  if (emoji) { db[slug].emoji = emoji; }
  if (creatorType) {
    db[slug].creatorType = creatorType;
    users[slug].creatorType = creatorType;
  }
  writeDB(db);
  writeUsers(users);
  res.json({ ok: true, wishlist: db[slug] });
});

// ════════════════════════════════════════
//  WISHLIST ENDPOINTS
// ════════════════════════════════════════

// GET /api/wishlists/:username — public (no address ever)
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

// PUT /api/wishlists/:username — update wishlist metadata
app.put('/api/wishlists/:username', requireAuth, (req, res) => {
  const slug = req.params.username.toLowerCase();
  if (req.user.username !== slug) return res.status(403).json({ error: 'Non autorisé' });

  const db = readDB();
  if (!db[slug]) return res.status(404).json({ error: 'Wishlist non trouvée' });

  const { displayName, bio, emoji, creatorType } = req.body;
  if (displayName) db[slug].displayName = displayName;
  if (bio !== undefined) db[slug].bio = bio;
  if (emoji) db[slug].emoji = emoji;
  if (creatorType) db[slug].creatorType = creatorType;
  writeDB(db);
  res.json(db[slug]);
});

// POST /api/wishlists/:username/items — add item
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

// DELETE /api/wishlists/:username/items/:itemId — remove item
app.delete('/api/wishlists/:username/items/:itemId', requireAuth, (req, res) => {
  const slug = req.params.username.toLowerCase();
  if (req.user.username !== slug) return res.status(403).json({ error: 'Non autorisé' });

  const db = readDB();
  if (!db[slug]) return res.status(404).json({ error: 'Wishlist non trouvée' });

  db[slug].items = db[slug].items.filter(i => i.id !== req.params.itemId);
  writeDB(db);
  res.json({ ok: true });
});

// ════════════════════════════════════════
//  ORDERS ENDPOINTS (concierge MVP)
// ════════════════════════════════════════

// POST /api/orders — fan submits a gift request
app.post('/api/orders', (req, res) => {
  const { creatorUsername, itemId, itemName, fanName, fanEmail, message } = req.body;
  if (!creatorUsername || !itemId) {
    return res.status(400).json({ error: 'creatorUsername et itemId requis' });
  }

  const db = readDB();
  const wishlist = db[creatorUsername.toLowerCase()];
  if (!wishlist) return res.status(404).json({ error: 'Créateur introuvable' });

  const item = wishlist.items.find(i => i.id === itemId);
  if (!item) return res.status(404).json({ error: 'Article introuvable' });

  const users = readUsers();
  const user = users[creatorUsername.toLowerCase()];
  if (!user || !user.deliveryAddressEnc) {
    return res.status(400).json({ error: 'Ce créateur n\'a pas encore configuré son adresse de livraison' });
  }

  const orders = readOrders();
  const order = {
    id: crypto.randomBytes(8).toString('hex'),
    creatorUsername: creatorUsername.toLowerCase(),
    itemId,
    itemName: item.name,
    itemUrl: item.url,
    itemPrice: item.price,
    fanName: fanName || 'Anonyme',
    fanEmail: fanEmail || null,
    message: message || '',
    status: 'pending',   // pending | processing | shipped | delivered | cancelled
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  orders.push(order);
  writeOrders(orders);

  res.status(201).json({
    ok: true,
    orderId: order.id,
    message: 'Cadeau enregistré ! L\'équipe OffreMoi va traiter ta commande sous 24-48h. Merci ! 🎁'
  });
});

// GET /api/orders/mine — creator sees their pending gifts (no fan payment info)
app.get('/api/orders/mine', requireAuth, (req, res) => {
  const orders = readOrders();
  const mine = orders
    .filter(o => o.creatorUsername === req.user.username)
    .map(o => ({
      id: o.id, itemName: o.itemName, itemPrice: o.itemPrice,
      fanName: o.fanName, message: o.message, status: o.status,
      createdAt: o.createdAt
    }));
  res.json(mine);
});

// ════════════════════════════════════════
//  ADMIN ENDPOINTS (concierge fulfillment)
// ════════════════════════════════════════

// GET /api/admin/orders — all pending orders with decrypted address
app.get('/api/admin/orders', requireAdmin, (req, res) => {
  const orders = readOrders();
  const users = readUsers();
  const result = orders
    .filter(o => o.status === 'pending' || o.status === 'processing')
    .map(o => {
      const user = users[o.creatorUsername];
      const addr = user ? decryptAddress(user.deliveryAddressEnc) : null;
      const addrObj = addr ? JSON.parse(addr) : null;
      return { ...o, deliveryAddress: addrObj };
    });
  res.json(result);
});

// PATCH /api/admin/orders/:id — update order status
app.patch('/api/admin/orders/:id', requireAdmin, (req, res) => {
  const orders = readOrders();
  const order = orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Commande introuvable' });
  order.status = req.body.status || order.status;
  order.updatedAt = new Date().toISOString();
  writeOrders(orders);
  res.json({ ok: true, order });
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
