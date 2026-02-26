const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3457;
const DATA_FILE = path.join(__dirname, 'data', 'wishlists.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper: read DB
function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    return {};
  }
}

// Helper: write DB
function writeDB(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// Helper: build affiliate URL
// TODO: add affiliate tag ?tag=offremoi-21
function buildAffiliateUrl(url) {
  return url;
}

// GET /api/wishlists/:username
app.get('/api/wishlists/:username', (req, res) => {
  const db = readDB();
  const wishlist = db[req.params.username.toLowerCase()];
  if (!wishlist) {
    return res.status(404).json({ error: 'Wishlist non trouvée' });
  }
  // Apply affiliate URLs
  const result = {
    ...wishlist,
    items: wishlist.items.map(item => ({
      ...item,
      affiliateUrl: buildAffiliateUrl(item.url)
    }))
  };
  res.json(result);
});

// POST /api/wishlists — create new wishlist
app.post('/api/wishlists', (req, res) => {
  const { username, displayName, bio, emoji, items } = req.body;

  if (!username || !displayName) {
    return res.status(400).json({ error: 'username et displayName sont requis' });
  }

  const slug = username.toLowerCase().replace(/[^a-z0-9_-]/g, '');
  if (!slug) {
    return res.status(400).json({ error: 'username invalide' });
  }

  const db = readDB();
  if (db[slug]) {
    return res.status(409).json({ error: 'Ce username est déjà pris' });
  }

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

  db[slug] = newWishlist;
  writeDB(db);

  res.status(201).json(newWishlist);
});

// POST /api/wishlists/:username/items — add item
app.post('/api/wishlists/:username/items', (req, res) => {
  const db = readDB();
  const slug = req.params.username.toLowerCase();
  const wishlist = db[slug];

  if (!wishlist) {
    return res.status(404).json({ error: 'Wishlist non trouvée' });
  }

  const { name, url, price } = req.body;
  const newItem = {
    id: String(Date.now()),
    name: name || 'Cadeau mystère',
    url: url || '',
    price: price || '',
    addedAt: new Date().toISOString().split('T')[0]
  };

  wishlist.items.push(newItem);
  db[slug] = wishlist;
  writeDB(db);

  res.status(201).json(newItem);
});

// GET /:username — SPA fallback for profile pages
app.get('/:username', (req, res) => {
  // Skip API routes and static files
  if (req.params.username.startsWith('api')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// GET / — landing page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🎁 OffreMoi running at http://localhost:${PORT}`);
});
