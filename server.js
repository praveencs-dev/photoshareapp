// server.js
require('dotenv').config(); // Optional if you add a .env file later
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'replace_with_a_strong_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
  })
);

// --- Multer setup (store files in memory so we can write to DB) ---
const storage = multer.memoryStorage();
const upload = multer({ storage });

// --- Helper middleware ---
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.redirect('/login');
}

// --- AUTH ROUTES ---
// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, display_name } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'username and password required' });

    const hashed = await bcrypt.hash(password, 10);

    const stmt = db.prepare(
      'INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)'
    );
    stmt.run(username, hashed, display_name || null, function (err) {
      if (err) return res.status(400).json({ error: 'username might be taken' });
      req.session.userId = this.lastID;
      req.session.username = username;
      res.json({ success: true, id: this.lastID });
    });
    stmt.finalize();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'username and password required' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(400).json({ error: 'invalid credentials' });

    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(400).json({ error: 'invalid credentials' });

    req.session.userId = row.id;
    req.session.username = row.username;
    res.json({ success: true });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// --- PHOTO UPLOAD ROUTE ---
app.post('/api/upload', requireAuth, upload.single('photo'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'no file uploaded' });

    const { mimetype, buffer } = req.file;
    const uploaderId = req.session.userId;
    const tagsRaw = req.body.tags || '';
    const desc=req.body.desc;
    const tagUsernames = tagsRaw.split(',').map(s => s.trim()).filter(Boolean);

    db.run(
      'INSERT INTO photos (filename, mimetype, data, uploader_id) VALUES (?, ?, ?, ?)',
      [desc, mimetype, buffer, uploaderId],
      function (err) {
        if (err) return res.status(500).json({ error: 'db insert failed' });
        const photoId = this.lastID;

        // Handle tagging if any
        if (tagUsernames.length === 0) return res.json({ success: true, photoId });

        const insertTag = db.prepare(
          'INSERT INTO photo_tags (photo_id, user_id, tagged_by) VALUES (?, ?, ?)'
        );
        let pending = tagUsernames.length;

        tagUsernames.forEach(username => {
          db.get('SELECT id FROM users WHERE username = ?', [username], (err, userRow) => {
            if (!err && userRow) {
              insertTag.run(photoId, userRow.id, uploaderId);
            }
            pending -= 1;
            if (pending === 0) {
              insertTag.finalize();
              res.json({ success: true, photoId });
            }
          });
        });
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// --- PHOTO API ---
app.get('/api/photo/:id', (req, res) => {
  const id = req.params.id;
  db.get('SELECT mimetype, data FROM photos WHERE id = ?', [id], (err, row) => {
    if (err || !row) return res.status(404).end('Not found');
    res.set('Content-Type', row.mimetype);
    res.send(row.data);
  });
});

// All photos (public)
app.get('/api/photos', (req, res) => {
  const sql = `
    SELECT p.id, p.filename, p.created_at, u.display_name AS uploader
    FROM photos p
    LEFT JOIN users u ON p.uploader_id = u.id
    ORDER BY p.created_at DESC
  `;
  db.all(sql, [], (err, photos) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!photos.length) return res.json([]);

    let remaining = photos.length;
    const result = [];

    photos.forEach(photo => {
      db.all(
        `SELECT u.username 
         FROM photo_tags t 
         JOIN users u ON t.user_id = u.id 
         WHERE t.photo_id = ?`,
        [photo.id],
        (err, tagsRows) => {
          const tags = (tagsRows || []).map(r => r.username);
          result.push({ ...photo, tags });
          remaining -= 1;
          if (remaining === 0) {
            result.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
            res.json(result);
          }
        }
      );
    });
  });
});

// List users
app.get('/api/users', (req, res) => {
  db.all('SELECT id, username, display_name FROM users LIMIT 100', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json(rows);
  });
});
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  
  db.get('SELECT id, username, display_name FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err || !user) return res.status(500).json({ error: 'DB error' });
    res.json(user);
  });
});

// --- Serve HTML Pages ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/upload', requireAuth, (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'upload.html'))
);
app.get('/dashboard', requireAuth, (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'))
);
// Get all photos (public feed)
app.get("/api/photos", (req, res) => {
  db.all(`
    SELECT photos.*, users.username AS uploader
    FROM photos
    LEFT JOIN users ON photos.uploader_id = users.id
    ORDER BY created_at DESC
  `, [], async (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    const photos = await Promise.all(rows.map(async (p) => {
      const tags = await new Promise((resolve) => {
        db.all(`
          SELECT u.username
          FROM photo_tags t
          JOIN users u ON t.user_id = u.id
          WHERE t.photo_id = ?`, [p.id], (err, tagRows) => {
          resolve(tagRows ? tagRows.map(r => r.username) : []);
        });
      });
      return { ...p, tags };
    }));
    res.json(photos);
  });
});

// Get only logged-in user's photos
// Get only logged-in user's photos
app.get("/api/myphotos", requireAuth, (req, res) => {
  const uid = req.session.userId; // <- use userId from session

  db.all(`
    SELECT photos.id, photos.filename, photos.created_at, users.username AS uploader
    FROM photos
    LEFT JOIN users ON photos.uploader_id = users.id
    WHERE photos.uploader_id = ?
    ORDER BY photos.created_at DESC
  `, [uid], async (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    const photos = await Promise.all(rows.map(p => new Promise(resolve => {
      db.all(`
        SELECT u.username
        FROM photo_tags t
        JOIN users u ON t.user_id = u.id
        WHERE t.photo_id = ?`, [p.id], (err, tagRows) => {
        const tags = tagRows ? tagRows.map(r => r.username) : [];
        resolve({ ...p, tags });
      });
    })));

    res.json(photos);
  });
});
// Delete photo by ID (only by owner)
app.delete('/api/photo/:id', requireAuth, (req, res) => {
  const photoId = req.params.id;
  const userId = req.session.userId;

  // Ensure the logged-in user is the uploader
  db.get('SELECT * FROM photos WHERE id = ?', [photoId], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Photo not found' });
    if (row.uploader_id !== userId) return res.status(403).json({ error: 'Forbidden' });

    // Delete the photo and any related tags
    db.run('DELETE FROM photo_tags WHERE photo_id = ?', [photoId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete tags' });

      db.run('DELETE FROM photos WHERE id = ?', [photoId], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to delete photo' });
        res.json({ success: true });
      });
    });
  });
});

// --- Start Server ---
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));

