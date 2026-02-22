const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;

// ── Configuration ────────────────────────────────────────
const BASE_UPLOAD_PATH = 'G:\\James Clips\\Uploads';
const PROFILE_PATH = path.join(BASE_UPLOAD_PATH, 'profiles');

if (!fs.existsSync(BASE_UPLOAD_PATH)) fs.mkdirSync(BASE_UPLOAD_PATH, { recursive: true });
if (!fs.existsSync(PROFILE_PATH)) fs.mkdirSync(PROFILE_PATH, { recursive: true });
console.log(`Storage folder: ${BASE_UPLOAD_PATH}`);

const JWT_SECRET = 'your-super-secret-key-change-this-in-production-2026';

// ── Database ─────────────────────────────────────────────
const db = new sqlite3.Database('./users_and_files.db', err => {
  if (err) console.error('DB connection error:', err);
  else console.log('SQLite connected');
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      profile_image TEXT DEFAULT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, name),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      folder_id INTEGER,
      filename TEXT NOT NULL,
      filepath TEXT NOT NULL,
      size INTEGER NOT NULL,
      upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS share_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id INTEGER,
      folder_id INTEGER,
      token TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
      FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS login_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      ip TEXT NOT NULL,
      login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS file_shares (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id INTEGER NOT NULL,
      shared_by INTEGER NOT NULL,
      shared_with INTEGER NOT NULL,
      shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
      FOREIGN KEY (shared_by) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (shared_with) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Create default admin
  bcrypt.hash('adminpass', 10, (err, hashed) => {
    if (err) console.error('Admin hash error:', err);
    db.run('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)', ['admin', hashed, 'admin']);
  });
});

// ── Middleware ───────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(BASE_UPLOAD_PATH));

// Get client IP
function getClientIp(req) {
  return req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
}

// ── Auth middleware ──────────────────────────────────────
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
};

// ── Register ─────────────────────────────────────────────
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashed, 'user'], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Username taken' });
        return res.status(500).json({ error: 'Database error' });
      }

      const safeUsername = username.replace(/[^a-zA-Z0-9-_]/g, '_');
      const userFolder = path.join(BASE_UPLOAD_PATH, safeUsername);
      if (!fs.existsSync(userFolder)) fs.mkdirSync(userFolder, { recursive: true });

      res.status(201).json({ message: 'User created' });
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Login ────────────────────────────────────────────────
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (err || !row || !(await bcrypt.compare(password, row.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: row.id, username: row.username, role: row.role }, JWT_SECRET, { expiresIn: '7d' });

    const ip = getClientIp(req);
    db.run('INSERT INTO login_history (user_id, ip) VALUES (?, ?)', [row.id, ip]);

    res.json({ token, username: row.username, role: row.role });
  });
});

// ── Admin: List users (basic info) ───────────────────────
app.get('/admin/users', authenticateToken, isAdmin, (req, res) => {
  db.all(
    'SELECT id, username, role, created_at FROM users ORDER BY created_at DESC',
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

// ── Admin: Get storage usage for all users ───────────────
app.get('/admin/users/storage', authenticateToken, isAdmin, (req, res) => {
  db.all(
    `SELECT u.id, u.username, u.role, 
            COALESCE(SUM(f.size) / (1024.0 * 1024.0), 0) as used_mb
     FROM users u
     LEFT JOIN files f ON u.id = f.user_id
     GROUP BY u.id
     ORDER BY u.created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      const stats = rows.map(row => ({
        id: row.id,
        username: row.username,
        role: row.role,
        usedMB: parseFloat(row.used_mb).toFixed(2)
      }));

      res.json(stats);
    }
  );
});

// ── Admin: Get global storage stats ──────────────────────
app.get('/admin/storage/global', authenticateToken, isAdmin, (req, res) => {
  db.get(
    `SELECT 
       COUNT(DISTINCT u.id) as total_users,
       SUM(CASE WHEN u.role = 'admin' THEN 1 ELSE 0 END) as total_admins,
       COUNT(f.id) as total_files,
       COALESCE(SUM(f.size) / (1024.0 * 1024.0), 0) as total_used_mb
     FROM users u
     LEFT JOIN files f ON u.id = f.user_id`,
    [],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      const stats = {
        totalUsers: row.total_users || 0,
        totalAdmins: row.total_admins || 0,
        totalFiles: row.total_files || 0,
        totalUsedMB: parseFloat(row.total_used_mb).toFixed(2),
        totalUsedGB: (parseFloat(row.total_used_mb) / 1024).toFixed(2)
      };

      res.json(stats);
    }
  );
});

// ── Admin: Create user ───────────────────────────────────
app.post('/admin/users', authenticateToken, isAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return res.status(400).json({ error: 'Missing fields' });
  if (role !== 'user' && role !== 'admin') return res.status(400).json({ error: 'Invalid role' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashed, role], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Username taken' });
        return res.status(500).json({ error: 'Database error' });
      }

      const safeUsername = username.replace(/[^a-zA-Z0-9-_]/g, '_');
      const userFolder = path.join(BASE_UPLOAD_PATH, safeUsername);
      if (!fs.existsSync(userFolder)) fs.mkdirSync(userFolder, { recursive: true });

      res.status(201).json({ message: 'User created' });
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Admin: Reset password ────────────────────────────────
app.post('/admin/users/:id/reset-password', authenticateToken, isAdmin, async (req, res) => {
  const userId = req.params.id;
  const { newPassword } = req.body;
  if (!newPassword) return res.status(400).json({ error: 'New password required' });

  db.get('SELECT id FROM users WHERE id = ?', [userId], async (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'User not found' });

    const hashed = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, userId], err => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ message: 'Password reset successfully' });
    });
  });
});

// ── Admin: Delete user + all data ────────────────────────
app.delete('/admin/users/:id', authenticateToken, isAdmin, (req, res) => {
  const userId = parseInt(req.params.id);

  if (userId === req.user.id) {
    return res.status(403).json({ error: 'You cannot delete your own account' });
  }

  db.get('SELECT username, profile_image FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'User not found' });

    const safeUsername = row.username.replace(/[^a-zA-Z0-9-_]/g, '_');
    const userFolderPath = path.join(BASE_UPLOAD_PATH, safeUsername);

    if (fs.existsSync(userFolderPath)) {
      try {
        fs.rmSync(userFolderPath, { recursive: true, force: true });
      } catch (fsErr) {
        console.error('Failed to delete user folder:', fsErr);
      }
    }

    if (row.profile_image) {
      const profileFullPath = path.join(BASE_UPLOAD_PATH, row.profile_image);
      if (fs.existsSync(profileFullPath)) {
        try {
          fs.unlinkSync(profileFullPath);
        } catch (unlinkErr) {
          console.error('Failed to delete profile image:', unlinkErr);
        }
      }
    }

    db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete user from database' });

      res.json({ message: `User ${row.username} and all their data deleted successfully` });
    });
  });
});

// ── Share file with another user by username ─────────────
app.post('/files/:id/share-with-user', authenticateToken, (req, res) => {
  const fileId = req.params.id;
  const { username } = req.body;

  if (!username) return res.status(400).json({ error: 'Username required' });

  db.get('SELECT id FROM users WHERE username = ?', [username], (err, targetUser) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!targetUser) return res.status(404).json({ error: 'User not found' });

    db.get('SELECT user_id FROM files WHERE id = ?', [fileId], (err, fileRow) => {
      if (err || !fileRow) return res.status(404).json({ error: 'File not found' });
      if (fileRow.user_id !== req.user.id) {
        return res.status(403).json({ error: 'You can only share your own files' });
      }

      db.get(
        'SELECT id FROM file_shares WHERE file_id = ? AND shared_with = ?',
        [fileId, targetUser.id],
        (err, shareRow) => {
          if (err) return res.status(500).json({ error: 'Database error' });
          if (shareRow) return res.status(409).json({ error: 'File already shared with this user' });

          db.run(
            'INSERT INTO file_shares (file_id, shared_by, shared_with) VALUES (?, ?, ?)',
            [fileId, req.user.id, targetUser.id],
            err => {
              if (err) return res.status(500).json({ error: 'Failed to share file' });
              res.json({ message: `File shared with ${username}` });
            }
          );
        }
      );
    });
  });
});

// ── Get files shared with me ─────────────────────────────────
app.get('/files/shared-with-me', authenticateToken, (req, res) => {
  db.all(
    `SELECT f.id, f.filename, f.filepath, f.size, f.upload_time, 
            u.username as shared_by_username
     FROM file_shares fs
     JOIN files f ON fs.file_id = f.id
     JOIN users u ON fs.shared_by = u.id
     WHERE fs.shared_with = ?
     ORDER BY fs.shared_at DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      const sharedFiles = rows.map(row => ({
        id: row.id,
        filename: row.filename,
        filepath: row.filepath,
        size: row.size,
        upload_time: new Date(row.upload_time).toLocaleString(),
        downloadUrl: `/uploads/${row.filepath}`,
        shared_by: row.shared_by_username
      }));

      res.json(sharedFiles);
    }
  );
});

// ── Create folder ────────────────────────────────────────
app.post('/folders', authenticateToken, (req, res) => {
  const { name } = req.body;
  if (!name || name.trim() === '') return res.status(400).json({ error: 'Folder name required' });

  const safeName = name.trim().replace(/[^a-zA-Z0-9-_ ]/g, '_');

  db.run(
    'INSERT INTO folders (user_id, name) VALUES (?, ?)',
    [req.user.id, safeName],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Folder name already exists' });
        return res.status(500).json({ error: 'Database error' });
      }

      const folderId = this.lastID;

      db.get('SELECT username FROM users WHERE id = ?', [req.user.id], (err, row) => {
        if (err || !row) return res.status(500).json({ error: 'User not found' });
        const safeUsername = row.username.replace(/[^a-zA-Z0-9-_]/g, '_');
        const fullPath = path.join(BASE_UPLOAD_PATH, safeUsername, safeName);
        if (!fs.existsSync(fullPath)) fs.mkdirSync(fullPath, { recursive: true });
        res.json({ id: folderId, name: safeName });
      });
    }
  );
});

// ── List folders ─────────────────────────────────────────
app.get('/folders', authenticateToken, (req, res) => {
  db.all(
    'SELECT id, name FROM folders WHERE user_id = ? ORDER BY name',
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

// ── Upload file ──────────────────────────────────────────
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const folderId = req.body.folderId ? parseInt(req.body.folderId) : null;
    db.get('SELECT username FROM users WHERE id = ?', [req.user.id], (err, row) => {
      if (err || !row) return cb(new Error('User not found'));
      const safeUsername = row.username.replace(/[^a-zA-Z0-9-_]/g, '_');
      let uploadPath = path.join(BASE_UPLOAD_PATH, safeUsername);

      if (folderId) {
        db.get('SELECT name FROM folders WHERE id = ? AND user_id = ?', [folderId, req.user.id], (err, fRow) => {
          if (err || !fRow) return cb(new Error('Folder not found'));
          uploadPath = path.join(uploadPath, fRow.name);
          cb(null, uploadPath);
        });
      } else {
        cb(null, uploadPath);
      }
    });
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage, limits: { fileSize: 200 * 1024 * 1024 } });

app.post('/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const folderId = req.body.folderId ? parseInt(req.body.folderId) : null;

  db.get('SELECT username FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err || !row) return res.status(500).json({ error: 'User lookup failed' });

    const safeUsername = row.username.replace(/[^a-zA-Z0-9-_]/g, '_');
    let relativePath = safeUsername;

    if (folderId) {
      db.get('SELECT name FROM folders WHERE id = ?', [folderId], (err, fRow) => {
        if (err || !fRow) return res.status(500).json({ error: 'Folder lookup failed' });
        relativePath = path.join(safeUsername, fRow.name, req.file.originalname).replace(/\\/g, '/');
        saveFileMetadata(req, res, folderId, relativePath);
      });
    } else {
      relativePath = path.join(safeUsername, req.file.originalname).replace(/\\/g, '/');
      saveFileMetadata(req, res, null, relativePath);
    }
  });
});

function saveFileMetadata(req, res, folderId, relativePath) {
  db.run(
    'INSERT INTO files (user_id, folder_id, filename, filepath, size) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, folderId, req.file.originalname, relativePath, req.file.size],
    function(err) {
      if (err) {
        console.error('Metadata insert error:', err.message);
        return res.status(500).json({ error: 'Metadata save failed: ' + err.message });
      }

      const fileId = this.lastID;

      const token = uuidv4();
      db.run(
        'INSERT INTO share_links (file_id, token) VALUES (?, ?)',
        [fileId, token],
        err => {
          if (err) return res.status(500).json({ error: 'Share link creation failed' });

          const shareUrl = `${req.protocol}://${req.get('host')}/share/${token}`;
          res.json({
            message: 'File uploaded successfully',
            filename: req.file.originalname,
            shareLink: shareUrl
          });
        }
      );
    }
  );
}

// ── Regenerate file share link ───────────────────────────
app.post('/files/:id/share', authenticateToken, (req, res) => {
  const fileId = req.params.id;

  db.get('SELECT user_id FROM files WHERE id = ?', [fileId], (err, row) => {
    if (err || !row || row.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Not authorized or file not found' });
    }

    const token = uuidv4();
    db.run(
      'INSERT INTO share_links (file_id, token) VALUES (?, ?)',
      [fileId, token],
      err => {
        if (err) return res.status(500).json({ error: 'Failed to create share link' });

        const shareUrl = `${req.protocol}://${req.get('host')}/share/${token}`;
        res.json({ shareLink: shareUrl });
      }
    );
  });
});

// ── Public file download ─────────────────────────────────
app.get('/share/:token', (req, res) => {
  const token = req.params.token;

  db.get(
    'SELECT f.filepath, f.filename FROM share_links sl JOIN files f ON sl.file_id = f.id WHERE sl.token = ?',
    [token],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      if (!row) return res.status(404).json({ error: 'Link not found' });

      const filePath = path.join(BASE_UPLOAD_PATH, row.filepath);

      if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });

      res.download(filePath, row.filename, err => {
        if (err) console.error('Download error:', err);
      });
    }
  );
});

// ── List files (own files) ───────────────────────────────
app.get('/files', authenticateToken, (req, res) => {
  db.all(
    `SELECT f.id, f.filename, f.filepath, f.size, f.upload_time, f.folder_id, fo.name AS folder_name
     FROM files f LEFT JOIN folders fo ON f.folder_id = fo.id
     WHERE f.user_id = ? ORDER BY fo.name, f.upload_time DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      const files = rows.map(row => ({
        id: row.id,
        filename: row.filename,
        filepath: row.filepath,
        size: row.size,
        upload_time: new Date(row.upload_time).toLocaleString(),
        downloadUrl: `/uploads/${row.filepath}`,
        folder_id: row.folder_id,
        folder_name: row.folder_name || null
      }));

      res.json(files);
    }
  );
});

// ── Move file ────────────────────────────────────────────
app.post('/files/:id/move', authenticateToken, (req, res) => {
  const fileId = req.params.id;
  const { folderId } = req.body;
  const newFolderId = folderId ? parseInt(folderId) : null;

  db.get('SELECT filepath, folder_id, user_id FROM files WHERE id = ?', [fileId], (err, row) => {
    if (err || !row || row.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Not authorized or file not found' });
    }

    db.get('SELECT username FROM users WHERE id = ?', [req.user.id], (err, uRow) => {
      if (err || !uRow) return res.status(500).json({ error: 'User not found' });

      const safeUsername = uRow.username.replace(/[^a-zA-Z0-9-_]/g, '_');
      const oldFullPath = path.join(BASE_UPLOAD_PATH, row.filepath);
      const filename = path.basename(row.filepath);

      let newRelativePath = safeUsername;
      let newFullPath = path.join(BASE_UPLOAD_PATH, safeUsername, filename);

      if (newFolderId !== null) {
        db.get('SELECT name FROM folders WHERE id = ? AND user_id = ?', [newFolderId, req.user.id], (err, fRow) => {
          if (err || !fRow) return res.status(400).json({ error: 'Invalid or unauthorized folder' });

          newRelativePath = path.join(safeUsername, fRow.name, filename);
          newFullPath = path.join(BASE_UPLOAD_PATH, newRelativePath);

          fs.rename(oldFullPath, newFullPath, err => {
            if (err) return res.status(500).json({ error: 'Failed to move file on disk' });

            db.run(
              'UPDATE files SET folder_id = ?, filepath = ? WHERE id = ?',
              [newFolderId, newRelativePath, fileId],
              err => {
                if (err) return res.status(500).json({ error: 'Database update failed' });
                res.json({ message: 'File moved successfully' });
              }
            );
          });
        });
      } else {
        fs.rename(oldFullPath, newFullPath, err => {
          if (err) return res.status(500).json({ error: 'Failed to move file on disk' });

          db.run(
            'UPDATE files SET folder_id = NULL, filepath = ? WHERE id = ?',
            [newRelativePath, fileId],
            err => {
              if (err) return res.status(500).json({ error: 'Database update failed' });
              res.json({ message: 'File moved to root' });
            }
          );
        });
      }
    });
  });
});

// ── Rename file ──────────────────────────────────────────
app.post('/files/:id/rename', authenticateToken, (req, res) => {
  const fileId = req.params.id;
  const { newName } = req.body;

  if (!newName || newName.trim() === '') return res.status(400).json({ error: 'New filename required' });

  const safeNewName = newName.trim().replace(/[^a-zA-Z0-9-_. ]/g, '_');

  db.get('SELECT filepath, user_id FROM files WHERE id = ?', [fileId], (err, row) => {
    if (err || !row || row.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Not authorized or file not found' });
    }

    const oldFullPath = path.join(BASE_UPLOAD_PATH, row.filepath);
    const oldDir = path.dirname(oldFullPath);
    const newFullPath = path.join(oldDir, safeNewName);

    if (fs.existsSync(newFullPath)) {
      return res.status(409).json({ error: 'A file with that name already exists in this folder' });
    }

    fs.rename(oldFullPath, newFullPath, err => {
      if (err) return res.status(500).json({ error: 'Failed to rename file on disk' });

      const newRelativePath = path.join(path.dirname(row.filepath), safeNewName).replace(/\\/g, '/');

      db.run(
        'UPDATE files SET filename = ?, filepath = ? WHERE id = ?',
        [safeNewName, newRelativePath, fileId],
        err => {
          if (err) return res.status(500).json({ error: 'Database update failed' });

          res.json({ message: 'File renamed successfully', newFilename: safeNewName });
        }
      );
    });
  });
});

// ── Storage usage (current user) ─────────────────────────
app.get('/storage', authenticateToken, (req, res) => {
  db.get(
    'SELECT SUM(size) as total FROM files WHERE user_id = ?',
    [req.user.id],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      const usedBytes = row.total || 0;
      const usedMB = (usedBytes / (1024 * 1024)).toFixed(2);
      res.json({ usedMB });
    }
  );
});

// ── Recent activity ──────────────────────────────────────
app.get('/recent-activity', authenticateToken, (req, res) => {
  db.all(
    `SELECT u.username, f.filename, f.upload_time, f.size
     FROM files f JOIN users u ON f.user_id = u.id
     ORDER BY f.upload_time DESC LIMIT 5`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      const activity = rows.map(row => ({
        username: row.username,
        filename: row.filename,
        upload_time: new Date(row.upload_time).toLocaleString(),
        sizeMB: (row.size / (1024 * 1024)).toFixed(2)
      }));

      res.json(activity);
    }
  );
});

// ── Profile data ─────────────────────────────────────────
app.get('/profile', authenticateToken, (req, res) => {
  db.get('SELECT username, profile_image FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err || !row) return res.status(500).json({ error: 'User not found' });

    db.get(
      'SELECT SUM(size) as total FROM files WHERE user_id = ?',
      [req.user.id],
      (err, statsRow) => {
        if (err) return res.status(500).json({ error: 'Stats error' });
        const usedBytes = statsRow.total || 0;
        const usedMB = (usedBytes / (1024 * 1024)).toFixed(2);

        res.json({
          username: row.username,
          profileImage: row.profile_image ? `/uploads/${row.profile_image}` : null,
          usedMB
        });
      }
    );
  });
});

// ── Upload profile image ─────────────────────────────────
const profileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, PROFILE_PATH);
  },
  filename: (req, file, cb) => {
    cb(null, `${req.user.id}.jpg`);
  }
});

const profileUpload = multer({ storage: profileStorage, limits: { fileSize: 5 * 1024 * 1024 } });

app.post('/profile/image', authenticateToken, profileUpload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No image uploaded' });

  const profilePath = `profiles/${req.user.id}.jpg`;

  db.run(
    'UPDATE users SET profile_image = ? WHERE id = ?',
    [profilePath, req.user.id],
    err => {
      if (err) return res.status(500).json({ error: 'Failed to save profile image' });
      res.json({ message: 'Profile image uploaded', profileImage: `/uploads/${profilePath}` });
    }
  );
});

// ── Change password ──────────────────────────────────────
app.post('/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });

  db.get('SELECT password FROM users WHERE id = ?', [req.user.id], async (err, row) => {
    if (err || !row || !(await bcrypt.compare(oldPassword, row.password))) {
      return res.status(401).json({ error: 'Invalid old password' });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, req.user.id], err => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ message: 'Password changed successfully' });
    });
  });
});

// ── Login history ────────────────────────────────────────
app.get('/login-history', authenticateToken, (req, res) => {
  db.all(
    'SELECT ip, login_time FROM login_history WHERE user_id = ? ORDER BY login_time DESC LIMIT 5',
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      const history = rows.map(row => ({
        ip: row.ip,
        login_time: new Date(row.login_time).toLocaleString()
      }));

      res.json(history);
    }
  );
});

// ── Delete file ──────────────────────────────────────────
app.delete('/files/:id', authenticateToken, (req, res) => {
  const fileId = req.params.id;

  db.get('SELECT filepath, user_id FROM files WHERE id = ?', [fileId], (err, row) => {
    if (err || !row || row.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Not authorized or file not found' });
    }

    const fullPath = path.join(BASE_UPLOAD_PATH, row.filepath);

    db.run('DELETE FROM files WHERE id = ?', [fileId], err => {
      if (err) return res.status(500).json({ error: 'Database error' });

      db.run('DELETE FROM share_links WHERE file_id = ?', [fileId]);

      fs.unlink(fullPath, err => {
        if (err) console.error('File delete error:', err);
        res.json({ message: 'File deleted' });
      });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Storage: ${BASE_UPLOAD_PATH}`);
});