const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'securedrop-super-secure-jwt-secret-dev-2026';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Multer storage for uploaded encrypted files
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, db.uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = crypto.randomBytes(16).toString('hex');
    cb(null, `enc_${Date.now()}_${uniqueSuffix}.enc`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

// Audit logger helper
function logAuditEvent({ userId = null, fileId = null, shareId = null, eventType, severity = 'INFO', ipAddress = null, userAgent = null, metadata = {} }) {
  const logId = crypto.randomBytes(16).toString('hex');
  const timestamp = Date.now();
  try {
    db.run(
      `INSERT INTO access_logs (id, user_id, file_id, share_id, event_type, severity, ip_address, user_agent, metadata_json, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [logId, userId, fileId, shareId, eventType, severity, ipAddress, userAgent, JSON.stringify(metadata), timestamp]
    );
    console.log(`[AUDIT LOG] [${severity}] ${eventType} - file:${fileId || 'none'} share:${shareId || 'none'} user:${userId || 'anon'}`);
  } catch (err) {
    console.error('[AUDIT LOG ERROR]', err);
  }
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Authentication token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired authentication token' });
    }
    req.user = user;
    next();
  });
}

// Optional Auth (for downloads/lookups)
function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) req.user = user;
      next();
    });
  } else {
    next();
  }
}

// Rate limiting map for passcode brute-force defense
const passcodeAttempts = new Map(); // token_hash -> { count, lockedUntil }

// ----------------------------------------------------
// AUTHENTICATION ENDPOINTS
// ----------------------------------------------------

// Register
app.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long' });
  }

  try {
    const existing = db.get('SELECT id FROM users WHERE email = ? OR username = ?', [email, username]);
    if (existing) {
      return res.status(409).json({ error: 'User with this email or username already exists' });
    }

    const salt = bcrypt.genSaltSync(12);
    const passwordHash = bcrypt.hashSync(password, salt);
    const userId = crypto.randomBytes(16).toString('hex');
    const createdAt = Date.now();

    db.run(
      'INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
      [userId, username, email, passwordHash, createdAt]
    );

    const token = jwt.sign({ id: userId, username, email }, JWT_SECRET, { expiresIn: '7d' });

    logAuditEvent({
      userId,
      eventType: 'AUTHENTICATION_SUCCESS',
      severity: 'INFO',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { action: 'register', username }
    });

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: { id: userId, username, email }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error during registration' });
  }
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { identifier, password } = req.body; // identifier can be email or username
  if (!identifier || !password) {
    return res.status(400).json({ error: 'Email/username and password are required' });
  }

  try {
    const user = db.get('SELECT * FROM users WHERE email = ? OR username = ?', [identifier, identifier]);
    if (!user) {
      logAuditEvent({
        eventType: 'AUTHENTICATION_FAILURE',
        severity: 'WARNING',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        metadata: { identifier, reason: 'user_not_found' }
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = bcrypt.compareSync(password, user.password_hash);
    if (!isMatch) {
      logAuditEvent({
        userId: user.id,
        eventType: 'AUTHENTICATION_FAILURE',
        severity: 'WARNING',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        metadata: { identifier, reason: 'invalid_password' }
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    logAuditEvent({
      userId: user.id,
      eventType: 'AUTHENTICATION_SUCCESS',
      severity: 'INFO',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { action: 'login' }
    });

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

// Profile / Validate token
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = db.get('SELECT id, username, email, created_at FROM users WHERE id = ?', [req.user.id]);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ user });
});

// ----------------------------------------------------
// FILE MANAGEMENT ENDPOINTS (ENCRYPTED PAYLOADS)
// ----------------------------------------------------

// Upload encrypted file
app.post('/api/files/upload', authenticateToken, upload.single('encrypted_file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No encrypted file uploaded' });
  }

  const {
    original_name,
    mime_type,
    encrypted_size,
    plaintext_size,
    sha256_hash,
    plaintext_sha256,
    iv_hex,
    auth_tag_hex
  } = req.body;

  if (!original_name || !sha256_hash || !iv_hex || !auth_tag_hex) {
    // Delete uploaded temp file
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Missing cryptographic metadata (sha256_hash, iv_hex, auth_tag_hex required)' });
  }

  try {
    // Verify server-side integrity of the uploaded encrypted blob
    const fileBuffer = fs.readFileSync(req.file.path);
    const computedHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    if (computedHash.toLowerCase() !== sha256_hash.toLowerCase()) {
      fs.unlinkSync(req.file.path);
      logAuditEvent({
        userId: req.user.id,
        eventType: 'INTEGRITY_FAILURE',
        severity: 'CRITICAL',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        metadata: { original_name, expected: sha256_hash, computed: computedHash }
      });
      return res.status(400).json({ error: 'Upload rejected: SHA-256 payload integrity check failed' });
    }

    const fileId = crypto.randomBytes(16).toString('hex');
    const createdAt = Date.now();

    db.run(
      `INSERT INTO files (id, owner_id, original_name, mime_type, encrypted_size, plaintext_size, sha256_hash, plaintext_sha256, iv_hex, auth_tag_hex, storage_filename, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        fileId,
        req.user.id,
        original_name,
        mime_type || 'application/octet-stream',
        parseInt(encrypted_size || req.file.size),
        parseInt(plaintext_size || 0),
        sha256_hash,
        plaintext_sha256 || '',
        iv_hex,
        auth_tag_hex,
        req.file.filename,
        createdAt
      ]
    );

    logAuditEvent({
      userId: req.user.id,
      fileId,
      eventType: 'FILE_UPLOADED',
      severity: 'INFO',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { original_name, encrypted_size: req.file.size, sha256_hash }
    });

    res.status(201).json({
      message: 'Encrypted file uploaded successfully',
      file: {
        id: fileId,
        original_name,
        mime_type: mime_type || 'application/octet-stream',
        encrypted_size: req.file.size,
        plaintext_size: parseInt(plaintext_size || 0),
        sha256_hash,
        plaintext_sha256: plaintext_sha256 || '',
        iv_hex,
        auth_tag_hex,
        created_at: createdAt
      }
    });
  } catch (err) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    console.error('File upload error:', err);
    res.status(500).json({ error: 'Internal server error during file upload' });
  }
});

// List user's files
app.get('/api/files', authenticateToken, (req, res) => {
  try {
    const files = db.all(
      `SELECT id, original_name, mime_type, encrypted_size, plaintext_size, sha256_hash, plaintext_sha256, iv_hex, auth_tag_hex, created_at
       FROM files WHERE owner_id = ? ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ files });
  } catch (err) {
    console.error('List files error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get file details (with strict IDOR object-level authorization check!)
app.get('/api/files/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  try {
    const file = db.get('SELECT * FROM files WHERE id = ?', [id]);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // IDOR Protection: verify user is owner
    if (file.owner_id !== req.user.id) {
      logAuditEvent({
        userId: req.user.id,
        fileId: id,
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'CRITICAL',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        metadata: { target_file_id: id, actual_owner_id: file.owner_id }
      });
      return res.status(403).json({ error: 'Access denied: You are not authorized to view or access this file' });
    }

    // Return sanitized metadata
    res.json({
      file: {
        id: file.id,
        original_name: file.original_name,
        mime_type: file.mime_type,
        encrypted_size: file.encrypted_size,
        plaintext_size: file.plaintext_size,
        sha256_hash: file.sha256_hash,
        plaintext_sha256: file.plaintext_sha256,
        iv_hex: file.iv_hex,
        auth_tag_hex: file.auth_tag_hex,
        created_at: file.created_at
      }
    });
  } catch (err) {
    console.error('Get file error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete file
app.delete('/api/files/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  try {
    const file = db.get('SELECT * FROM files WHERE id = ?', [id]);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    if (file.owner_id !== req.user.id) {
      logAuditEvent({
        userId: req.user.id,
        fileId: id,
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'CRITICAL',
        metadata: { action: 'delete', file_id: id }
      });
      return res.status(403).json({ error: 'Access denied' });
    }

    // Delete associated physical file
    const filePath = path.join(db.uploadsDir, file.storage_filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Delete shares & logs
    db.run('DELETE FROM shares WHERE file_id = ?', [id]);
    db.run('DELETE FROM files WHERE id = ?', [id]);

    logAuditEvent({
      userId: req.user.id,
      fileId: id,
      eventType: 'FILE_DELETED',
      severity: 'INFO',
      metadata: { original_name: file.original_name }
    });

    res.json({ message: 'File and associated shares deleted successfully' });
  } catch (err) {
    console.error('Delete file error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ----------------------------------------------------
// SECURE SHARE ENDPOINTS
// ----------------------------------------------------

// Create Share
app.post('/api/shares', authenticateToken, (req, res) => {
  const {
    file_id,
    expires_in_seconds = 86400,
    one_time = false,
    passcode = null,
    require_biometric = false,
    prevent_screenshots = true
  } = req.body;

  if (!file_id) {
    return res.status(400).json({ error: 'file_id is required' });
  }

  try {
    const file = db.get('SELECT * FROM files WHERE id = ?', [file_id]);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    if (file.owner_id !== req.user.id) {
      logAuditEvent({
        userId: req.user.id,
        fileId: file_id,
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'CRITICAL',
        metadata: { action: 'create_share_unauthorized', target_file: file_id }
      });
      return res.status(403).json({ error: 'Access denied: You do not own this file' });
    }

    // Generate high-entropy 256-bit cryptographically secure random share token
    const rawToken = crypto.randomBytes(32).toString('hex');
    // Store only SHA-256 hash of token in database!
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

    const shareId = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    const expiresAt = now + (parseInt(expires_in_seconds) * 1000);

    let passcodeHash = null;
    if (passcode && passcode.trim().length > 0) {
      passcodeHash = bcrypt.hashSync(passcode.trim(), 10);
    }

    db.run(
      `INSERT INTO shares (id, file_id, owner_id, token_hash, expires_at, one_time, download_count, max_downloads, revoked, passcode_hash, require_biometric, prevent_screenshots, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0, ?, ?, ?, ?)`,
      [
        shareId,
        file_id,
        req.user.id,
        tokenHash,
        expiresAt,
        one_time ? 1 : 0,
        one_time ? 1 : -1,
        passcodeHash,
        require_biometric ? 1 : 0,
        prevent_screenshots ? 1 : 0,
        now
      ]
    );

    logAuditEvent({
      userId: req.user.id,
      fileId: file_id,
      shareId,
      eventType: 'SHARE_CREATED',
      severity: 'INFO',
      metadata: {
        expires_at: expiresAt,
        expires_in_seconds,
        one_time,
        require_passcode: !!passcodeHash,
        require_biometric,
        prevent_screenshots
      }
    });

    // Return the raw token only once upon creation
    res.status(201).json({
      message: 'Secure share created successfully',
      share: {
        id: shareId,
        file_id,
        token: rawToken, // Client shares this token with recipient
        expires_at: expiresAt,
        one_time: !!one_time,
        require_passcode: !!passcodeHash,
        require_biometric: !!require_biometric,
        prevent_screenshots: !!prevent_screenshots,
        created_at: now
      }
    });
  } catch (err) {
    console.error('Create share error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// List user's active/created shares
app.get('/api/shares/my', authenticateToken, (req, res) => {
  try {
    const shares = db.all(
      `SELECT s.id, s.file_id, s.expires_at, s.one_time, s.download_count, s.max_downloads, s.revoked,
              s.require_biometric, s.prevent_screenshots, s.created_at,
              CASE WHEN s.passcode_hash IS NOT NULL THEN 1 ELSE 0 END as has_passcode,
              f.original_name, f.encrypted_size, f.mime_type
       FROM shares s
       JOIN files f ON s.file_id = f.id
       WHERE s.owner_id = ?
       ORDER BY s.created_at DESC`,
      [req.user.id]
    );
    res.json({ shares });
  } catch (err) {
    console.error('List user shares error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Revoke Share
app.post('/api/shares/:id/revoke', authenticateToken, (req, res) => {
  const { id } = req.params;
  try {
    const share = db.get('SELECT * FROM shares WHERE id = ?', [id]);
    if (!share) {
      return res.status(404).json({ error: 'Share not found' });
    }
    if (share.owner_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied: You do not own this share' });
    }

    db.run('UPDATE shares SET revoked = 1 WHERE id = ?', [id]);

    logAuditEvent({
      userId: req.user.id,
      fileId: share.file_id,
      shareId: id,
      eventType: 'SHARE_REVOKED',
      severity: 'WARNING',
      metadata: { action: 'revoked_by_owner' }
    });

    res.json({ message: 'Secure share revoked successfully. Future access attempts will be blocked.' });
  } catch (err) {
    console.error('Revoke share error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Lookup share metadata (by recipient using token)
app.get('/api/shares/lookup/:token', optionalAuth, (req, res) => {
  const { token } = req.params;
  if (!token) {
    return res.status(400).json({ error: 'Share token required' });
  }

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const share = db.get(
      `SELECT s.*, f.original_name, f.mime_type, f.encrypted_size, f.plaintext_size, f.sha256_hash, f.plaintext_sha256, f.iv_hex, f.auth_tag_hex
       FROM shares s
       JOIN files f ON s.file_id = f.id
       WHERE s.token_hash = ?`,
      [tokenHash]
    );

    if (!share) {
      logAuditEvent({
        eventType: 'INVALID_TOKEN',
        severity: 'WARNING',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        metadata: { attempted_token: token.substring(0, 8) + '...' }
      });
      return res.status(404).json({ error: 'Invalid share token or file no longer exists' });
    }

    // Check Revocation
    if (share.revoked === 1) {
      logAuditEvent({
        fileId: share.file_id,
        shareId: share.id,
        eventType: 'DOWNLOAD_BLOCKED',
        severity: 'WARNING',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        metadata: { reason: 'revoked' }
      });
      return res.status(403).json({ error: 'Access revoked: The sender has revoked access to this file.' });
    }

    // Check Expiration
    if (Date.now() > share.expires_at) {
      logAuditEvent({
        fileId: share.file_id,
        shareId: share.id,
        eventType: 'SHARE_EXPIRED',
        severity: 'WARNING',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        metadata: { expires_at: share.expires_at, now: Date.now() }
      });
      return res.status(410).json({ error: 'Share expired: This secure link has expired and is no longer available.' });
    }

    // Check One-Time Download Enforcement
    if (share.one_time === 1 && share.download_count >= 1) {
      logAuditEvent({
        fileId: share.file_id,
        shareId: share.id,
        eventType: 'DOWNLOAD_BLOCKED',
        severity: 'WARNING',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        metadata: { reason: 'one_time_already_used', download_count: share.download_count }
      });
      return res.status(410).json({ error: 'This secure link has already been used. One-time download consumed.' });
    }

    logAuditEvent({
      userId: req.user ? req.user.id : null,
      fileId: share.file_id,
      shareId: share.id,
      eventType: 'SHARE_OPENED',
      severity: 'INFO',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      metadata: { original_name: share.original_name }
    });

    res.json({
      share: {
        id: share.id,
        original_name: share.original_name,
        mime_type: share.mime_type,
        encrypted_size: share.encrypted_size,
        plaintext_size: share.plaintext_size,
        sha256_hash: share.sha256_hash,
        plaintext_sha256: share.plaintext_sha256,
        iv_hex: share.iv_hex,
        auth_tag_hex: share.auth_tag_hex,
        expires_at: share.expires_at,
        one_time: !!share.one_time,
        require_passcode: !!share.passcode_hash,
        require_biometric: !!share.require_biometric,
        prevent_screenshots: !!share.prevent_screenshots
      }
    });
  } catch (err) {
    console.error('Lookup share error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Download encrypted file payload
app.post('/api/shares/download/:token', optionalAuth, (req, res) => {
  const { token } = req.params;
  const { passcode } = req.body || {};

  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Check rate limit on passcode attempts
    const rateLimit = passcodeAttempts.get(tokenHash);
    if (rateLimit && rateLimit.lockedUntil && Date.now() < rateLimit.lockedUntil) {
      const waitSeconds = Math.ceil((rateLimit.lockedUntil - Date.now()) / 1000);
      return res.status(429).json({ error: `Too many failed passcode attempts. Locked for ${waitSeconds} seconds.` });
    }

    const share = db.get(
      `SELECT s.*, f.storage_filename, f.original_name, f.sha256_hash, f.encrypted_size
       FROM shares s
       JOIN files f ON s.file_id = f.id
       WHERE s.token_hash = ?`,
      [tokenHash]
    );

    if (!share) {
      logAuditEvent({
        eventType: 'INVALID_TOKEN',
        severity: 'WARNING',
        ipAddress: req.ip,
        metadata: { action: 'download' }
      });
      return res.status(404).json({ error: 'Invalid share token' });
    }

    // Check Revoked
    if (share.revoked === 1) {
      logAuditEvent({
        fileId: share.file_id,
        shareId: share.id,
        eventType: 'DOWNLOAD_BLOCKED',
        severity: 'WARNING',
        metadata: { reason: 'revoked' }
      });
      return res.status(403).json({ error: 'Access revoked: This share has been revoked by the owner.' });
    }

    // Check Expiration
    if (Date.now() > share.expires_at) {
      logAuditEvent({
        fileId: share.file_id,
        shareId: share.id,
        eventType: 'SHARE_EXPIRED',
        severity: 'WARNING',
        metadata: { action: 'download_expired' }
      });
      return res.status(410).json({ error: 'Share expired: This link has expired.' });
    }

    // Check One-Time Download
    if (share.one_time === 1 && share.download_count >= 1) {
      logAuditEvent({
        fileId: share.file_id,
        shareId: share.id,
        eventType: 'DOWNLOAD_BLOCKED',
        severity: 'WARNING',
        metadata: { reason: 'one_time_already_used' }
      });
      return res.status(410).json({ error: 'This secure link has already been used.' });
    }

    // Check Passcode if required
    if (share.passcode_hash) {
      if (!passcode) {
        return res.status(401).json({ error: 'Passcode required for this protected file', require_passcode: true });
      }
      const match = bcrypt.compareSync(passcode, share.passcode_hash);
      if (!match) {
        const attempts = (rateLimit ? rateLimit.count : 0) + 1;
        let lockedUntil = null;
        if (attempts >= 5) {
          lockedUntil = Date.now() + 15 * 60 * 1000; // 15 min lock
        }
        passcodeAttempts.set(tokenHash, { count: attempts, lockedUntil });

        logAuditEvent({
          fileId: share.file_id,
          shareId: share.id,
          eventType: 'INVALID_PASSCODE',
          severity: 'WARNING',
          ipAddress: req.ip,
          metadata: { attempts }
        });
        return res.status(401).json({ error: 'Incorrect passcode', require_passcode: true });
      }
      // Passcode success: reset rate limit
      passcodeAttempts.delete(tokenHash);
    }

    // Atomic update to increment download count and consume one-time links
    // If one_time = 1, require download_count = 0 in the WHERE clause to prevent race conditions!
    const result = db.run(
      `UPDATE shares
       SET download_count = download_count + 1
       WHERE id = ? AND (one_time = 0 OR download_count = 0)`,
      [share.id]
    );

    if (result.changes === 0) {
      logAuditEvent({
        fileId: share.file_id,
        shareId: share.id,
        eventType: 'DOWNLOAD_BLOCKED',
        severity: 'WARNING',
        metadata: { reason: 'concurrent_one_time_conflict' }
      });
      return res.status(410).json({ error: 'This secure link has already been used.' });
    }

    const filePath = path.join(db.uploadsDir, share.storage_filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Encrypted file not found on storage' });
    }

    logAuditEvent({
      userId: req.user ? req.user.id : null,
      fileId: share.file_id,
      shareId: share.id,
      eventType: 'DOWNLOAD_COMPLETED',
      severity: 'INFO',
      ipAddress: req.ip,
      metadata: { original_name: share.original_name, download_number: share.download_count + 1 }
    });

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${share.original_name}.enc"`);
    res.setHeader('X-Encrypted-SHA256', share.sha256_hash);

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).json({ error: 'Internal server error during download' });
  }
});

// ----------------------------------------------------
// AUDIT LOGS & CLIENT EVENTS
// ----------------------------------------------------

// List audit logs for user
app.get('/api/logs', authenticateToken, (req, res) => {
  try {
    // Show logs related to this user's files, shares, or direct actions
    const logs = db.all(
      `SELECT al.*, f.original_name
       FROM access_logs al
       LEFT JOIN files f ON al.file_id = f.id
       WHERE al.user_id = ?
          OR al.file_id IN (SELECT id FROM files WHERE owner_id = ?)
          OR al.share_id IN (SELECT id FROM shares WHERE owner_id = ?)
       ORDER BY al.timestamp DESC
       LIMIT 100`,
      [req.user.id, req.user.id, req.user.id]
    );
    res.json({ logs });
  } catch (err) {
    console.error('Fetch logs error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Client records a security event (e.g. SCREENSHOT_DETECTED, BIOMETRIC_SUCCESS/FAILURE, INTEGRITY_FAILURE)
app.post('/api/logs', optionalAuth, (req, res) => {
  const { event_type, file_id, share_id, severity = 'INFO', metadata = {} } = req.body;
  if (!event_type) {
    return res.status(400).json({ error: 'event_type is required' });
  }

  logAuditEvent({
    userId: req.user ? req.user.id : null,
    fileId: file_id || null,
    shareId: share_id || null,
    eventType: event_type,
    severity: severity || 'INFO',
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    metadata: metadata
  });

  res.status(201).json({ message: 'Security event recorded' });
});

// ----------------------------------------------------
// AUTOMATIC CLEANUP & MAINTENANCE
// ----------------------------------------------------

function runAutomaticCleanup() {
  const now = Date.now();
  console.log(`[CLEANUP] Running automatic cleanup check at ${new Date(now).toISOString()}...`);

  try {
    // Expired or consumed one-time shares
    const deadShares = db.all(
      'SELECT id, file_id FROM shares WHERE expires_at < ? OR (one_time = 1 AND download_count >= 1)',
      [now]
    );

    for (const dead of deadShares) {
      // Check if there are any remaining active shares for this file
      const activeShares = db.get(
        'SELECT COUNT(*) as count FROM shares WHERE file_id = ? AND expires_at >= ? AND (one_time = 0 OR download_count = 0) AND revoked = 0',
        [dead.file_id, now]
      );

      // If no other active shares, check if owner still has the file marked as persistent
      // In SecureDrop, if an expired share has no remaining active shares, the share is cleaned up.
      console.log(`[CLEANUP] Share ${dead.id} is expired/consumed. Active shares remaining for file ${dead.file_id}: ${activeShares ? activeShares.count : 0}`);
    }
  } catch (err) {
    console.error('[CLEANUP ERROR]', err);
  }
}

// Run cleanup every 60 seconds
setInterval(runAutomaticCleanup, 60000);

// Manual cleanup endpoint
app.post('/api/cleanup', (req, res) => {
  runAutomaticCleanup();
  res.json({ message: 'Automatic cleanup executed successfully' });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    application: 'SecureDrop Backend',
    version: '1.0.0',
    timestamp: Date.now()
  });
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`====================================================`);
  console.log(`  SECUREDROP BACKEND SERVER STARTED`);
  console.log(`  Port: ${PORT}`);
  console.log(`  Local URL: http://localhost:${PORT}`);
  console.log(`  Android Emulator URL: http://10.0.2.2:${PORT}`);
  console.log(`  Listening on 0.0.0.0 (Accessible to LAN/Physical devices)`);
  console.log(`====================================================`);
});

module.exports = app;
