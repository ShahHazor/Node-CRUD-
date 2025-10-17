// routes/auth.js
const express = require('express');
const router = express.Router();
const pool = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
dotenv.config();

const ACCESS_EXPIRES = process.env.ACCESS_TOKEN_EXPIRES_IN || '5m';
const REFRESH_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || '7', 10);
router.use(cors());
function generateAccessToken(user) {
  // short-lived access token
  return jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
}

function generateRefreshToken(user) {
  // refresh token longer lived; we still sign it but will also save server-side
  return jwt.sign({ userId: user.id }, process.env.JWT_REFRESH_SECRET, { expiresIn: `${REFRESH_DAYS}d` });
}

// register
router.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'username and password required' });

    const hashed = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed]);
    return res.status(201).json({ message: 'User created', userId: result.insertId });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ message: 'Username already exists' });
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'username and password required' });

    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    const user = rows[0];
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Invalid credentials' });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // store refresh token in DB with expiry
    const expiresAt = new Date(Date.now() + REFRESH_DAYS * 24 * 60 * 60 * 1000); // days -> ms
    await pool.query('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, refreshToken, expiresAt]);

    // return both tokens (you can also set refresh token as httpOnly cookie)
    res.json({
      accessToken,
      refreshToken,
      expiresIn: ACCESS_EXPIRES
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// token - refresh access token using refresh token
router.post('/token', async (req, res) => {
  try {
    // client may send refresh token in body or cookie
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ message: 'Refresh token required' });

    // verify signature first
    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, payload) => {
      if (err) return res.status(403).json({ message: 'Invalid or expired refresh token' });

      // check that refresh token exists in DB and not expired
      const [rows] = await pool.query('SELECT * FROM refresh_tokens WHERE token = ?', [refreshToken]);
      const row = rows[0];
      if (!row) return res.status(403).json({ message: 'Refresh token not recognized' });

      const now = new Date();
      if (new Date(row.expires_at) < now) {
        // delete expired token
        await pool.query('DELETE FROM refresh_tokens WHERE id = ?', [row.id]);
        return res.status(403).json({ message: 'Refresh token expired' });
      }

      // fetch user for signing
      const [urows] = await pool.query('SELECT id, username FROM users WHERE id = ?', [row.user_id]);
      const user = urows[0];
      if (!user) return res.status(404).json({ message: 'User not found' });

      // generate new access token (and optionally a new refresh token)
      const accessToken = generateAccessToken(user);
      // Optionally: rotate refresh token (recommended). We'll issue a new refresh token and delete old one.
      const newRefreshToken = generateRefreshToken(user);
      const newExpiresAt = new Date(Date.now() + REFRESH_DAYS * 24 * 60 * 60 * 1000);

      // perform rotation: delete old token, insert new one
      await pool.query('DELETE FROM refresh_tokens WHERE id = ?', [row.id]);
      await pool.query('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, newRefreshToken, newExpiresAt]);

      res.json({
        accessToken,
        refreshToken: newRefreshToken,
        expiresIn: ACCESS_EXPIRES
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// logout - revoke refresh token
router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ message: 'Refresh token required' });

    await pool.query('DELETE FROM refresh_tokens WHERE token = ?', [refreshToken]);
    res.json({ message: 'Logged out (refresh token revoked)' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
