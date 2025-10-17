// server.js
const express = require('express');
const app = express();
const dotenv = require('dotenv');
dotenv.config();
const authRoutes = require('./routes/auth');
const { authenticateToken } = require('./authMiddleware');
const pool = require('./db');
const cookieParser = require('cookie-parser');

app.use(express.json());
app.use(cookieParser());

// routes
app.use('/auth', authRoutes);

// example protected route
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    // req.user populated by middleware
    const [rows] = await pool.query('SELECT id, username, created_at FROM users WHERE id = ?', [req.user.id]);
    const user = rows[0];
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
