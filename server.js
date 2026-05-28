const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Health check routes
app.get('/', (req, res) => {
  res.send('Backend is running');
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const db = new sqlite3.Database('./database.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    phone TEXT,
    message TEXT,
    gender TEXT,
    nationality TEXT,
    selectedCelebrity TEXT,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'new'
  )`);

  const hashed = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
  db.run(`INSERT OR IGNORE INTO admins (username, password) VALUES (?,?)`,
    [process.env.ADMIN_USERNAME, hashed]);
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// POST /api/apply - handle membership form submission
app.post("/api/apply", (req, res) => {
  try {
    const { fullName, email, gender, phone, nationality, favoriteCelebrity, reason } = req.body;

    if (!fullName || !email) {
      return res.status(400).json({ message: "Name and email are required" });
    }

    const sql = `INSERT INTO applications
      (name, email, phone, gender, nationality, selectedCelebrity, message)
      VALUES (?,?,?,?,?,?,?)`;

    db.run(sql, [fullName, email, phone, gender, nationality, favoriteCelebrity, reason], function(err) {
      if (err) {
        console.error("DB insert error:", err);
        return res.status(500).json({ message: "Database error" });
      }
      console.log("Application saved with ID:", this.lastID);
      res.json({ success: true, message: "Application submitted successfully!" });
    });

  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// POST /api/login - admin login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM admins WHERE username =?', [username], (err, admin) => {
    if (err ||!admin) return res.status(401).json({ message: 'Invalid credentials' });

    if (bcrypt.compareSync(password, admin.password)) {
      const token = jwt.sign({ id: admin.id, username: admin.username }, process.env.JWT_SECRET, { expiresIn: '24h' });
      res.json({ token });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  });
});

// GET /api/applications - view all submissions, protected
app.get('/api/applications', authenticateToken, (req, res) => {
  db.all('SELECT * FROM applications ORDER BY submitted_at DESC', [], (err, rows) => {
    if (err) {
      console.error("DB fetch error:", err);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json(rows);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
