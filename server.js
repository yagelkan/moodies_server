const express = require('express');
const cors = require('cors');

const Database = require('better-sqlite3');
const db = new Database('moods.db');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json()); // parse JSON requests

app.get('/', (req, res) => {
    res.send('Mood Journal API is running 🚀');
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

app.post('/moods', auth, (req, res) => {
    const { date, mood, notes } = req.body;
    const stmt = db.prepare('INSERT INTO moods (user_id, date, mood, notes) VALUES (?, ?, ?, ?)');
    const info = stmt.run(req.userId, date, mood, notes);
    res.json({ id: info.lastInsertRowid, date, mood, notes });
});


app.get('/moods', auth, (req, res) => {
    const rows = db.prepare('SELECT * FROM moods WHERE user_id = ?').all(req.userId);
    res.json(rows);
});

 app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
        const info = stmt.run(username, hashedPassword);
        res.json({ id: info.lastInsertRowid, username });
    } catch (err) {
        res.status(400).json({ error: 'Username already exists' });
    }
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const bcrypt = require('bcryptjs');
    const jwt = require('jsonwebtoken');
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!(user) || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({userId: user.id}, 'SECRET_KEY');
    res.json({ token });
});

function auth(req, res, next) {
  const jwt = require('jsonwebtoken');
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, "SECRET_KEY");
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(403).json({ error: "Invalid token" });
  }
}



db.prepare(`
  CREATE TABLE IF NOT EXISTS moods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    date TEXT,
    mood TEXT,
    notes TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  );
`).run();