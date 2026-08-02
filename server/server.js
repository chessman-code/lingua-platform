/**
 * 言葉 LINGUA 后端服务
 * Express + SQLite + JWT + bcrypt
 *
 * 功能：
 *  - 用户注册/登录（密码 bcrypt 加密）
 *  - 学习进度同步
 *  - 管理后台：查看所有用户、登录记录、统计数据
 *
 * 首位注册用户自动成为管理员
 * 启动：node server.js （默认端口 3001）
 */
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

app.use(cors());
app.use(express.json());

// ---- 数据库初始化 ----
const db = new Database('lingua.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    last_login_at TEXT,
    login_count INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    lang TEXT DEFAULT 'ja',
    vocab_idx INTEGER DEFAULT 0,
    grammar_idx INTEGER DEFAULT 0,
    streak INTEGER DEFAULT 0,
    xp INTEGER DEFAULT 0,
    mastered_words INTEGER DEFAULT 0,
    study_hours REAL DEFAULT 0,
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(user_id)
  );
  CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT,
    login_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// ---- 工具函数 ----
function sign(user) {
  return jwt.sign(
    { id: user.id, email: user.email, isAdmin: user.is_admin },
    SECRET,
    { expiresIn: '7d' }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'NO_TOKEN' });
  try {
    req.payload = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'INVALID_TOKEN' });
  }
}

function adminOnly(req, res, next) {
  if (!req.payload.isAdmin) return res.status(403).json({ error: 'ADMIN_ONLY' });
  next();
}

// ---- 路由：注册 ----
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'INVALID_INPUT' });
  if (password.length < 6) return res.status(400).json({ error: 'PASSWORD_TOO_SHORT' });

  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) return res.status(409).json({ error: 'EMAIL_EXISTS' });

  const hash = bcrypt.hashSync(password, 10);
  // 首位用户成为管理员
  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const isAdmin = userCount === 0 ? 1 : 0;

  const info = db.prepare(
    'INSERT INTO users (name, email, password_hash, is_admin) VALUES (?,?,?,?)'
  ).run(name, email, hash, isAdmin);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);

  // 初始化进度
  db.prepare('INSERT INTO progress (user_id) VALUES (?)').run(user.id);

  // 记录登录
  db.prepare('INSERT INTO login_logs (user_id, ip, user_agent) VALUES (?,?,?)')
    .run(user.id, req.ip, req.get('user-agent') || '');
  db.prepare('UPDATE users SET last_login_at = datetime(\'now\'), login_count = login_count + 1 WHERE id = ?')
    .run(user.id);

  res.json({ token: sign(user), user: { id: user.id, name: user.name, email: user.email, isAdmin: !!user.is_admin } });
});

// ---- 路由：登录 ----
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'INVALID_INPUT' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });

  if (!bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'INVALID_CREDENTIALS' });

  // 记录登录
  db.prepare('INSERT INTO login_logs (user_id, ip, user_agent) VALUES (?,?,?)')
    .run(user.id, req.ip, req.get('user-agent') || '');
  db.prepare('UPDATE users SET last_login_at = datetime(\'now\'), login_count = login_count + 1 WHERE id = ?')
    .run(user.id);

  res.json({ token: sign(user), user: { id: user.id, name: user.name, email: user.email, isAdmin: !!user.is_admin } });
});

// ---- 路由：获取当前用户 ----
app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, is_admin FROM users WHERE id = ?').get(req.payload.id);
  if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND' });
  res.json({ user: { ...user, isAdmin: !!user.is_admin } });
});

// ---- 路由：保存进度 ----
app.post('/api/progress', auth, (req, res) => {
  const { lang, vocabIdx, grammarIdx, streak, xp, masteredWords, studyHours } = req.body;
  db.prepare(`
    UPDATE progress SET
      lang = COALESCE(?, lang),
      vocab_idx = COALESCE(?, vocab_idx),
      grammar_idx = COALESCE(?, grammar_idx),
      streak = COALESCE(?, streak),
      xp = COALESCE(?, xp),
      mastered_words = COALESCE(?, mastered_words),
      study_hours = COALESCE(?, study_hours),
      updated_at = datetime('now')
    WHERE user_id = ?
  `).run(lang, vocabIdx, grammarIdx, streak, xp, masteredWords, studyHours, req.payload.id);
  res.json({ ok: true });
});

// ---- 路由：获取进度 ----
app.get('/api/progress', auth, (req, res) => {
  const p = db.prepare('SELECT * FROM progress WHERE user_id = ?').get(req.payload.id);
  if (!p) return res.json({});
  res.json({
    lang: p.lang,
    vocabIdx: p.vocab_idx,
    grammarIdx: p.grammar_idx,
    streak: p.streak,
    xp: p.xp,
    masteredWords: p.mastered_words,
    studyHours: p.study_hours
  });
});

// ---- 管理后台路由 ----
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.name, u.email, u.is_admin, u.created_at, u.last_login_at, u.login_count,
           (SELECT lang FROM progress WHERE user_id = u.id) as lang,
           (SELECT xp FROM progress WHERE user_id = u.id) as xp,
           (SELECT streak FROM progress WHERE user_id = u.id) as streak
    FROM users u ORDER BY u.created_at DESC
  `).all();
  res.json({ users });
});

app.get('/api/admin/login-logs', auth, adminOnly, (req, res) => {
  const logs = db.prepare(`
    SELECT l.id, l.login_at, l.ip, u.name, u.email
    FROM login_logs l JOIN users u ON l.user_id = u.id
    ORDER BY l.login_at DESC LIMIT 200
  `).all();
  res.json({ logs });
});

app.get('/api/admin/stats', auth, adminOnly, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const loginsToday = db.prepare(`SELECT COUNT(*) as c FROM login_logs WHERE date(login_at) = date('now')`).get().c;
  const activeToday = db.prepare(`SELECT COUNT(DISTINCT user_id) as c FROM login_logs WHERE date(login_at) = date('now')`).get().c;
  const totalLogins = db.prepare('SELECT COUNT(*) as c FROM login_logs').get().c;
  res.json({ totalUsers, loginsToday, activeToday, totalLogins });
});

// ---- 健康检查 ----
app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

app.listen(PORT, () => {
  console.log(`🌐 言葉 LINGUA 后端已启动: http://localhost:${PORT}`);
  console.log(`📋 管理后台: 首位注册用户自动成为管理员`);
  console.log(`💾 数据库: lingua.db`);
});
