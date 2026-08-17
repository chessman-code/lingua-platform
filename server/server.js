/**
 * 言葉 LINGUA 后端服务（PostgreSQL 版本）
 * Express + PostgreSQL + JWT + bcrypt
 *
 * 功能：
 *  - 用户注册/登录（密码 bcrypt 加密）
 *  - 学习进度同步
 *  - 管理后台：查看所有用户、登录记录、统计数据
 *
 * 首位注册用户自动成为管理员
 * 启动：node server.js
 * 环境变量：
 *  - DATABASE_URL: PostgreSQL 连接字符串（Render 自动注入）
 *  - PORT: 端口（Render 自动注入，默认 3001）
 *  - JWT_SECRET: JWT 签名密钥（建议在 Render 配置）
 */
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

app.use(cors());
app.use(express.json());

// ---- 数据库连接 ----
// Render 部署时自动注入 DATABASE_URL
// 本地开发可设置环境变量，或回退到 SQLite 提示
if (!process.env.DATABASE_URL) {
  console.warn('⚠️  未检测到 DATABASE_URL 环境变量');
  console.warn('   本地开发请运行：export DATABASE_URL="postgresql://user:pass@localhost:5432/lingua"');
  console.warn('   或使用 Docker: docker run -d -p 5432:5432 -e POSTGRES_DB=lingua -e POSTGRES_PASSWORD=pass postgres:16');
  console.warn('   Render 部署会自动注入 DATABASE_URL，无需手动设置\n');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// ---- 数据库初始化（建表，幂等） ----
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_login_at TIMESTAMPTZ,
        login_count INTEGER DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS progress (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        lang TEXT DEFAULT 'ja',
        vocab_idx INTEGER DEFAULT 0,
        grammar_idx INTEGER DEFAULT 0,
        streak INTEGER DEFAULT 0,
        xp INTEGER DEFAULT 0,
        mastered_words INTEGER DEFAULT 0,
        study_hours REAL DEFAULT 0,
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id)
      );
      CREATE TABLE IF NOT EXISTS login_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ip TEXT,
        user_agent TEXT,
        login_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_login_logs_user ON login_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_login_logs_at ON login_logs(login_at DESC);
    `);
    console.log('✅ 数据库表已就绪');
  } finally {
    client.release();
  }
}

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
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'INVALID_INPUT' });
  if (password.length < 6) return res.status(400).json({ error: 'PASSWORD_TOO_SHORT' });

  try {
    const exists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'EMAIL_EXISTS' });

    const hash = bcrypt.hashSync(password, 10);
    // 首位用户成为管理员
    const countRes = await pool.query('SELECT COUNT(*)::int as c FROM users');
    const isAdmin = countRes.rows[0].c === 0;

    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash, is_admin) VALUES ($1,$2,$3,$4) RETURNING id, name, email, is_admin',
      [name, email, hash, isAdmin]
    );
    const user = result.rows[0];

    // 初始化进度
    await pool.query('INSERT INTO progress (user_id) VALUES ($1)', [user.id]);

    // 记录登录
    await pool.query(
      'INSERT INTO login_logs (user_id, ip, user_agent) VALUES ($1,$2,$3)',
      [user.id, req.ip, req.get('user-agent') || '']
    );
    await pool.query(
      'UPDATE users SET last_login_at = NOW(), login_count = login_count + 1 WHERE id = $1',
      [user.id]
    );

    res.json({
      token: sign(user),
      user: { id: user.id, name: user.name, email: user.email, isAdmin: !!user.is_admin }
    });
  } catch (e) {
    console.error('register error:', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// ---- 路由：登录 ----
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'INVALID_INPUT' });

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (!result.rows.length) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
    const user = result.rows[0];

    if (!bcrypt.compareSync(password, user.password_hash))
      return res.status(401).json({ error: 'INVALID_CREDENTIALS' });

    // 记录登录
    await pool.query(
      'INSERT INTO login_logs (user_id, ip, user_agent) VALUES ($1,$2,$3)',
      [user.id, req.ip, req.get('user-agent') || '']
    );
    await pool.query(
      'UPDATE users SET last_login_at = NOW(), login_count = login_count + 1 WHERE id = $1',
      [user.id]
    );

    res.json({
      token: sign(user),
      user: { id: user.id, name: user.name, email: user.email, isAdmin: !!user.is_admin }
    });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// ---- 路由：获取当前用户 ----
app.get('/api/me', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, name, email, is_admin FROM users WHERE id = $1', [req.payload.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'USER_NOT_FOUND' });
    const u = r.rows[0];
    res.json({ user: { ...u, isAdmin: !!u.is_admin } });
  } catch (e) {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// ---- 路由：保存进度 ----
app.post('/api/progress', auth, async (req, res) => {
  const { lang, vocabIdx, grammarIdx, streak, xp, masteredWords, studyHours } = req.body;
  try {
    await pool.query(`
      UPDATE progress SET
        lang = COALESCE($1, lang),
        vocab_idx = COALESCE($2, vocab_idx),
        grammar_idx = COALESCE($3, grammar_idx),
        streak = COALESCE($4, streak),
        xp = COALESCE($5, xp),
        mastered_words = COALESCE($6, mastered_words),
        study_hours = COALESCE($7, study_hours),
        updated_at = NOW()
      WHERE user_id = $8
    `, [lang, vocabIdx, grammarIdx, streak, xp, masteredWords, studyHours, req.payload.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// ---- 路由：获取进度 ----
app.get('/api/progress', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM progress WHERE user_id = $1', [req.payload.id]);
    if (!r.rows.length) return res.json({});
    const p = r.rows[0];
    res.json({
      lang: p.lang,
      vocabIdx: p.vocab_idx,
      grammarIdx: p.grammar_idx,
      streak: p.streak,
      xp: p.xp,
      masteredWords: p.mastered_words,
      studyHours: p.study_hours
    });
  } catch (e) {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// ---- 管理后台路由 ----
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT u.id, u.name, u.email, u.is_admin, u.created_at, u.last_login_at, u.login_count,
             p.lang, p.xp, p.streak
      FROM users u
      LEFT JOIN progress p ON p.user_id = u.id
      ORDER BY u.created_at DESC
    `);
    res.json({ users: r.rows.map(u => ({ ...u, isAdmin: !!u.is_admin })) });
  } catch (e) {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/api/admin/login-logs', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT l.id, l.login_at, l.ip, u.name, u.email
      FROM login_logs l JOIN users u ON l.user_id = u.id
      ORDER BY l.login_at DESC LIMIT 200
    `);
    res.json({ logs: r.rows });
  } catch (e) {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  try {
    const totalUsers = await pool.query('SELECT COUNT(*)::int as c FROM users');
    const loginsToday = await pool.query(`SELECT COUNT(*)::int as c FROM login_logs WHERE login_at::date = NOW()::date`);
    const activeToday = await pool.query(`SELECT COUNT(DISTINCT user_id)::int as c FROM login_logs WHERE login_at::date = NOW()::date`);
    const totalLogins = await pool.query('SELECT COUNT(*)::int as c FROM login_logs');
    res.json({
      totalUsers: totalUsers.rows[0].c,
      loginsToday: loginsToday.rows[0].c,
      activeToday: activeToday.rows[0].c,
      totalLogins: totalLogins.rows[0].c
    });
  } catch (e) {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// ---- 健康检查 ----
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, ts: Date.now(), db: 'connected' });
  } catch {
    res.status(503).json({ ok: false, db: 'disconnected' });
  }
});

// ---- 启动 ----
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🌐 言葉 LINGUA 后端已启动: http://localhost:${PORT}`);
    console.log(`📋 管理后台: 首位注册用户自动成为管理员`);
    console.log(`💾 数据库: ${process.env.DATABASE_URL ? 'PostgreSQL (远程)' : 'PostgreSQL (本地配置)'}`);
  });
}).catch(e => {
  console.error('❌ 数据库初始化失败:', e.message);
  console.error('   请检查 DATABASE_URL 环境变量是否正确');
  process.exit(1);
});
