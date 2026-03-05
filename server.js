require('dotenv').config();

const express    = require('express');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const helmet     = require('helmet');
const cors       = require('cors');
const crypto     = require('crypto');
const path       = require('path');
const cookieParser = require('cookie-parser');
const db         = require('./db');

const app = express();

// ================= CONFIGURAÇÃO =================

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const saltRounds = 12;

// ================= EX 4.2 — CORS =================
// Só aceita pedidos da origem definida em .env
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN,
  credentials: true
}));

// ================= EX 4.2 — SECURITY HEADERS (helmet) =================
// Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, etc.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'"],
      imgSrc:     ["'self'"]
    }
  },
  frameguard:       { action: 'deny' },
  hsts:             { maxAge: 31536000, includeSubDomains: true }
}));

// ================= EX 3.2 — CIFRA EM REPOUSO =================
// Usa AES-256-GCM. A chave vem do .env e nunca está no código.
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');

function encrypt(text) {
  const iv         = crypto.randomBytes(12);
  const cipher     = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted  = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const authTag    = cipher.getAuthTag();
  // Guarda iv + authTag + ciphertext tudo junto em base64
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function decrypt(data) {
  const buf        = Buffer.from(data, 'base64');
  const iv         = buf.slice(0, 12);
  const authTag    = buf.slice(12, 28);
  const encrypted  = buf.slice(28);
  const decipher   = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);
  return decipher.update(encrypted) + decipher.final('utf8');
}

// ================= EX 5.1 — SANITIZAÇÃO DE LOGS =================
// Mascara emails, tokens JWT e passwords antes de escrever para o log
function sanitizeLog(message) {
  return message
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[EMAIL]')
    .replace(/eyJ[a-zA-Z0-9._-]{10,}/g, '[TOKEN]')
    .replace(/"password"\s*:\s*"[^"]*"/g, '"password":"[REDACTED]"');
}

function safeLog(message) {
  console.log(sanitizeLog(message));
}

// ================= EX 5.1 — REGISTO DE AUDITORIA =================
// Imutável: só INSERT, nunca UPDATE nem DELETE
function auditLog(userId, action, result, ip) {
  const timestamp = new Date().toISOString();
  db.run(
    'INSERT INTO audit_log (user_id, action, timestamp, result, ip) VALUES (?, ?, ?, ?, ?)',
    [userId || null, action, timestamp, result, ip || null]
  );
}

// ================= EX 4.1 — JWT =================
// Access token: curta duração (5 min)
// Refresh token: longa duração (7 dias), guardado em base de dados

function generateAccessToken(user) {
  return jwt.sign(
    { userId: user.id, username: user.username, role: user.role, version: user.token_version },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: '5m' }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    { userId: user.id, version: user.token_version },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
}

// Middleware de autenticação JWT (substitui as sessões em memória do ex 2.1)
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token      = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ error: 'Token de acesso em falta' });
  }

  jwt.verify(token, process.env.JWT_ACCESS_SECRET, (err, payload) => {
    if (err) {
      return res.status(401).json({ error: 'Token inválido ou expirado' });
    }

    // Verificar token_version para invalidar tokens após mudança de password
    db.get('SELECT token_version FROM users WHERE id = ?', [payload.userId], (err, user) => {
      if (err || !user) return res.status(401).json({ error: 'Utilizador não encontrado' });

      if (user.token_version !== payload.version) {
        return res.status(401).json({ error: 'Token invalidado. Faz login novamente.' });
      }

      req.user = payload;
      next();
    });
  });
}

// ================= MIDDLEWARE RBAC (ex 2.1) =================
// Agora usa JWT em vez de sessões em memória
function requireRole(role) {
  return [requireAuth, (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({
        error: `Acesso negado. Requer papel: ${role}. O teu papel: ${req.user.role}`
      });
    }
    next();
  }];
}

// ================= CONTROLE DE LOGIN (ex 1.2) =================

const loginAttempts = {};
const blockedIPs    = {};

// ================= ROTAS =================


// ---------- REGISTO ----------
app.post('/register', async (req, res) => {

  const { username, password, role } = req.body;
  const userRole = role === 'admin' ? 'admin' : 'user';

  if (!username || !password) {
    return res.status(400).json({ error: 'Username e password são obrigatórios' });
  }

  if (!isPasswordStrong(password)) {
    return res.status(400).json({
      error: 'Password fraca: mínimo 8 caracteres, um número e um símbolo (!@#$%^&*)'
    });
  }

  try {
    const hash = await bcrypt.hash(password, saltRounds);

    db.run(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, hash, userRole],
      function (err) {
        if (err) {
          return res.status(400).json({ error: 'Username já existe' });
        }
        auditLog(this.lastID, 'register', 'success', req.ip);
        res.json({ message: 'Utilizador registado com sucesso' });
      }
    );

  } catch (error) {
    res.status(500).json({ error: 'Erro ao registar utilizador' });
  }

});


// ---------- LOGIN ----------
app.post('/login', async (req, res) => {

  const { username, password } = req.body;
  const ip = req.ip;

  safeLog(`Tentativa de login de IP: ${ip}`);

  // Verificar bloqueio (ex 1.2)
  if (blockedIPs[ip] && blockedIPs[ip] > Date.now()) {
    auditLog(null, 'login_blocked', 'fail', ip);
    return res.status(429).json({ error: 'IP bloqueado temporariamente' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {

    if (err) return res.status(500).json({ error: 'Erro interno' });

    if (!user) return registerFailedAttempt(ip, res, null);

    const match = await bcrypt.compare(password, user.password);
    if (!match) return registerFailedAttempt(ip, res, user.id);

    // Login bem-sucedido
    loginAttempts[ip] = 0;
    auditLog(user.id, 'login', 'success', ip);

    // Gerar tokens JWT (ex 4.1)
    const accessToken  = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Guardar refresh token na base de dados
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    db.run(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
      [user.id, refreshToken, expiresAt]
    );

    // Refresh token em cookie HttpOnly (não acessível por JS — protege contra XSS)
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure:   false, // mudar para true em produção com HTTPS
      sameSite: 'strict',
      maxAge:   7 * 24 * 60 * 60 * 1000
    });

    res.json({
      message:     'Login bem-sucedido',
      accessToken,
      role:        user.role,
      username:    user.username
    });
  });
});


// ---------- REFRESH TOKEN (ex 4.1) ----------
// Emite novo access token usando o refresh token do cookie HttpOnly
app.post('/refresh', (req, res) => {
  const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token em falta' });
  }

  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Refresh token inválido' });

    // Verificar se o token existe na base de dados e não expirou
    db.get(
      'SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > ?',
      [refreshToken, Date.now()],
      (err, row) => {
        if (err || !row) return res.status(401).json({ error: 'Refresh token revogado ou expirado' });

        db.get('SELECT * FROM users WHERE id = ?', [payload.userId], (err, user) => {
          if (err || !user) return res.status(401).json({ error: 'Utilizador não encontrado' });

          // Verificar versão do token (invalidado após mudança de password)
          if (user.token_version !== payload.version) {
            return res.status(401).json({ error: 'Token invalidado. Faz login novamente.' });
          }

          const newAccessToken = generateAccessToken(user);
          res.json({ accessToken: newAccessToken });
        });
      }
    );
  });
});


// ---------- LOGOUT (ex 4.1) ----------
app.post('/logout', requireAuth, (req, res) => {
  const refreshToken = req.cookies?.refreshToken;

  if (refreshToken) {
    db.run('DELETE FROM refresh_tokens WHERE token = ?', [refreshToken]);
  }

  res.clearCookie('refreshToken');
  auditLog(req.user.userId, 'logout', 'success', req.ip);
  res.json({ message: 'Sessão terminada' });
});


// ---------- SECRETS — criar (ex 2.2, 3.2) ----------
app.post('/secrets', requireAuth, (req, res) => {

  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Conteúdo obrigatório' });

  // Ex 3.2: cifra o conteúdo antes de guardar na base de dados
  const encryptedContent = encrypt(content);

  db.run(
    'INSERT INTO secrets (owner_id, content) VALUES (?, ?)',
    [req.user.userId, encryptedContent],
    function (err) {
      if (err) return res.status(500).json({ error: 'Erro ao guardar segredo' });
      auditLog(req.user.userId, 'create_secret', 'success', req.ip);
      res.json({ message: 'Segredo criado', id: this.lastID });
    }
  );
});


// ---------- SECRETS — pesquisa (ex 3.1) ----------
// Versão VULNERÁVEL (comentada, para comparação):
// db.all(`SELECT * FROM secrets WHERE content LIKE '%${search}%'`, ...)
//
// Versão CORRIGIDA: query parametrizada para obter os segredos do utilizador,
// depois filtragem em memória sobre o texto decifrado (necessário porque o
// conteúdo está cifrado na base de dados e não é pesquisável com LIKE)
app.get('/secrets/search', requireAuth, (req, res) => {

  const search = req.query.q || '';

  db.all(
    'SELECT id, content FROM secrets WHERE owner_id = ?',
    [req.user.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Erro na pesquisa' });

      // Decifra e filtra em memória pelo termo de pesquisa
      const results = rows
        .map(row => ({ id: row.id, content: decrypt(row.content) }))
        .filter(row => row.content.includes(search));

      res.json(results);
    }
  );
});


// ---------- SECRETS — obter por ID (ex 2.2, 3.2) ----------
app.get('/secrets/:id', requireAuth, (req, res) => {

  db.get(
    'SELECT * FROM secrets WHERE id = ? AND owner_id = ?',
    [req.params.id, req.user.userId],
    (err, secret) => {
      if (err) return res.status(500).json({ error: 'Erro interno' });
      // 404 em vez de 403: não revela que o recurso existe (ex 2.2)
      if (!secret) return res.status(404).json({ error: 'Segredo não encontrado' });

      // Ex 3.2: decifra apenas ao devolver ao utilizador autorizado
      res.json({ id: secret.id, content: decrypt(secret.content) });
    }
  );
});


// ---------- SYSTEM LOGS — só admin (ex 2.1) ----------
app.get('/system/logs', requireRole('admin'), (req, res) => {

  db.all('SELECT * FROM audit_log ORDER BY id DESC LIMIT 50', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Erro ao obter logs' });
    res.json({ logs: rows, accessedBy: req.user.username });
  });
});


// ---------- MUDAR PASSWORD (ex 4.1 — invalida tokens) ----------
app.post('/change-password', requireAuth, async (req, res) => {

  const { currentPassword, newPassword } = req.body;

  if (!isPasswordStrong(newPassword)) {
    return res.status(400).json({ error: 'Nova password fraca' });
  }

  db.get('SELECT * FROM users WHERE id = ?', [req.user.userId], async (err, user) => {
    if (err || !user) return res.status(500).json({ error: 'Erro interno' });

    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.status(401).json({ error: 'Password atual incorreta' });

    const newHash = await bcrypt.hash(newPassword, saltRounds);

    // Incrementa token_version → invalida todos os tokens JWT existentes
    db.run(
      'UPDATE users SET password = ?, token_version = token_version + 1 WHERE id = ?',
      [newHash, user.id],
      (err) => {
        if (err) return res.status(500).json({ error: 'Erro ao atualizar password' });

        // Apaga todos os refresh tokens do utilizador
        db.run('DELETE FROM refresh_tokens WHERE user_id = ?', [user.id]);

        auditLog(user.id, 'change_password', 'success', req.ip);
        res.json({ message: 'Password alterada. Faz login novamente.' });
      }
    );
  });
});


// ================= ENDPOINTS AUXILIARES =================

// Listar IPs bloqueados
app.get('/blocked', (req, res) => {
  res.json(blockedIPs);
});

// Desbloquear IP manualmente
app.post('/unblock', (req, res) => {
  const { ip } = req.body;
  if (blockedIPs[ip])    delete blockedIPs[ip];
  if (loginAttempts[ip]) loginAttempts[ip] = 0;
  res.json({ message: `IP ${ip} desbloqueado e tentativas resetadas` });
});


// ================= FUNÇÕES AUXILIARES =================

function isPasswordStrong(password) {
  const minLength  = /.{8,}/;
  const hasNumber  = /[0-9]/;
  const hasSpecial = /[!@#$%^&*]/;
  return minLength.test(password) && hasNumber.test(password) && hasSpecial.test(password);
}

function registerFailedAttempt(ip, res, userId) {
  loginAttempts[ip] = (loginAttempts[ip] || 0) + 1;

  auditLog(userId, 'login', 'fail', ip);

  if (loginAttempts[ip] >= 5) {
    blockedIPs[ip] = Date.now() + 15 * 60 * 1000;
    safeLog(`IP bloqueado: ${ip}`);
    return res.status(429).json({ error: 'IP bloqueado por 15 minutos' });
  }

  res.status(401).json({ error: 'Credenciais inválidas' });
}


// ================= SERVIDOR =================

app.listen(3000, () =>
  console.log('Servidor a correr na porta 3000\nLogin: http://localhost:3000/login.html')
);