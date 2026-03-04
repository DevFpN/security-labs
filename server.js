const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');
const path = require('path');

const app = express();

// ================= CONFIGURAÇÃO =================

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const saltRounds = 12;

// ================= SESSÕES EM MEMÓRIA =================
// Nota: solução simples para demonstrar RBAC antes de implementar JWT (ex 4.1)
// Cada entrada: sessionId -> { userId, username, role }
const sessions = {};

function generateSessionId() {
  return require('crypto').randomBytes(32).toString('hex');
}

// ================= MIDDLEWARE RBAC =================

function requireRole(role) {
  return (req, res, next) => {
    const sessionId = req.headers['x-session-id'];

    if (!sessionId || !sessions[sessionId]) {
      return res.status(401).json({ error: 'Não autenticado' });
    }

    const session = sessions[sessionId];

    if (session.role !== role) {
      return res.status(403).json({
        error: `Acesso negado. Requer papel: ${role}. O teu papel: ${session.role}`
      });
    }

    // Disponibiliza os dados da sessão no pedido para uso nas rotas
    req.session = session;
    next();
  };
}

// ================= CONTROLE DE LOGIN =================

const loginAttempts = {};
const blockedIPs = {};

// ================= ROTAS =================


// ---------- REGISTO ----------
app.post('/register', async (req, res) => {

  const { username, password, role } = req.body;
  const userRole = role === 'admin' ? 'admin' : 'user'; // só aceita 'admin' explicitamente

  // Validação básica
  if (!username || !password) {
    return res.status(400).json({
      error: "Username e password são obrigatórios"
    });
  }

  // Validação de força da password (server-side)
  if (!isPasswordStrong(password)) {
    return res.status(400).json({
      error: "Password fraca: mínimo 8 caracteres, um número e um símbolo (!@#$%^&*)"
    });
  }

  try {
    // Gerar hash com bcrypt
    const hash = await bcrypt.hash(password, saltRounds);

    // Guardar na base de dados
    db.run(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
      [username, hash, userRole],
      function (err) {

        if (err) {
          return res.status(400).json({
            error: "Username já existe"
          });
        }

        res.json({
          message: "Utilizador registado com sucesso"
        });
      }
    );

  } catch (error) {
    res.status(500).json({
      error: "Erro ao registar utilizador"
    });
  }

});


// ---------- LOGIN ----------
app.post('/login', async (req, res) => {

  const { username, password } = req.body;
  const ip = req.ip;

  console.log("Tentativa de login de IP:", ip);

  // Verificar bloqueio
  if (blockedIPs[ip] && blockedIPs[ip] > Date.now()) {
    return res.status(429).json({
      error: "IP bloqueado temporariamente"
    });
  }

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {

      if (err) {
        return res.status(500).json({ error: "Erro interno" });
      }

      if (!user) {
        return registerFailedAttempt(ip, res);
      }

      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return registerFailedAttempt(ip, res);
      }

      // Login bem-sucedido
      loginAttempts[ip] = 0;

      // Criar sessão em memória
      const sessionId = generateSessionId();
      sessions[sessionId] = {
        userId: user.id,
        username: user.username,
        role: user.role
      };

      res.json({
        message: "Login bem-sucedido",
        sessionId,
        role: user.role,
        username: user.username
      });
    }
  );
});


// ================= FUNÇÕES AUXILIARES =================


function isPasswordStrong(password) {
  const minLength = /.{8,}/;
  const hasNumber = /[0-9]/;
  const hasSpecial = /[!@#$%^&*]/;
  return minLength.test(password) && hasNumber.test(password) && hasSpecial.test(password);
}

function registerFailedAttempt(ip, res) {

  if (!loginAttempts[ip]) {
    loginAttempts[ip] = 1;
  } else {
    loginAttempts[ip]++;
  }

  if (loginAttempts[ip] >= 5) {

    blockedIPs[ip] = Date.now() + (15 * 60 * 1000);

    console.log("IP bloqueado:", ip);

    return res.status(429).json({
      error: "IP bloqueado por 15 minutos"
    });
  }

  res.status(401).json({
    error: "Credenciais inválidas"
  });
}


// ================= ENDPOINTS AUXILIARES =================

// ---------- SECRETS ----------

// Criar um segredo (utilizador autenticado)
app.post('/secrets', (req, res) => {
  const sessionId = req.headers['x-session-id'];

  if (!sessionId || !sessions[sessionId]) {
    return res.status(401).json({ error: 'Não autenticado' });
  }

  const { content } = req.body;
  if (!content) {
    return res.status(400).json({ error: 'Conteúdo obrigatório' });
  }

  const userId = sessions[sessionId].userId;

  db.run(
    'INSERT INTO secrets (owner_id, content) VALUES (?, ?)',
    [userId, content],
    function (err) {
      if (err) return res.status(500).json({ error: 'Erro ao guardar segredo' });
      res.json({ message: 'Segredo criado', id: this.lastID });
    }
  );
});

// Obter um segredo por ID
// VULNERABILIDADE CORRIGIDA: verifica que owner_id == userId da sessão
// Se o segredo não pertencer ao utilizador → 404 (não revela que existe)
app.get('/secrets/:id', (req, res) => {
  const sessionId = req.headers['x-session-id'];

  if (!sessionId || !sessions[sessionId]) {
    return res.status(401).json({ error: 'Não autenticado' });
  }

  const userId = sessions[sessionId].userId;
  const secretId = req.params.id;

  db.get(
    'SELECT * FROM secrets WHERE id = ? AND owner_id = ?',
    [secretId, userId],
    (err, secret) => {
      if (err) return res.status(500).json({ error: 'Erro interno' });

      // 404 em vez de 403: não revela que o recurso existe mas pertence a outro utilizador
      if (!secret) return res.status(404).json({ error: 'Segredo não encontrado' });

      res.json({ id: secret.id, content: secret.content });
    }
  );
});

// ---------- SYSTEM LOGS (só admin) ----------
// Demonstra o middleware requireRole em ação:
// - user normal  → 403 Forbidden
// - admin        → 200 com os registos de log
app.get('/system/logs', requireRole('admin'), (req, res) => {
  // Simula registos de sistema que só um admin deve ver
  const logs = [
    { timestamp: new Date().toISOString(), event: 'server_start', detail: 'Servidor iniciado na porta 3000' },
    { timestamp: new Date().toISOString(), event: 'login_success', detail: `Admin ${req.session.username} acedeu aos logs` },
    { timestamp: new Date().toISOString(), event: 'db_query', detail: 'SELECT * FROM users — 3 resultados' }
  ];
  res.json({ logs, accessedBy: req.session.username, role: req.session.role });
});

// ---------- LOGOUT ----------
app.post('/logout', (req, res) => {
  const sessionId = req.headers['x-session-id'];
  if (sessionId && sessions[sessionId]) {
    delete sessions[sessionId];
  }
  res.json({ message: 'Sessão terminada' });
});

// Listar IPs bloqueados
app.get('/blocked', (req, res) => {
  res.json(blockedIPs);
});

// Desbloquear IP manualmente
app.post('/unblock', (req, res) => {

  const { ip } = req.body;

  if (blockedIPs[ip]) {
    delete blockedIPs[ip];
  }

  if (loginAttempts[ip]) {
    loginAttempts[ip] = 0;
  }

  res.json({
    message: `IP ${ip} desbloqueado e tentativas resetadas`
  });
});


// ================= SERVIDOR =================

app.listen(3000, () =>
  console.log('Servidor a correr na porta 3000\nLogin: http://localhost:3000/login.html')
);