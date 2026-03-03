const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');
const path = require('path');

const app = express();

// ================= CONFIGURAÇÃO =================

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const saltRounds = 12;

// ================= CONTROLE DE LOGIN =================

const loginAttempts = {};
const blockedIPs = {};

// ================= ROTAS =================


// ---------- REGISTO ----------
app.post('/register', async (req, res) => {

  const { username, password } = req.body;

  // Validação básica
  if (!username || !password) {
    return res.status(400).json({
      error: "Username e password são obrigatórios"
    });
  }

  try {
    // Gerar hash com bcrypt
    const hash = await bcrypt.hash(password, saltRounds);

    // Guardar na base de dados
    db.run(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hash],
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

      res.json({
        message: "Login bem-sucedido"
      });
    }
  );
});


// ================= FUNÇÕES AUXILIARES =================

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