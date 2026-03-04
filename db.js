const sqlite3 = require('sqlite3').verbose();

// Cria/abre o ficheiro da base de dados
const db = new sqlite3.Database('./users', (err) => {
  if (err) {
    console.error('Erro ao abrir a DB', err.message);
  } else {
    console.log('Base de dados SQLite pronta.');
  }
});

// Criação das tabelas
db.serialize(() => {

  // Tabela de utilizadores (ex 1.1, 2.1)
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT NOT NULL DEFAULT 'user',
      token_version INTEGER NOT NULL DEFAULT 0
    )
  `);

  // Tabela de segredos (ex 2.2, 3.1, 3.2)
  db.run(`
    CREATE TABLE IF NOT EXISTS secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      FOREIGN KEY (owner_id) REFERENCES users(id)
    )
  `);

  // Tabela de refresh tokens (ex 4.1)
  db.run(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Tabela de auditoria (ex 5.1)
  // Imutável: sem UPDATE nem DELETE permitidos na aplicação
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      result TEXT NOT NULL,
      ip TEXT
    )
  `);

});

module.exports = db;