const sqlite3 = require('sqlite3').verbose();

// Cria/abre o ficheiro database.sqlite
const db = new sqlite3.Database('./users', (err) => {
  if (err) {
    console.error('Erro ao abrir a DB', err.message);
  } else {
    console.log('Base de dados SQLite pronta.');
  }
});

// Criação das tabelas
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT NOT NULL DEFAULT 'user'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      FOREIGN KEY (owner_id) REFERENCES users(id)
    )
  `);
});

module.exports = db;