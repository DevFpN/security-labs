const sqlite3 = require('sqlite3').verbose();

// Cria/abre o ficheiro database.sqlite
const db = new sqlite3.Database('./users', (err) => {
  if (err) {
    console.error('Erro ao abrir a DB', err.message);
  } else {
    console.log('Base de dados SQLite pronta.');
  }
});

// Criação da tabela users
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);
});

module.exports = db;