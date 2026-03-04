const db = require('./db');

db.all('SELECT id, username, password, role FROM users', [], (err, rows) => {
  if (err) throw err;

  console.log('Dump da base de dados:');
  rows.forEach(row => {
    console.log(`[${row.id}] User: ${row.username} | Role: ${row.role} | Password hash: ${row.password}`);
  });
});