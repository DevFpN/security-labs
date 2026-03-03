const db = require('./db');

db.all('SELECT username, password FROM users', [], (err, rows) => {
  if (err) throw err;

  console.log('Dump da base de dados:');
  rows.forEach(row => {
    console.log(`User: ${row.username} | Password: ${row.password}`);
  });
});