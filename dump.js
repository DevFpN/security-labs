const db = require('./db');

db.all('SELECT id, username, password, role FROM users', [], (err, rows) => {
  if (err) throw err;

  console.log('=== Tabela: users ===');
  rows.forEach(row => {
    console.log(`[${row.id}] User: ${row.username} | Role: ${row.role} | Password hash: ${row.password}`);
  });

  db.all('SELECT id, owner_id, content FROM secrets', [], (err, secrets) => {
    if (err) throw err;

    console.log('\n=== Tabela: secrets (conteúdo cifrado) ===');
    secrets.forEach(row => {
      console.log(`[${row.id}] Owner ID: ${row.owner_id} | Content (cifrado): ${row.content}`);
    });
  });
});