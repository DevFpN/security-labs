// test-idor.js
// Demonstra a proteção contra IDOR (Insecure Direct Object Reference)
//
// Fluxo:
// 1. Regista utilizador A e utilizador B
// 2. Cada um cria um segredo
// 3. Utilizador A tenta aceder ao segredo do utilizador B → deve receber 404

const BASE = 'http://localhost:3000';

async function post(path, body, sessionId) {
  const headers = { 'Content-Type': 'application/json' };
  if (sessionId) headers['x-session-id'] = sessionId;
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body)
  });
  return { status: res.status, data: await res.json() };
}

async function get(path, sessionId) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'x-session-id': sessionId }
  });
  return { status: res.status, data: await res.json() };
}

async function run() {
  console.log('=== Teste IDOR ===\n');

  // 1. Registar utilizadores
  await post('/register', { username: 'alice', password: 'Alice123!' });
  await post('/register', { username: 'bob',   password: 'Bobby123!' });
  console.log('✔ Alice e Bob registados\n');

  // 2. Login
  const loginA = await post('/login', { username: 'alice', password: 'Alice123!' });
  const loginB = await post('/login', { username: 'bob',   password: 'Bobby123!' });
  const sessionA = loginA.data.sessionId;
  const sessionB = loginB.data.sessionId;
  console.log('✔ Alice sessionId:', sessionA);
  console.log('✔ Bob   sessionId:', sessionB, '\n');

  // 3. Cada um cria um segredo
  const secretA = await post('/secrets', { content: 'Segredo da Alice' }, sessionA);
  const secretB = await post('/secrets', { content: 'Segredo do Bob'   }, sessionB);
  console.log('✔ Alice criou segredo ID:', secretA.data.id);
  console.log('✔ Bob   criou segredo ID:', secretB.data.id, '\n');

  // 4. Alice acede ao seu próprio segredo → deve funcionar (200)
  const ownAccess = await get(`/secrets/${secretA.data.id}`, sessionA);
  console.log(`Alice acede ao seu segredo → ${ownAccess.status}`, ownAccess.data);

  // 5. Alice tenta aceder ao segredo do Bob → deve receber 404
  const idorAttempt = await get(`/secrets/${secretB.data.id}`, sessionA);
  console.log(`Alice tenta aceder ao segredo do Bob → ${idorAttempt.status}`, idorAttempt.data);

  if (idorAttempt.status === 404) {
    console.log('\n✔ Proteção IDOR funciona: 404 devolvido, segredo do Bob não exposto.');
  } else {
    console.log('\n✘ VULNERABILIDADE: Alice conseguiu aceder ao segredo do Bob!');
  }
}

run().catch(console.error);