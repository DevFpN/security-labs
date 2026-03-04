// test-idor.js
// Demonstra a proteção contra IDOR (Insecure Direct Object Reference)
//
// Fluxo:
// 1. Regista utilizador A e utilizador B
// 2. Cada um cria um segredo
// 3. Utilizador A tenta aceder ao segredo do utilizador B → deve receber 404

const BASE = 'http://localhost:3000';

async function post(path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers,
    credentials: 'include',
    body: JSON.stringify(body)
  });
  return { status: res.status, data: await res.json() };
}

async function get(path, token) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Authorization': `Bearer ${token}` },
    credentials: 'include'
  });
  return { status: res.status, data: await res.json() };
}

async function run() {
  console.log('=== Teste IDOR ===\n');

  // 1. Registar utilizadores
  await post('/register', { username: 'alice', password: 'Alice123!' });
  await post('/register', { username: 'bob',   password: 'Bobby123!' });
  console.log('✔ Alice e Bob registados\n');

  // 2. Login — guarda o accessToken JWT
  const loginA = await post('/login', { username: 'alice', password: 'Alice123!' });
  const loginB = await post('/login', { username: 'bob',   password: 'Bobby123!' });
  const tokenA = loginA.data.accessToken;
  const tokenB = loginB.data.accessToken;
  console.log('✔ Alice accessToken:', tokenA ? tokenA.slice(0, 20) + '...' : 'ERRO');
  console.log('✔ Bob   accessToken:', tokenB ? tokenB.slice(0, 20) + '...' : 'ERRO', '\n');

  // 3. Cada um cria um segredo
  const secretA = await post('/secrets', { content: 'Segredo da Alice' }, tokenA);
  const secretB = await post('/secrets', { content: 'Segredo do Bob'   }, tokenB);
  console.log('✔ Alice criou segredo ID:', secretA.data.id);
  console.log('✔ Bob   criou segredo ID:', secretB.data.id, '\n');

  // 4. Alice acede ao seu próprio segredo → deve funcionar (200)
  const ownAccess = await get(`/secrets/${secretA.data.id}`, tokenA);
  console.log(`Alice acede ao seu segredo → ${ownAccess.status}`, ownAccess.data);

  // 5. Alice tenta aceder ao segredo do Bob → deve receber 404
  const idorAttempt = await get(`/secrets/${secretB.data.id}`, tokenA);
  console.log(`Alice tenta aceder ao segredo do Bob → ${idorAttempt.status}`, idorAttempt.data);

  if (idorAttempt.status === 404) {
    console.log('\n✔ Proteção IDOR funciona: 404 devolvido, segredo do Bob não exposto.');
  } else {
    console.log('\n✘ VULNERABILIDADE: Alice conseguiu aceder ao segredo do Bob!');
  }
}

run().catch(console.error);