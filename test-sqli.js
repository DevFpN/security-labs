// test-sqli.js
// Demonstra a proteção contra SQL Injection na rota GET /secrets/search
//
// A versão vulnerável seria:
//   `SELECT * FROM secrets WHERE content LIKE '%${search}%'`
// Com search = "' OR '1'='1" a query tornava-se:
//   SELECT * FROM secrets WHERE content LIKE '%' OR '1'='1%'
// ... devolvendo TODOS os segredos de TODOS os utilizadores.
//
// A versão corrigida usa query parametrizada — o input nunca é interpolado no SQL.

const BASE = 'http://localhost:3000';

async function post(path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST', headers, credentials: 'include', body: JSON.stringify(body)
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
  console.log('=== Teste SQL Injection ===\n');

  // Registar dois utilizadores
  await post('/register', { username: 'carlos', password: 'Carlos123!' });
  await post('/register', { username: 'diana',  password: 'Diana123!' });

  // Login
  const loginC = await post('/login', { username: 'carlos', password: 'Carlos123!' });
  const loginD = await post('/login', { username: 'diana',  password: 'Diana123!' });
  const tokenC = loginC.data.accessToken;
  const tokenD = loginD.data.accessToken;

  // Cada um cria um segredo
  await post('/secrets', { content: 'Segredo privado do Carlos' }, tokenC);
  await post('/secrets', { content: 'Segredo privado da Diana'  }, tokenD);
  console.log('✔ Segredos criados\n');

  // Pesquisa normal — Carlos pesquisa os seus próprios segredos
  const normalSearch = await get('/secrets/search?q=Carlos', tokenC);
  console.log('Pesquisa normal (q=Carlos):', normalSearch.status, normalSearch.data);

  // Tentativa de SQLi — Carlos tenta ver todos os segredos
  const sqliAttempt = await get("/secrets/search?q=' OR '1'='1", tokenC);
  console.log("\nTentativa SQLi (q=' OR '1'='1):", sqliAttempt.status, sqliAttempt.data);

  const allSecrets = sqliAttempt.data;
  const dianaVisible = Array.isArray(allSecrets) &&
    allSecrets.some(s => s.content && s.content.includes('Diana'));

  if (!dianaVisible) {
    console.log('\n✔ Proteção SQLi funciona: segredo da Diana não exposto.');
  } else {
    console.log('\n✘ VULNERABILIDADE: Carlos conseguiu ver o segredo da Diana!');
  }
}

run().catch(console.error);