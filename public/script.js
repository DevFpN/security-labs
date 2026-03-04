// ================= EX 1.2 — FORÇA DA PASSWORD =================

function checkPasswordStrength(password) {
  const minLength  = /.{8,}/;
  const hasNumber  = /[0-9]/;
  const hasSpecial = /[!@#$%^&*]/;

  if (!minLength.test(password))  return 'Fraca: mínimo 8 caracteres';
  if (!hasNumber.test(password))  return 'Fraca: precisa de número';
  if (!hasSpecial.test(password)) return 'Fraca: precisa de símbolo';

  return 'Forte';
}

const passwordInput    = document.getElementById('password');
const strengthMessage  = document.getElementById('strengthMessage');

if (passwordInput) {
  passwordInput.addEventListener('input', () => {
    strengthMessage.textContent = checkPasswordStrength(passwordInput.value);
  });
}

// ================= EX 4.1 — GESTÃO DO ACCESS TOKEN =================
// O access token é guardado em memória (não em localStorage — protege contra XSS)
// O refresh token está num cookie HttpOnly gerido pelo servidor

let accessToken = null;

async function refreshAccessToken() {
  const res  = await fetch('/refresh', { method: 'POST', credentials: 'include' });
  const data = await res.json();
  if (res.ok) {
    accessToken = data.accessToken;
    return true;
  }
  return false;
}

// Wrapper para fetch autenticado — renova o token automaticamente se expirar
async function authFetch(url, options = {}) {
  options.headers = { ...options.headers, 'Authorization': `Bearer ${accessToken}` };
  options.credentials = 'include';

  let res = await fetch(url, options);

  // Se o token expirou (401), tenta renovar e repetir o pedido
  if (res.status === 401) {
    const renewed = await refreshAccessToken();
    if (renewed) {
      options.headers['Authorization'] = `Bearer ${accessToken}`;
      res = await fetch(url, options);
    }
  }

  return res;
}

// ================= EX 3.2 — SANITIZAÇÃO XSS (DOMPurify) =================
// Antes de mostrar qualquer conteúdo no DOM, passa pelo DOMPurify
// Isto impede que <script>alert(1)</script> guardado num segredo seja executado

function safeRender(element, html) {
  element.innerHTML = DOMPurify.sanitize(html);
}

// ================= LOGIN =================

const loginForm = document.getElementById('loginForm');
if (loginForm) {
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (checkPasswordStrength(passwordInput.value) !== 'Forte') {
      alert('Password fraca. Corrija antes de enviar.');
      return;
    }

    const response = await fetch('/login', {
      method:      'POST',
      credentials: 'include',
      headers:     { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: passwordInput.value
      })
    });

    const data = await response.json();

    if (response.ok) {
      // Guarda o access token em memória (não em localStorage)
      accessToken = data.accessToken;
      alert(`Login bem-sucedido. Papel: ${data.role}`);
    } else {
      alert(data.error);
    }
  });
}

// ================= REGISTO =================

const registerForm = document.getElementById('registerForm');
if (registerForm) {
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (checkPasswordStrength(passwordInput.value) !== 'Forte') {
      alert('Password fraca. Corrija antes de enviar.');
      return;
    }

    const response = await fetch('/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: passwordInput.value
      })
    });

    const data = await response.json();
    alert(data.message || data.error);

    if (response.ok) {
      window.location.href = 'login.html';
    }
  });
}