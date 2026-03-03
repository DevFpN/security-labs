const form = document.getElementById('loginForm');
const passwordInput = document.getElementById('password');
const strengthMessage = document.getElementById('strengthMessage');

function checkPasswordStrength(password) {
  const minLength = /.{8,}/;
  const hasNumber = /[0-9]/;
  const hasSpecial = /[!@#$%^&*]/;

  if (!minLength.test(password)) return 'Fraca: mínimo 8 caracteres';
  if (!hasNumber.test(password)) return 'Fraca: precisa de número';
  if (!hasSpecial.test(password)) return 'Fraca: precisa de símbolo';

  return 'Forte';
}

passwordInput.addEventListener('input', () => {
  strengthMessage.textContent = checkPasswordStrength(passwordInput.value);
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  if (checkPasswordStrength(passwordInput.value) !== 'Forte') {
    alert('Password fraca. Corrija antes de enviar.');
    return;
  }

  const response = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: document.getElementById('username').value,
      password: passwordInput.value
    })
  });

  const data = await response.json();
  alert(data.message || data.error);
});