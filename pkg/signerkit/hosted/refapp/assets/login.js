'use strict';

function operatorName() { return document.getElementById('username').value.trim(); }

document.getElementById('passkey').addEventListener('click', async function () {
  const username = operatorName();
  if (!username) { setStatus('Enter your operator name first.', 'error'); return; }
  setStatus('Waiting for your passkey…', '');
  try {
    await webauthnLogin(username);
    location.href = 'pending.html';
  } catch (error) {
    const message = error && error.message ? error.message : 'Passkey sign-in failed';
    setStatus(message + '. You can use a one-time code instead.', 'error');
  }
});

document.getElementById('code').addEventListener('click', async function () {
  const username = operatorName();
  const code = document.getElementById('totp').value.trim();
  if (!username || !code) { setStatus('Enter your operator name and code.', 'error'); return; }
  setStatus('Checking…', '');
  const result = await apiPost('/auth/login', {username, totp_code: code}, {keep401: true});
  if (result.ok) location.href = 'pending.html';
  else setStatus('Invalid credentials.', 'error');
});

document.getElementById('totp').addEventListener('keydown', function (event) {
  if (event.key === 'Enter') document.getElementById('code').click();
});
