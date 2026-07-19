'use strict';

// All requests are same-origin and every server-supplied value is rendered via
// textContent. The approval surface has no external dependencies.
function gotoLogin() {
  if (!location.pathname.endsWith('/login.html')) location.href = 'login.html';
}

async function api(method, path, body, options) {
  const opts = {
    method,
    credentials: 'same-origin',
    headers: {Accept: 'application/json'},
  };
  if (body !== undefined && body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const response = await fetch(path, opts);
  const raw = await response.text();
  let data = null;
  if (raw) {
    try { data = JSON.parse(raw); } catch (_) { data = null; }
  }
  if (response.status === 401 && !(options && options.keep401)) gotoLogin();
  return {ok: response.ok, status: response.status, data};
}

const apiGet = (path, options) => api('GET', path, null, options);
const apiPost = (path, body, options) => api('POST', path, body, options);

function setStatus(message, kind) {
  const status = document.getElementById('status');
  if (!status) return;
  status.textContent = message || '';
  status.className = 'status' + (kind ? ' ' + kind : '');
}

function b64urlToBuf(value) {
  const pad = '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob((value + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Escape controls and all non-ASCII code points. This makes bidi controls,
// zero-width characters and homoglyphs visible while preserving the exact
// code point in the displayed representation.
function neutralize(value) {
  let output = '';
  for (const character of String(value)) {
	if (character === '\\') {
	  output += '\\\\';
	  continue;
	}
    const cp = character.codePointAt(0);
    if (cp < 0x20 || cp === 0x7f || cp > 0x7e) {
      output += '\\u{' + cp.toString(16).padStart(2, '0') + '}';
    } else {
      output += character;
    }
  }
  return output;
}

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === 'text') node.textContent = value;
    else if (key === 'class') node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child == null) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

function fmtTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? neutralize(value) : date.toLocaleString();
}

function fact(label, value) {
  const node = el('span');
  node.appendChild(el('span', {class: 'k', text: label + ': '}));
  node.appendChild(document.createTextNode(neutralize(value)));
  return node;
}

function renderCommand(command, options) {
  const block = el('section', {class: 'cmd' + (options && options.prominent ? ' prominent' : '')});
  block.appendChild(el('div', {class: 'label', text: 'command'}));
  block.appendChild(el('div', {class: 'text', text: neutralize(command.cmd || '')}));
  block.appendChild(el('div', {class: 'label', text: 'sha-256'}));
  block.appendChild(el('div', {class: 'sha', text: neutralize(command.sha256 || '—')}));
  const facts = el('div', {class: 'facts'});
  facts.appendChild(fact('server', command.server || '—'));
  facts.appendChild(fact('host-key fp', command.host_key_fp || '(none)'));
  const ttl = command.ttl_seconds == null ? '?' : command.ttl_seconds;
  facts.appendChild(fact('validity', 'signature valid ' + ttl + 's after approval'));
  block.appendChild(facts);
  return block;
}

function renderTally(tally, showVoters) {
  const wrapper = el('div');
  if (!tally) {
    wrapper.appendChild(el('p', {class: 'tally', text: 'Tally unavailable.'}));
    return wrapper;
  }
  const line = el('p', {class: 'tally'});
  line.appendChild(el('span', {
    class: 'count',
    text: String(tally.approvals || 0) + ' of ' + String(tally.required || 0),
  }));
  line.appendChild(document.createTextNode(' approvals'));
  if (tally.denials) line.appendChild(document.createTextNode(' · ' + tally.denials + ' deny'));
  wrapper.appendChild(line);

  if (showVoters && Array.isArray(tally.voters) && tally.voters.length) {
    const voters = el('ul', {class: 'voters'});
    for (const vote of tally.voters) {
      voters.appendChild(el('li', {
        text: neutralize(vote.operator) + ' — ' + neutralize(vote.decision) +
          ' (' + neutralize(vote.authn_method) + ') · ' + fmtTime(vote.ts),
      }));
    }
    wrapper.appendChild(voters);
  }
  return wrapper;
}

async function webauthnLogin(username) {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('this browser does not support passkeys');
  }
  const begin = await apiPost('/auth/webauthn/login/begin', {username}, {keep401: true});
  if (!begin.ok || !begin.data || !begin.data.options) {
    throw new Error((begin.data && begin.data.error) || 'could not start passkey sign-in');
  }
  const source = begin.data.options.publicKey;
  const publicKey = {
    challenge: b64urlToBuf(source.challenge),
    rpId: source.rpId,
    timeout: source.timeout,
    userVerification: source.userVerification,
  };
  if (Array.isArray(source.allowCredentials)) {
    publicKey.allowCredentials = source.allowCredentials.map((credential) => ({
      type: credential.type,
      id: b64urlToBuf(credential.id),
      transports: credential.transports,
    }));
  }
  const assertion = await navigator.credentials.get({publicKey});
  const credential = {
    id: assertion.id,
    rawId: bufToB64url(assertion.rawId),
    type: assertion.type,
    response: {
      clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
      authenticatorData: bufToB64url(assertion.response.authenticatorData),
      signature: bufToB64url(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : null,
    },
    clientExtensionResults: assertion.getClientExtensionResults(),
  };
  const finish = await apiPost('/auth/webauthn/login/finish', {
    username,
    challenge_id: begin.data.challenge_id,
    response: credential,
  }, {keep401: true});
  if (!finish.ok) throw new Error((finish.data && finish.data.error) || 'passkey sign-in failed');
}

async function logout() {
  await apiPost('/auth/logout', {});
  location.href = 'login.html';
}
