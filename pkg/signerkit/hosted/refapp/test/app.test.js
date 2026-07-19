'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function loadApp(overrides) {
  const context = {
    ArrayBuffer,
    Uint8Array,
    atob,
    btoa,
    console,
    document: {getElementById: () => null},
    location: {pathname: '/login.html', href: ''},
    navigator: {},
    ...overrides,
  };
  context.window = context;
  vm.createContext(context);
  const source = fs.readFileSync(path.join(__dirname, '..', 'assets', 'app.js'), 'utf8');
  vm.runInContext(source + '\n;globalThis.__test = {b64urlToBuf, bufToB64url, neutralize, webauthnLogin};', context);
  return context;
}

test('base64url adapters round-trip arbitrary credential bytes', () => {
  const context = loadApp();
  const input = new Uint8Array([0, 1, 127, 128, 254, 255]);
  const encoded = context.__test.bufToB64url(input.buffer);
  assert.equal(encoded, 'AAF_gP7_');
  assert.deepEqual(Array.from(new Uint8Array(context.__test.b64urlToBuf(encoded))), Array.from(input));
});

test('render neutralization is injective for literal escapes and bidi controls', () => {
  const context = loadApp();
  assert.equal(context.__test.neutralize('\\u{202e}'), '\\\\u{202e}');
  assert.equal(context.__test.neutralize('\u202e'), '\\u{202e}');
  assert.notEqual(context.__test.neutralize('\\u{202e}'), context.__test.neutralize('\u202e'));
});

test('WebAuthn login maps browser buffers and nullable userHandle correctly', async () => {
  const calls = [];
  let publicKeySeen;
  const assertion = {
    id: 'credential-id',
    rawId: new Uint8Array([5, 6]).buffer,
    type: 'public-key',
    response: {
      clientDataJSON: new Uint8Array([7]).buffer,
      authenticatorData: new Uint8Array([8]).buffer,
      signature: new Uint8Array([9]).buffer,
      userHandle: null,
    },
    getClientExtensionResults: () => ({appid: false}),
  };
  const context = loadApp({
    PublicKeyCredential: function PublicKeyCredential() {},
    navigator: {
      credentials: {
        get: async ({publicKey}) => {
          publicKeySeen = publicKey;
          return assertion;
        },
      },
    },
    fetch: async (url, options) => {
      calls.push({url, options});
      if (calls.length === 1) {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({
            challenge_id: 'challenge-1',
            options: {publicKey: {
              challenge: 'AQI',
              rpId: 'signer.example.com',
              timeout: 60000,
              userVerification: 'required',
              allowCredentials: [{type: 'public-key', id: 'AwQ', transports: ['usb']}],
            }},
          }),
        };
      }
      return {ok: true, status: 200, text: async () => '{}'};
    },
  });

  await context.__test.webauthnLogin('alice');

  assert.deepEqual(Array.from(new Uint8Array(publicKeySeen.challenge)), [1, 2]);
  assert.deepEqual(Array.from(new Uint8Array(publicKeySeen.allowCredentials[0].id)), [3, 4]);
  assert.equal(calls[0].url, '/auth/webauthn/login/begin');
  assert.equal(calls[1].url, '/auth/webauthn/login/finish');
  const finish = JSON.parse(calls[1].options.body);
  assert.equal(finish.challenge_id, 'challenge-1');
  assert.equal(finish.response.rawId, 'BQY');
  assert.equal(finish.response.response.clientDataJSON, 'Bw');
  assert.equal(finish.response.response.userHandle, null);
  assert.deepEqual(finish.response.clientExtensionResults, {appid: false});
});
