'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const assets = process.env.REFAPP_ASSETS || path.join(__dirname, '..', 'assets');
class Node {
  constructor() { this.children = []; this.value = ''; this.hidden = false; this.disabled = false; this.attrs = {}; this.listeners = {}; this._text = ''; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map(n => n.textContent).join(''); }
  set innerHTML(v) { throw new Error('HTML injection: ' + v); }
  setAttribute(k, v) { this.attrs[k] = v; }
  appendChild(n) { this.children.push(n); return n; }
  addEventListener(k, f) { this.listeners[k] = f; }
}
const ok = data => ({ok: true, status: 200, data});
const challenge = {challenge: 'opaque-token', allowed_actions: ['approve', 'deny']};
const detail = (extra = {}) => ({record_handle: 'HANDLE', sub_principal: 'principal', approval_status: 'pending', required_approvals: 2, votes: [], vote_challenge: challenge, review: {requester: 'client sub=principal', submitted_at: '2026-01-01', reason_label: 'Agent reason', reason: '<script>reason</script>', summary: 'summary', items: [{text_label: 'Display-redacted command', text: '[hidden]', sha256: 'abc', notes: ['route']}], assist: {state: 'ready', summary: '<img onerror=bad>', concerns: ['concern'], effects: ['effect']}, approve_label: 'Approve displayed commands'}, ...extra});
async function page(script, data, search = '?h=HANDLE') {
  const nodes = new Map(); const gets = []; const posts = [];
  const context = {URLSearchParams, console, location: {search, pathname: '/' + script, href: ''}, document: {
    getElementById(id) {
      if (!nodes.has(id)) {
        const node = new Node();
        node.hidden = ['step-up', 'detail', 'actions'].includes(id);
        nodes.set(id, node);
      }
      return nodes.get(id);
    },
    createElement: () => new Node(), createTextNode: text => { const n = new Node(); n.textContent = text; return n; },
  }};
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(assets, 'app.js'), 'utf8'), context);
  context.getResult = ok(data); context.postResult = ok({decision: 'pending'});
  context.fetch = async (url, options) => {
    let result;
    if (options.method === 'GET') { gets.push(url); result = context.getResult; }
    else { posts.push({url, body: JSON.parse(options.body)}); result = context.postResult; }
    return {...result, text: async () => JSON.stringify(result.data)};
  };
  vm.runInContext(fs.readFileSync(path.join(assets, script), 'utf8'), context);
  await new Promise(resolve => setImmediate(resolve));
  return {context, nodes, gets, posts, run: code => vm.runInContext(code, context)};
}
test('v2 detail renders stored review as text and votes with its challenge', async () => {
  const p = await page('request.js', detail());
  assert.equal(p.gets[0], '/ui/v2/request/HANDLE');
  assert.match(p.nodes.get('integrity').textContent, /<script>reason<\/script>/);
  assert.match(p.nodes.get('integrity').textContent, /<img onerror=bad>/);
  assert.match(p.nodes.get('integrity').textContent, /Display-redacted command/);
  await p.run("vote('approve')");
  assert.deepEqual(p.posts[0], {url: '/ui/v2/request/HANDLE/approve', body: {challenge: 'opaque-token'}});
  assert.equal(p.nodes.get('approve').disabled, true);
});
test('preparing and absent challenges disable approval, including direct calls', async () => {
  for (const token of [null, {challenge: 'deny-only', allowed_actions: ['deny']}]) {
    const p = await page('request.js', detail({vote_challenge: token}));
    assert.equal(p.nodes.get('approve').disabled, true);
    await p.run("vote('approve')"); assert.equal(p.posts.length, 0);
    if (token) { await p.run("vote('deny')"); assert.equal(p.posts[0].body.challenge, 'deny-only'); }
  }
});
test('terminal states and pruned detail cannot vote', async () => {
  for (const status of ['approved', 'denied', 'expired', 'canceled', 'error']) {
    const p = await page('request.js', detail({approval_status: status, pruned: true, details: 'details pruned', review: null}));
    assert.equal(p.nodes.get('actions').hidden, true);
    assert.match(p.nodes.get('integrity').textContent, /details pruned/);
    await p.run("vote('deny')"); assert.equal(p.posts.length, 0);
  }
});
test('v1 route, command rendering and step-up still work with challenge', async () => {
  const p = await page('request.js', {status: 'pending', command_details: [{cmd: 'echo ok'}], vote_challenge: challenge}, '?id=r_test');
  assert.equal(p.gets[0], '/ui/request/r_test');
  assert.match(p.nodes.get('integrity').textContent, /echo ok/);
  p.context.postResult = {status: 401, data: {error: 'step-up required'}};
  await p.run("vote('approve')"); assert.equal(p.nodes.get('step-up').hidden, false);
  p.context.document.getElementById('step-up-code').value = '123456'; p.context.postResult = ok({decision: 'approved'});
  await p.run("vote('approve')"); assert.equal(p.posts[1].body.step_up_totp, '123456');
  assert.equal(p.posts[1].body.challenge, 'opaque-token');
});
test('legacy terminal reason hides actions', async () => {
  const p = await page('request.js', {status: 'pending', terminal_reason: 'canceled', vote_challenge: challenge}, '?id=r_test');
  assert.equal(p.nodes.get('actions').hidden, true);
  assert.match(p.nodes.get('integrity').textContent, /canceled/);
});
test('busy messages retain challenge and require a fresh code only when spent', async () => {
  for (const fresh of [false, true]) {
    const p = await page('request.js', detail()); p.context.document.getElementById('step-up-code').value = '123456';
    p.context.postResult = {status: 503, data: {error: fresh ? 'busy — retry with a fresh code' : 'busy — retry'}};
    await p.run("vote('approve')");
    assert.match(p.nodes.get('status').textContent, /signer is busy/);
    assert.equal(p.nodes.get('step-up-code').value, fresh ? '' : '123456');
    assert.equal(p.nodes.get('approve').disabled, false);
  }
});
test('stale challenge reloads and a failed reload disables stale actions', async () => {
  const p = await page('request.js', detail());
  p.context.postResult = {status: 409, data: {error: 'view changed'}};
  p.context.getResult = ok(detail({vote_challenge: {...challenge, challenge: 'replacement'}}));
  await p.run("vote('approve')");
  p.context.postResult = ok({decision: 'pending'}); await p.run("vote('deny')");
  assert.equal(p.posts[1].body.challenge, 'replacement');
  const q = await page('request.js', detail()); q.context.postResult = {status: 409, data: {error: 'view changed'}};
  q.context.getResult = {status: 500}; await q.run("vote('approve')");
  assert.equal(q.nodes.get('approve').disabled, true);
});
test('pending pages each plane independently with opaque cursor and no duplicates', async () => {
  for (const moreV1 of [false, true]) {
    const p = await page('pending.js', {pending: [{request_id: 'r_one'}], has_more: moreV1, next_offset: 50, v2_pending: [detail()], v2_has_more: !moreV1, v2_next_cursor: 'opaque+/='});
    assert.equal(p.nodes.get('list').children.length, 2);
    assert.equal(p.nodes.get('load-more').hidden, false);
    p.context.getResult = ok({pending: [{request_id: 'r_two'}], has_more: false, v2_pending: [detail({record_handle: 'SECOND'})], v2_has_more: false});
    await p.run('load(false)');
    assert.equal(p.nodes.get('list').children.length, 3);
    assert.equal(p.nodes.get('load-more').hidden, true);
    if (!moreV1) assert.match(p.gets[1], /v2_cursor=opaque%2B%2F%3D/);
    else assert.match(p.gets[1], /offset=50/);
  }
});
test('v2-only pending and audit rows are visible and link by handle', async () => {
  const p = await page('pending.js', {pending: [], v2_pending: [detail()]});
  assert.equal(p.nodes.get('list').children.length, 1);
  assert.equal(p.nodes.get('list').children[0].children[0].attrs.href, 'request.html?h=HANDLE');
  const a = await page('audit.js', {entries: [], v2_entries: [{record_handle: 'HANDLE', sub_principal: 'principal', decision: 'approved', rationale_redacted: '<b>reason</b>', assist_bound: {state: 'ready', revision: 1, digest: 'abc'}, votes: [{operator: 'voter', decision: 'approve'}]}]});
  assert.equal(a.nodes.get('list').children.length, 1);
  assert.match(a.nodes.get('list').textContent, /<b>reason<\/b>/);
  assert.match(a.nodes.get('list').textContent, /abc/);
});
test('stored neutralization survives rendering unchanged, including assist states', async () => {
  for (const state of ['preparing', 'disabled', 'unavailable', 'ready']) {
    const row = detail();
    row.review.reason = 'literal \\u{202e}'; row.review.assist.state = state;
    const p = await page('request.js', row);
    assert.ok(p.nodes.get('integrity').textContent.includes(row.review.reason));
    assert.ok(!p.nodes.get('integrity').textContent.includes('literal \\\\u{202e}'));
    assert.ok(p.nodes.get('integrity').textContent.includes(state));
  }
});
test('concurrent vote clicks submit only once', async () => {
  const p = await page('request.js', detail());
  let release;
  const originalFetch = p.context.fetch;
  p.context.fetch = async (url, options) => {
    if (options.method === 'POST') await new Promise(resolve => { release = resolve; });
    return originalFetch(url, options);
  };
  const first = p.run("vote('approve')");
  await p.run("vote('deny')");
  release(); await first;
  assert.equal(p.posts.length, 1);
});
test('pending refresh resets both tokens and a failed page can be retried', async () => {
  const first = {pending: [], has_more: true, next_offset: 50, v2_pending: [detail()], v2_has_more: true, v2_next_cursor: 'cursor'};
  const p = await page('pending.js', first);
  p.context.getResult = {status: 500}; await p.run('load(false)');
  assert.equal(p.nodes.get('list').children.length, 1);
  p.context.getResult = ok({pending: [{request_id: 'r_next'}], has_more: false, v2_pending: [detail({record_handle: 'NEXT'})], v2_has_more: false});
  await p.run('load(false)');
  assert.equal(p.gets[1], p.gets[2]);
  assert.match(p.gets[2], /offset=50&v2_cursor=cursor/);
  assert.equal(p.nodes.get('list').children.length, 3);
  p.context.getResult = ok(first); await p.run('load(true)');
  assert.equal(p.gets[3], '/ui/pending?offset=0');
  assert.equal(p.nodes.get('list').children.length, 1);
});
test('v2 commands use the whitespace-preserving command display', async () => {
  const row = detail(); row.review.items[0].text = 'echo  two-spaces';
  const p = await page('request.js', row);
  const block = p.nodes.get('integrity').children[0];
  const command = block.children.find(n => n.className === 'cmd');
  assert.equal(command.children.find(n => n.className === 'text').textContent, 'echo  two-spaces');
  assert.match(command.children.find(n => n.className === 'sha').textContent, /abc/);
});
test('concurrent pending clicks fetch and append each page only once', async () => {
  const p = await page('pending.js', {pending: [], v2_pending: [detail()], v2_has_more: true, v2_next_cursor: 'cursor'});
  const releases = [];
  const originalFetch = p.context.fetch;
  p.context.fetch = async (url, options) => {
    await new Promise(resolve => { releases.push(resolve); });
    return originalFetch(url, options);
  };
  p.context.getResult = ok({pending: [], v2_pending: [detail({record_handle: 'NEXT'})], v2_has_more: false});
  const first = p.run('load(false)');
  const second = p.run('load(false)');
  for (const release of releases) release();
  await Promise.all([first, second]);
  assert.equal(releases.length, 1);
  assert.equal(p.gets.length, 2);
  assert.equal(p.nodes.get('list').children.length, 2);
});

for (const subPrincipal of ['', 'local-uid:1000']) {
  const variant = subPrincipal ? 'populated' : 'empty';
  for (const view of ['request', 'pending']) {
    test('v2 ' + view + ' requester includes principal with ' + variant + ' sub-principal', async () => {
      const row = detail({sub_principal: subPrincipal});
      const requester = '<client>\\u{202e}' + (subPrincipal ? ' sub=' + subPrincipal : '');
      row.review.requester = requester;
      const p = await page(view + '.js', view === 'request' ? row : {pending: [], v2_pending: [row]});
      if (view === 'request') assert.equal(p.nodes.get('requester').textContent, requester);
      else assert.equal(p.nodes.get('list').children[0].children[1].textContent, 'from ' + requester + ' · pending');
    });
  }
}
