'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const {TextEncoder} = require('node:util');

class FakeNode {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.className = '';
    this._text = '';
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  set textContent(value) {
    this._text = String(value);
    this.children = [];
  }

  get textContent() {
    return this._text + this.children.map((child) => typeof child === 'string' ? child : child.textContent).join('');
  }
}

function loadPolicy() {
  const document = {
    createElement: (tag) => new FakeNode(tag),
    createTextNode: (value) => String(value),
    getElementById: () => null,
  };
  const context = {
    ArrayBuffer,
    Uint8Array,
    TextEncoder,
    atob,
    btoa,
    console,
    document,
    location: {pathname: '/policy-request.html', href: ''},
    navigator: {},
  };
  context.window = context;
  vm.createContext(context);
  const assets = path.join(__dirname, '..', 'assets');
  vm.runInContext(fs.readFileSync(path.join(assets, 'app.js'), 'utf8'), context);
  const policy = fs.readFileSync(path.join(assets, 'policy-common.js'), 'utf8');
  vm.runInContext(policy + `
    ;globalThis.__policyTest = {
      validatePolicyReview, validatePolicyVotes, validatePolicyAudit, validatePolicyPending, renderPolicyReview,
      policyPreset, policyWarning, policyMaxItems, policyMaxPreviewBytes
    };`, context);
  return context;
}

function detailWith(items, overrides) {
  const review = {
    contract: 'sshgate-policy-review-v2',
    purpose: 'base_manifest_sign_v1',
    principal: 'machine',
    request_id: 'pm_11111111111111111111111111111111',
    review_id: 'pr_11111111111111111111111111111111',
    authority_id: 'pauth_11111111111111111111111111111111',
    host: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    bootstrap: false,
    epoch: '1',
    revision: '2',
    miss_action: 'ask',
    growth: 'sign-to-add',
    entry_count: '1',
    revocation_count: '0',
    logical_change_count: String(items.length),
    axes_changed: items.some((item) => item.kind === 'axes'),
    items,
    warnings: items.some((item) => item.kind === 'added') ? [loadPolicy().__policyTest.policyWarning] : [],
    ...(overrides || {}),
  };
  return {
    review_id: review.review_id,
    state: 'pending',
    created_at: 7,
    keys: {
      expected_signer_key_id: 'a'.repeat(64),
      frozen_signer_key_id: 'a'.repeat(64),
      frozen_signer_public_key_b64: 'A'.repeat(43) + '=',
      mismatch: false,
    },
    digests: {candidate_base_digest: 'b'.repeat(64), trusted_head_digest: 'c'.repeat(64)},
    tally: {approvals: 0, denials: 0, required_approvals: 1, deny_veto: true},
    votes: [],
    review,
  };
}

function added(id, length, preview) {
  const item = {
    kind: 'added',
    id,
    identity_digest: 'd'.repeat(64),
    literal_length: String(length),
    hidden_bytes: preview == null ? String(length) : '0',
  };
  if (preview != null) item.preview = {text: preview, redacted: true};
  return item;
}

test('complete policy review renders hostile HTML and bidi only as neutralized text', () => {
  const context = loadPolicy();
  const hostile = '<img src=x onerror=alert(1)>\u202e\\u{202e}';
  const detail = detailWith([added('pa_oob_00000000000000000000000000000001', hostile.length, hostile)]);
  const root = new FakeNode('div');
  context.__policyTest.renderPolicyReview(detail, root);
  assert.match(root.textContent, /<img src=x onerror=alert\(1\)>/);
  assert.match(root.textContent, /\\u\{202e\}/);
  assert.equal(root.children.some((child) => child.tag === 'img'), false);
});

test('complete semantic content labels digests, presets, additions, removals, revocations, axes, and warning', () => {
  const context = loadPolicy();
  const items = [
    added('added-01', 4, 'echo'),
    {kind: 'removed', id: 'removed-01'},
    {kind: 'revoked', id: 'revoked-01'},
    {kind: 'axes'},
  ];
  const detail = detailWith(items, {axes_changed: true, entry_count: '1', revocation_count: '1'});
  const root = new FakeNode('div');
  context.__policyTest.renderPolicyReview(detail, root);
  for (const expected of [
    'expected signer key ID', 'frozen signer key ID', 'candidate/base digest', 'signer-owned-head digest',
    'named presetask', 'epoch1', 'revision2', 'entry count1', 'revocation count1', 'logical-change count4',
    'added entry IDadded-01', 'identity digest', 'original literal bytes4', 'display-redacted previewecho', 'hidden bytes0',
    'removed entry IDremoved-01', 'newly revoked entry IDrevoked-01', 'axes change', context.__policyTest.policyWarning,
  ]) {
    assert.match(root.textContent, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('acknowledged rejection without a review document still renders frozen forensic evidence', () => {
  const context = loadPolicy();
  const detail = detailWith([]);
  delete detail.review;
  detail.state = 'error';
  detail.tally = {approvals: 0, denials: 0, required_approvals: 1, deny_veto: true};
  const root = new FakeNode('div');
  context.__policyTest.renderPolicyReview(detail, root);
  assert.match(root.textContent, /Admission evidence/);
  assert.match(root.textContent, /stored semantic reviewabsent at admission/);
  assert.match(root.textContent, /candidate\/base digest/);
});

test('bootstrap review renders signer-owned-head digest absence explicitly', () => {
  const context = loadPolicy();
  const detail = detailWith([added('added-01', 1, 'x'), {kind: 'axes'}], {bootstrap: true, entry_count: '1'});
  delete detail.digests.trusted_head_digest;
  const root = new FakeNode('div');
  context.__policyTest.renderPolicyReview(detail, root);
  assert.match(root.textContent, /signer-owned-head digestabsent: explicit bootstrap/);
});

test('P7 item, preview, bootstrap literal, and aggregate bounds fail at max plus one', () => {
  const context = loadPolicy();
  const maxItems = [
    ...Array.from({length: 32}, (_, index) => added(`added-${String(index).padStart(2, '0')}`, 1, 'x')),
    ...Array.from({length: 7}, (_, index) => ({kind: 'revoked', id: `revoked-${String(index).padStart(2, '0')}`})),
    {kind: 'axes'},
  ];
  const atItemMax = detailWith(maxItems, {bootstrap: true, entry_count: '32', revocation_count: '7'});
  delete atItemMax.digests.trusted_head_digest;
  assert.doesNotThrow(() => context.__policyTest.validatePolicyReview(atItemMax));
  const overItemMax = detailWith([...maxItems.slice(0, -1), {kind: 'revoked', id: 'revoked-07'}, {kind: 'axes'}],
    {bootstrap: true, entry_count: '32', revocation_count: '8'});
  delete overItemMax.digests.trusted_head_digest;
  assert.throws(() => context.__policyTest.validatePolicyReview(overItemMax), /invalid stored policy review/);

  const preview512 = 'x'.repeat(512);
  assert.doesNotThrow(() => context.__policyTest.validatePolicyReview(detailWith([added('a', 512, preview512)])));
  assert.throws(() => context.__policyTest.validatePolicyReview(detailWith([added('a', 513, preview512 + 'x')])), /invalid policy preview/);

  const bootstrap = detailWith([added('a', 4096, null), {kind: 'axes'}], {bootstrap: true, entry_count: '1'});
  delete bootstrap.digests.trusted_head_digest;
  assert.doesNotThrow(() => context.__policyTest.validatePolicyReview(bootstrap));
  const tooLong = detailWith([added('a', 4097, null), {kind: 'axes'}], {bootstrap: true, entry_count: '1'});
  delete tooLong.digests.trusted_head_digest;
  assert.throws(() => context.__policyTest.validatePolicyReview(tooLong), /literal bounds/);

  const six = [...Array.from({length: 6}, (_, index) => added(`a-${index}`, 4096, null)), {kind: 'axes'}];
  const aggregateMax = detailWith(six, {bootstrap: true, entry_count: '6'});
  delete aggregateMax.digests.trusted_head_digest;
  assert.doesNotThrow(() => context.__policyTest.validatePolicyReview(aggregateMax));
  const aggregate = [...six.slice(0, -1), added('a-6', 1, null), {kind: 'axes'}];
  const aggregateOver = detailWith(aggregate, {bootstrap: true, entry_count: '7'});
  delete aggregateOver.digests.trusted_head_digest;
  assert.throws(() => context.__policyTest.validatePolicyReview(aggregateOver), /change bounds/);
});

test('preview omission preserves full hidden count and malformed redaction metadata fails closed', () => {
  const context = loadPolicy();
  assert.doesNotThrow(() => context.__policyTest.validatePolicyReview(detailWith([added('a', 7, null)])));
  const malformed = added('a', 7, null);
  malformed.hidden_bytes = '6';
  assert.throws(() => context.__policyTest.validatePolicyReview(detailWith([malformed])), /unsafe preview omission/);
});

test('vote arrays are bounded, audited shapes only, and sorted by timestamp then operator', () => {
  const context = loadPolicy();
  const votes = [
    {operator: 'a', decision: 'approve', authn_method: 'session', ts: 1},
    {operator: 'b', decision: 'deny', authn_method: 'totp', ts: 1},
  ];
  assert.doesNotThrow(() => context.__policyTest.validatePolicyVotes(votes));
  assert.throws(() => context.__policyTest.validatePolicyVotes([...votes].reverse()), /unsorted/);
  assert.throws(() => context.__policyTest.validatePolicyVotes(Array.from({length: 257}, (_, index) => ({
    operator: String(index).padStart(3, '0'), decision: 'approve', authn_method: 'session', ts: index,
  }))), /invalid policy vote list/);
  assert.throws(() => context.__policyTest.validatePolicyVotes([{...votes[0], audited: false}]), /invalid audited policy vote/);
});

test('pending and audit projections enforce their frozen shapes, order, and bounds', () => {
  const context = loadPolicy();
  const pending = Array.from({length: 256}, (_, index) => ({
    review_id: `pr_${index.toString(16).padStart(32, '0')}`,
    principal: 'machine',
    request_id: `pm_${index.toString(16).padStart(32, '0')}`,
    purpose: 'base_manifest_sign_v1',
    host: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    state: 'pending',
    created_at: index,
    approvals: 0,
    denials: 0,
    required_approvals: 1,
    deny_veto: true,
    bootstrap: true,
  }));
  assert.doesNotThrow(() => context.__policyTest.validatePolicyPending(pending));
  assert.throws(() => context.__policyTest.validatePolicyPending([...pending, pending[255]]), /invalid policy pending list/);
  assert.throws(() => context.__policyTest.validatePolicyPending([pending[1], pending[0]]), /unsorted policy pending list/);

  const detail = detailWith([]);
  const audit = {review_id: detail.review_id, state: detail.state, keys: detail.keys, digests: detail.digests, votes: []};
  assert.doesNotThrow(() => context.__policyTest.validatePolicyAudit(audit));
  assert.doesNotThrow(() => context.__policyTest.validatePolicyAudit({...audit, terminal_http_status: 200}));
  assert.throws(() => context.__policyTest.validatePolicyAudit({...audit, tally: detail.tally}), /invalid stored policy audit/);
});

test('named preset mapping is frozen', () => {
  const context = loadPolicy();
  assert.equal(context.__policyTest.policyPreset({miss_action: 'classifier', growth: 'none'}), 'auto');
  assert.equal(context.__policyTest.policyPreset({miss_action: 'ask', growth: 'out-of-band'}), 'strict');
  assert.equal(context.__policyTest.policyPreset({miss_action: 'ask', growth: 'sign-to-add'}), 'ask');
  assert.equal(context.__policyTest.policyPreset({miss_action: 'deny', growth: 'none'}), 'custom');
});
