'use strict';

const policyReviewIDPattern = /^pr_[0-9a-f]{32}$/;
const policyReviewContract = 'sshgate-policy-review-v2';
const policyWarning = 'WARNING: source-exact is not exact effect; variables, globs, interpreters, cwd/env, and referenced files can change behavior. Dynamic/interpreter commands should not be made permanent.';
const policyMaxDocumentBytes = 128 * 1024;
const policyMaxItems = 40;
const policyMaxVotes = 256;
const policyMaxPreviewBytes = 512;
const policyMaxRenderedNodes = 10000;
const policyMaxRenderedText = 1024 * 1024;
const policyHex64Pattern = /^[0-9a-f]{64}$/;
const policyRequestIDPattern = /^pm_[0-9a-f]{32}$/;
const policyAuthorityIDPattern = /^pauth_[0-9a-f]{32}$/;

class PolicyRenderBudget {
  constructor() {
    this.nodes = 0;
    this.text = 0;
  }

  add(value, nodes) {
    const safe = neutralize(value == null ? '' : String(value));
    this.nodes += nodes == null ? 1 : nodes;
    this.text += safe.length;
    if (this.nodes > policyMaxRenderedNodes || this.text > policyMaxRenderedText) {
      throw new Error('policy review exceeds browser render bounds');
    }
    return safe;
  }
}

function policyElement(tag, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  return node;
}

function policyText(node, value, budget) {
  node.textContent = budget.add(value);
  return node;
}

function policyLine(parent, label, value, budget) {
  const line = policyElement('div', 'row');
  const key = policyElement('span', 'k');
  key.textContent = label;
  line.appendChild(key);
  line.appendChild(document.createTextNode(budget.add(value, 2)));
  parent.appendChild(line);
  return line;
}

function policyHeading(parent, value, budget) {
  const heading = policyElement('h2');
  policyText(heading, value, budget);
  parent.appendChild(heading);
  return heading;
}

function policyInputReviewID(inputID) {
  const value = document.getElementById(inputID).value.trim();
  if (!policyReviewIDPattern.test(value)) throw new Error('Review ID must be pr_ followed by 32 lowercase hexadecimal characters.');
  return value;
}

// reviewID is accepted only from the operator-controlled text input after the
// closed grammar check above. Server-returned policy data is never put in a URL.
function policyRequestPath(reviewID, action) {
  let target = '/ui/policy/requests/' + reviewID;
  if (action) target += '/' + action;
  return target;
}

async function policyGet(reviewID, action) {
  return apiGet(policyRequestPath(reviewID, action), {keep401: true});
}

async function policyPost(reviewID, action, body) {
  return apiPost(policyRequestPath(reviewID, action), body, {keep401: true});
}

function policyUTF8Length(value) {
  return new TextEncoder().encode(String(value)).length;
}

function policyExactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) {
    throw new Error('invalid stored ' + label);
  }
}

function policyBoundedString(value, label, maximum) {
  if (typeof value !== 'string' || !value || policyUTF8Length(value) > maximum) throw new Error('invalid stored ' + label);
  return value;
}

function policyDecimal(value, label) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || value.length > 20) {
    throw new Error('invalid stored ' + label);
  }
  const parsed = BigInt(value);
  if (parsed > 18446744073709551615n) throw new Error('invalid stored ' + label);
  return parsed;
}

function policyPreset(review) {
  if (review.miss_action === 'classifier' && review.growth === 'none') return 'auto';
  if (review.miss_action === 'ask' && review.growth === 'out-of-band') return 'strict';
  if (review.miss_action === 'ask' && review.growth === 'sign-to-add') return 'ask';
  return 'custom';
}

function validatePolicyVotes(votes) {
  if (!Array.isArray(votes) || votes.length > policyMaxVotes) throw new Error('invalid policy vote list');
  let lastTS = -1;
  let lastOperator = '';
  for (const vote of votes) {
    const keys = vote && Object.keys(vote).sort().join(',');
    if (!vote || keys !== 'authn_method,decision,operator,ts' || typeof vote.operator !== 'string' || !['approve', 'deny'].includes(vote.decision) ||
        !['session', 'totp'].includes(vote.authn_method) || !Number.isSafeInteger(vote.ts) || vote.ts < 0) {
      throw new Error('invalid audited policy vote');
    }
    policyBoundedString(vote.operator, 'policy vote operator', 128);
    if (vote.ts < lastTS || (vote.ts === lastTS && vote.operator < lastOperator)) throw new Error('unsorted policy votes');
    lastTS = vote.ts;
    lastOperator = vote.operator;
  }
}

function validatePolicyEvidence(detail) {
  if (!detail || !policyReviewIDPattern.test(detail.review_id) || !['received_unaudited', 'rejection_unaudited', 'rejection_error_received', 'pending',
    'approved_materializing', 'approved_unexposed', 'no_op_unexposed', 'denial_received', 'error_received', 'approved', 'denied', 'error'].includes(detail.state)) {
    throw new Error('invalid frozen policy evidence');
  }
  policyExactKeys(detail.keys,
    detail.keys && detail.keys.frozen_signer_key_id != null ? ['expected_signer_key_id', 'frozen_signer_key_id', 'frozen_signer_public_key_b64', 'mismatch'] : ['expected_signer_key_id', 'mismatch'],
    'policy key evidence');
  if (!policyHex64Pattern.test(detail.keys.expected_signer_key_id) || typeof detail.keys.mismatch !== 'boolean') throw new Error('invalid frozen policy key evidence');
  const frozenID = detail.keys.frozen_signer_key_id;
  const frozenKey = detail.keys.frozen_signer_public_key_b64;
  if ((frozenID == null) !== (frozenKey == null) || (frozenID != null && (!policyHex64Pattern.test(frozenID) || !/^[A-Za-z0-9+/]{43}=$/.test(frozenKey)))) {
    throw new Error('invalid frozen policy key evidence');
  }
  if (detail.keys.mismatch !== (frozenID != null && frozenID !== detail.keys.expected_signer_key_id)) throw new Error('invalid frozen policy key mismatch');
  policyExactKeys(detail.digests,
    detail.digests && detail.digests.trusted_head_digest != null ? ['candidate_base_digest', 'trusted_head_digest'] : ['candidate_base_digest'],
    'policy digest evidence');
  if (!policyHex64Pattern.test(detail.digests.candidate_base_digest) ||
      (detail.digests.trusted_head_digest != null && !policyHex64Pattern.test(detail.digests.trusted_head_digest))) {
    throw new Error('invalid frozen policy digest evidence');
  }
  validatePolicyVotes(detail.votes);
}

function validatePolicyTally(tally) {
  policyExactKeys(tally, ['approvals', 'denials', 'required_approvals', 'deny_veto'], 'policy tally');
  if (!Number.isSafeInteger(tally.approvals) || tally.approvals < 0 || !Number.isSafeInteger(tally.denials) || tally.denials < 0 ||
      !Number.isSafeInteger(tally.required_approvals) || tally.required_approvals < 1 || typeof tally.deny_veto !== 'boolean') {
    throw new Error('invalid stored policy tally');
  }
}

function validatePolicyDetail(detail) {
  policyExactKeys(detail, detail && detail.review != null ?
    ['review_id', 'state', 'created_at', 'keys', 'digests', 'tally', 'votes', 'review'] :
    ['review_id', 'state', 'created_at', 'keys', 'digests', 'tally', 'votes'], 'policy detail');
  validatePolicyEvidence(detail);
  validatePolicyTally(detail.tally);
  if (!Number.isSafeInteger(detail.created_at) || detail.created_at < 0) {
    throw new Error('invalid stored policy detail');
  }
}

function validatePolicyReview(detail) {
  validatePolicyDetail(detail);
  if (!detail.review || detail.review.contract !== policyReviewContract) {
    throw new Error('stored policy review is unavailable');
  }
  const review = detail.review;
  if (policyUTF8Length(JSON.stringify(review)) > policyMaxDocumentBytes) throw new Error('stored policy review is too large');
  policyExactKeys(review, ['contract', 'purpose', 'principal', 'request_id', 'review_id', 'authority_id', 'host', 'bootstrap', 'epoch', 'revision',
    'miss_action', 'growth', 'entry_count', 'revocation_count', 'logical_change_count', 'axes_changed', 'items', 'warnings'], 'policy review');
  if (review.review_id !== detail.review_id || review.purpose !== 'base_manifest_sign_v1' || !policyRequestIDPattern.test(review.request_id) ||
      !policyReviewIDPattern.test(review.review_id) || !policyAuthorityIDPattern.test(review.authority_id) ||
      !['classifier', 'ask', 'deny'].includes(review.miss_action) || !['none', 'sign-to-add', 'out-of-band'].includes(review.growth) ||
      typeof review.bootstrap !== 'boolean' || typeof review.axes_changed !== 'boolean' ||
      !Array.isArray(review.items) || review.items.length > policyMaxItems || !Array.isArray(review.warnings)) {
    throw new Error('invalid stored policy review');
  }
  policyBoundedString(review.principal, 'principal', 128);
  policyBoundedString(review.host, 'host fingerprint', 128);

  const entryCount = policyDecimal(review.entry_count, 'entry count');
  const logicalChanges = policyDecimal(review.logical_change_count, 'logical change count');
  const revocationCount = policyDecimal(review.revocation_count, 'revocation count');
  policyDecimal(review.epoch, 'epoch');
  policyDecimal(review.revision, 'revision');
  if (logicalChanges !== BigInt(review.items.length)) throw new Error('invalid policy logical-change count');
  if (entryCount > 256n || revocationCount > 256n) throw new Error('invalid policy object counts');
  if (review.bootstrap && entryCount > 32n) throw new Error('bootstrap entry bound exceeded');
  if (!review.bootstrap && logicalChanges > 32n) throw new Error('revision change bound exceeded');
  if (review.bootstrap !== (detail.digests.trusted_head_digest == null)) throw new Error('invalid bootstrap digest evidence');

  const order = {added: 0, removed: 1, revoked: 2, axes: 3};
  let previousKind = -1;
  let previousID = '';
  let addedBytes = 0n;
  let addedCount = 0;
  let axesCount = 0;
  for (const item of review.items) {
    if (!item || !Object.hasOwn(order, item.kind) || order[item.kind] < previousKind) throw new Error('invalid policy item order');
    if (order[item.kind] !== previousKind) previousID = '';
    if (item.kind !== 'axes') {
      if (typeof item.id !== 'string' || item.id < previousID) throw new Error('invalid policy item id order');
      previousID = item.id;
    }
    previousKind = order[item.kind];
    if (item.kind === 'added') {
      policyExactKeys(item, item.preview == null ? ['kind', 'id', 'identity_digest', 'literal_length', 'hidden_bytes'] :
        ['kind', 'id', 'identity_digest', 'literal_length', 'hidden_bytes', 'preview'], 'added policy item');
      policyBoundedString(item.id, 'policy item ID', 128);
      if (!policyHex64Pattern.test(item.identity_digest)) throw new Error('invalid policy identity digest');
      const literalLength = policyDecimal(item.literal_length, 'literal length');
      const hiddenBytes = policyDecimal(item.hidden_bytes, 'hidden byte count');
      if (hiddenBytes > literalLength || (review.bootstrap && literalLength > 4096n)) throw new Error('invalid policy literal bounds');
      addedBytes += literalLength;
      addedCount++;
      if (item.preview != null) {
        policyExactKeys(item.preview, ['text', 'redacted'], 'policy preview');
        if (typeof item.preview.text !== 'string' || typeof item.preview.redacted !== 'boolean' ||
            policyUTF8Length(item.preview.text) > policyMaxPreviewBytes) throw new Error('invalid policy preview');
      } else if (hiddenBytes !== literalLength) {
        throw new Error('unsafe preview omission');
      }
    } else if (item.kind === 'removed' || item.kind === 'revoked') {
      policyExactKeys(item, ['kind', 'id'], item.kind + ' policy item');
      policyBoundedString(item.id, 'policy item ID', 128);
    } else {
      policyExactKeys(item, ['kind'], 'axes policy item');
    }
    if (item.kind === 'axes') axesCount++;
  }
  if (addedBytes > 24n * 1024n || axesCount > 1 || Boolean(axesCount) !== review.axes_changed || (review.bootstrap && !review.axes_changed) ||
      (review.bootstrap && BigInt(addedCount) !== entryCount)) throw new Error('invalid policy change bounds');
  if ((addedCount === 0 && review.warnings.length !== 0) ||
      (addedCount !== 0 && (review.warnings.length !== 1 || review.warnings[0] !== policyWarning))) throw new Error('invalid stored policy warnings');
  return review;
}

function validatePolicyAudit(audit) {
  policyExactKeys(audit, audit && audit.terminal_http_status != null ?
    ['review_id', 'state', 'keys', 'digests', 'terminal_http_status', 'votes'] :
    ['review_id', 'state', 'keys', 'digests', 'votes'], 'policy audit');
  validatePolicyEvidence(audit);
  if (audit.terminal_http_status != null && (!Number.isSafeInteger(audit.terminal_http_status) || audit.terminal_http_status < 100 || audit.terminal_http_status > 599)) {
    throw new Error('invalid stored terminal HTTP status');
  }
}

function validatePolicyPending(pending) {
  if (!Array.isArray(pending) || pending.length > 256) throw new Error('invalid policy pending list');
  let lastCreated = -1;
  let lastReviewID = '';
  for (const row of pending) {
    policyExactKeys(row, ['review_id', 'principal', 'request_id', 'purpose', 'host', 'state', 'created_at', 'approvals', 'denials',
      'required_approvals', 'deny_veto', 'bootstrap'], 'policy pending row');
    if (!policyReviewIDPattern.test(row.review_id) || !policyRequestIDPattern.test(row.request_id) || row.purpose !== 'base_manifest_sign_v1' || row.state !== 'pending' ||
        !Number.isSafeInteger(row.created_at) || row.created_at < 0 || typeof row.bootstrap !== 'boolean') throw new Error('invalid policy pending row');
    policyBoundedString(row.principal, 'principal', 128);
    policyBoundedString(row.host, 'host fingerprint', 128);
    validatePolicyTally({approvals: row.approvals, denials: row.denials, required_approvals: row.required_approvals, deny_veto: row.deny_veto});
    if (row.created_at < lastCreated || (row.created_at === lastCreated && row.review_id < lastReviewID)) throw new Error('unsorted policy pending list');
    lastCreated = row.created_at;
    lastReviewID = row.review_id;
  }
}

function renderPolicyKeysAndDigests(detail, root, budget) {
  policyHeading(root, 'Frozen signer evidence', budget);
  policyLine(root, 'expected signer key ID', detail.keys.expected_signer_key_id, budget);
  if (detail.keys.frozen_signer_key_id != null) policyLine(root, 'frozen signer key ID', detail.keys.frozen_signer_key_id, budget);
  if (detail.keys.frozen_signer_public_key_b64 != null) policyLine(root, 'frozen signer public key (base64)', detail.keys.frozen_signer_public_key_b64, budget);
  policyLine(root, 'custody mismatch', detail.keys.mismatch, budget);
  policyLine(root, 'candidate/base digest', detail.digests.candidate_base_digest, budget);
  if (detail.digests.trusted_head_digest != null) policyLine(root, 'signer-owned-head digest', detail.digests.trusted_head_digest, budget);
}

function renderPolicyVotes(votes, root, budget) {
  validatePolicyVotes(votes);
  policyHeading(root, 'Audited votes', budget);
  if (!votes.length) policyLine(root, 'votes', 'none', budget);
  for (const vote of votes) {
    policyLine(root, 'vote', vote.operator + ' — ' + vote.decision + ' (' + vote.authn_method + ') at ' + vote.ts, budget);
  }
}

function renderPolicyReview(detail, root) {
  validatePolicyDetail(detail);
  const budget = new PolicyRenderBudget();
  root.textContent = '';
  const card = policyElement('section', 'card');
  root.appendChild(card);

  if (detail.review == null) {
    policyHeading(card, 'Admission evidence', budget);
    policyLine(card, 'review ID', detail.review_id, budget);
    policyLine(card, 'state', detail.state, budget);
    renderPolicyKeysAndDigests(detail, card, budget);
    policyLine(card, 'stored semantic review', 'absent at admission', budget);
    policyLine(card, 'approvals', detail.tally.approvals, budget);
    policyLine(card, 'denials', detail.tally.denials, budget);
    policyLine(card, 'required approvals', detail.tally.required_approvals, budget);
    policyLine(card, 'deny veto', detail.tally.deny_veto, budget);
    renderPolicyVotes(detail.votes, card, budget);
    return;
  }
  const review = validatePolicyReview(detail);

  policyHeading(card, 'Request identity', budget);
  policyLine(card, 'review ID', detail.review_id, budget);
  policyLine(card, 'request ID', review.request_id, budget);
  policyLine(card, 'request principal', review.principal, budget);
  policyLine(card, 'authority ID', review.authority_id, budget);
  policyLine(card, 'host fingerprint', review.host, budget);
  renderPolicyKeysAndDigests(detail, card, budget);

  policyHeading(card, 'Policy axes and version', budget);
  policyLine(card, 'named preset', policyPreset(review), budget);
  policyLine(card, 'miss action', review.miss_action, budget);
  policyLine(card, 'growth', review.growth, budget);
  policyLine(card, 'axes changed', review.axes_changed, budget);
  policyLine(card, 'epoch', review.epoch, budget);
  policyLine(card, 'revision', review.revision, budget);
  policyLine(card, 'bootstrap', review.bootstrap, budget);

  policyHeading(card, 'Frozen counts and digests', budget);
  if (detail.digests.trusted_head_digest == null) {
    if (!review.bootstrap) throw new Error('non-bootstrap review lacks a signer-owned-head digest');
    policyLine(card, 'signer-owned-head digest', 'absent: explicit bootstrap', budget);
  }
  policyLine(card, 'entry count', review.entry_count, budget);
  policyLine(card, 'revocation count', review.revocation_count, budget);
  policyLine(card, 'logical-change count', review.logical_change_count, budget);

  policyHeading(card, 'Complete semantic diff', budget);
  if (!review.items.length) policyLine(card, 'changes', 'none', budget);
  for (const item of review.items) {
    const block = policyElement('section', 'cmd');
    card.appendChild(block);
    policyLine(block, 'kind', item.kind, budget);
    if (item.kind === 'added') {
      policyLine(block, 'added entry ID', item.id, budget);
      policyLine(block, 'identity digest', item.identity_digest, budget);
      policyLine(block, 'original literal bytes', item.literal_length, budget);
      policyLine(block, 'hidden bytes', item.hidden_bytes, budget);
      if (item.preview != null) {
        policyLine(block, 'display-redacted preview', item.preview.text, budget);
        policyLine(block, 'redacted', item.preview.redacted, budget);
      } else {
        policyLine(block, 'display-redacted preview', 'omitted: no bounded safe mapping', budget);
      }
    } else if (item.kind === 'removed') {
      policyLine(block, 'removed entry ID', item.id, budget);
    } else if (item.kind === 'revoked') {
      policyLine(block, 'newly revoked entry ID', item.id, budget);
    } else {
      policyLine(block, 'axes change', 'miss action and/or growth changed; see frozen axes above', budget);
    }
  }
  for (const warning of review.warnings) policyLine(card, 'warning', warning, budget);
  policyHeading(card, 'Vote state', budget);
  policyLine(card, 'state', detail.state, budget);
  policyLine(card, 'created at (Unix seconds)', detail.created_at, budget);
  policyLine(card, 'approvals', detail.tally.approvals, budget);
  policyLine(card, 'denials', detail.tally.denials, budget);
  policyLine(card, 'required approvals', detail.tally.required_approvals, budget);
  policyLine(card, 'deny veto', detail.tally.deny_veto, budget);
  renderPolicyVotes(detail.votes, card, budget);
}
