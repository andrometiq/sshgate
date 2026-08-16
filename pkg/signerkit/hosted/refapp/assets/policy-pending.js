'use strict';

async function loadPolicyPending() {
  setStatus('Loading…', '');
  const result = await apiGet('/ui/policy/pending', {keep401: true});
  if (result.status === 401) { gotoLogin(); return; }
  if (!result.ok || !result.data) {
    setStatus('Could not load the bounded policy queue.', 'error');
    return;
  }
  const root = document.getElementById('policy-list');
  root.textContent = '';
  const budget = new PolicyRenderBudget();
  try {
    policyExactKeys(result.data, ['pending'], 'policy pending response');
    validatePolicyPending(result.data.pending);
    if (!result.data.pending.length) policyText(root, 'No pending permanent policy requests.', budget);
    for (const row of result.data.pending) {
      const card = policyElement('article', 'card');
      root.appendChild(card);
      policyLine(card, 'review ID', row.review_id, budget);
      policyLine(card, 'principal', row.principal, budget);
      policyLine(card, 'request ID', row.request_id, budget);
      policyLine(card, 'purpose', row.purpose, budget);
      policyLine(card, 'host fingerprint', row.host, budget);
      policyLine(card, 'state', row.state, budget);
      policyLine(card, 'created at (Unix seconds)', row.created_at, budget);
      policyLine(card, 'approvals', row.approvals, budget);
      policyLine(card, 'denials', row.denials, budget);
      policyLine(card, 'required approvals', row.required_approvals, budget);
      policyLine(card, 'deny veto', row.deny_veto, budget);
      policyLine(card, 'bootstrap', row.bootstrap, budget);
    }
    setStatus('', '');
  } catch (_) {
    root.textContent = '';
    setStatus('The policy queue exceeded safe browser render bounds.', 'error');
  }
}

document.getElementById('refresh').addEventListener('click', loadPolicyPending);
document.getElementById('logout').addEventListener('click', function (event) { event.preventDefault(); logout(); });
loadPolicyPending();
