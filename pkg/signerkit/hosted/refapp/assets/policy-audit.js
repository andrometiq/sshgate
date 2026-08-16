'use strict';

async function loadPolicyAudit() {
  const root = document.getElementById('policy-audit');
  try {
    const reviewID = policyInputReviewID('policy-audit-id');
    setStatus('Loading frozen audit evidence…', '');
    const result = await policyGet(reviewID, 'audit');
    if (result.status === 401) { gotoLogin(); return; }
    if (result.status === 404) { setStatus('No acknowledged policy request has that review ID.', 'error'); return; }
    if (!result.ok) { setStatus('Could not load policy audit evidence.', 'error'); return; }
    validatePolicyAudit(result.data);
    const budget = new PolicyRenderBudget();
    root.textContent = '';
    const card = policyElement('section', 'card');
    root.appendChild(card);
    policyLine(card, 'review ID', result.data.review_id, budget);
    policyLine(card, 'state', result.data.state, budget);
    renderPolicyKeys(result.data, card, budget);
    policyHeading(card, 'Frozen counts and digests', budget);
    renderPolicyDigests(result.data, null, card, budget);
    if (result.data.terminal_http_status != null) policyLine(card, 'terminal HTTP status', result.data.terminal_http_status, budget);
    renderPolicyVotes(result.data.votes, card, budget);
    setStatus('', '');
  } catch (error) {
    root.textContent = '';
    setStatus(error.message || 'The audit evidence failed safe browser validation.', 'error');
  }
}

document.getElementById('load-audit').addEventListener('click', loadPolicyAudit);
document.getElementById('logout').addEventListener('click', function (event) { event.preventDefault(); logout(); });
