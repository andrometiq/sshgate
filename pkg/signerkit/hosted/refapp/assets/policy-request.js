'use strict';

async function loadPolicyReview() {
  const root = document.getElementById('policy-review');
  try {
    const reviewID = policyInputReviewID('policy-review-id');
    setStatus('Loading frozen review…', '');
    const result = await policyGet(reviewID, '');
    if (result.status === 401) { gotoLogin(); return; }
    if (result.status === 404) { setStatus('No acknowledged policy request has that review ID.', 'error'); return; }
    if (!result.ok) { setStatus('Could not load the frozen policy review.', 'error'); return; }
    renderPolicyReview(result.data, root);
    setStatus('', '');
  } catch (error) {
    root.textContent = '';
    setStatus(error.message || 'The stored review failed safe browser validation.', 'error');
  }
}

async function submitPolicyVote(action) {
  try {
    const reviewID = policyInputReviewID('policy-review-id');
    const code = document.getElementById('policy-step-up-code').value.trim();
    const body = code ? {step_up_totp: code} : {};
    setStatus('Submitting audited policy vote…', '');
    const result = await policyPost(reviewID, action, body);
    if (result.status === 401 && result.data && result.data.error === 'step-up required') {
      document.getElementById('policy-step-up').hidden = false;
      setStatus('Fresh TOTP step-up required.', 'error');
      return;
    }
    if (result.status === 401) { gotoLogin(); return; }
    if (!result.ok) {
      setStatus((result.data && result.data.error) || 'Could not record the policy vote.', 'error');
      return;
    }
    setStatus('Audited ' + action + ' vote recorded.', 'ok');
    await loadPolicyReview();
  } catch (error) {
    setStatus(error.message || 'Could not record the policy vote.', 'error');
  }
}

document.getElementById('load-review').addEventListener('click', loadPolicyReview);
document.getElementById('policy-approve').addEventListener('click', function () { submitPolicyVote('approve'); });
document.getElementById('policy-deny').addEventListener('click', function () { submitPolicyVote('deny'); });
document.getElementById('logout').addEventListener('click', function (event) { event.preventDefault(); logout(); });
