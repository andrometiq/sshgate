'use strict';

const params = new URLSearchParams(location.search);
const isV2 = params.has('h');
const requestID = params.get(isV2 ? 'h' : 'id') || '';
const requestPath = (isV2 ? '/ui/v2/request/' : '/ui/request/') + encodeURIComponent(requestID);
let voteChallenge = null;
let resolved = false;
let voted = false;
let submitting = false;
document.getElementById('request-id').textContent = requestID ? 'Request ' + neutralize(requestID) : 'No request id given';

function terminal(status) {
  return ['approved', 'denied', 'timeout', 'error', 'expired', 'canceled'].includes(status);
}

function updateVoteControls() {
  const disabled = resolved || voted || submitting || !voteChallenge;
  const actions = voteChallenge && voteChallenge.allowed_actions || [];
  document.getElementById('approve').disabled = disabled || !actions.includes('approve');
  document.getElementById('deny').disabled = disabled || !actions.includes('deny');
  document.getElementById('actions').hidden = resolved || voted;
}

async function load() {
  voteChallenge = null;
  updateVoteControls();
  if (!requestID) { setStatus('No request id in the URL.', 'error'); return; }
  const result = await apiGet(requestPath);
  if (result.status === 404) { setStatus('Unknown request.', 'error'); return; }
  if (!result.ok) { setStatus('Could not load the request.', 'error'); return; }
  const request = result.data;
  const integrity = document.getElementById('integrity');
  integrity.textContent = '';
  if (isV2) integrity.appendChild(renderV2Review(request));
  else integrity.appendChild(el('p', {text: neutralize(request.legacy_label || 'Legacy v1 request')}));
  if (request.terminal_reason) integrity.appendChild(el('p', {text: neutralize(request.terminal_reason)}));
  for (const command of request.command_details || []) integrity.appendChild(renderCommand(command, {prominent: true}));
  document.getElementById('requester').textContent = isV2 ? (request.review && request.review.requester || '—') : neutralize(request.client_id || '—');
  document.getElementById('submitted').textContent = fmtTime(isV2 ? request.review && request.review.submitted_at : request.created_at);
  document.getElementById('request-status').textContent = neutralize(request.approval_status || request.status || '—');
  const tally = document.getElementById('tally');
  tally.textContent = '';
  tally.appendChild(isV2 ? renderV2Votes(request.votes, request.required_approvals) : renderTally(request.tally, true));
  document.getElementById('detail').hidden = false;
  resolved = terminal(request.approval_status || request.status) || Boolean(request.terminal_reason);
  voted = voted || Boolean(request.viewer_vote);
  voteChallenge = request.vote_challenge || null;
  document.getElementById('approve').textContent = isV2 && request.review ? request.review.approve_label : 'Approve';
  updateVoteControls();
  if (resolved) setStatus('This request is already ' + neutralize(request.terminal_reason || request.approval_status || request.status) + '.', '');
  else if (voted) setStatus(request.viewer_vote ? 'Your ' + neutralize(request.viewer_vote) + ' vote is recorded.' : 'Your vote is recorded.', '');
}

async function vote(decision) {
  if (resolved || voted || submitting || !voteChallenge || !voteChallenge.allowed_actions.includes(decision)) return;
  const code = document.getElementById('step-up-code').value.trim();
  const body = {challenge: voteChallenge.challenge};
  if (code) body.step_up_totp = code;
  submitting = true;
  updateVoteControls();
  setStatus('Submitting…', '');
  try {
    const result = await apiPost(requestPath + '/' + decision, body, {keep401: true});
    if (result.status === 401 && result.data && result.data.error === 'step-up required') {
      document.getElementById('step-up').hidden = false;
      setStatus('Step-up required: enter your 6-digit code and submit again.', 'error');
      return;
    }
    if (result.status === 401) { gotoLogin(); return; }
    if (result.status === 409) {
      setStatus((result.data && result.data.error) || 'This request was already resolved.', 'error');
      await load();
      return;
    }
    if (result.status === 503 && result.data && typeof result.data.error === 'string' && result.data.error.startsWith('busy')) {
      const fresh = result.data.error === 'busy — retry with a fresh code';
      if (fresh) {
        document.getElementById('step-up-code').value = '';
        document.getElementById('step-up').hidden = false;
      }
      setStatus('The signer is busy — tap again.' + (fresh ? ' Wait for the next authenticator code.' : ''), 'error');
      return;
    }
    if (result.status === 404) { setStatus('Unknown request.', 'error'); return; }
    if (!result.ok) { setStatus((result.data && result.data.error) || 'Could not record your vote.', 'error'); return; }
    voted = true;
    const decisionState = result.data.decision;
    await load();
    if (decisionState === 'approved') setStatus(isV2 ? 'Approved — awaiting execution.' : 'Approved — signatures minted.', 'ok');
    else if (decisionState === 'denied') setStatus('Denied.', '');
    else setStatus('Recorded — awaiting more approvals.', '');
  } finally {
    submitting = false;
    updateVoteControls();
  }
}

document.getElementById('approve').addEventListener('click', function () { vote('approve'); });
document.getElementById('deny').addEventListener('click', function () { vote('deny'); });
document.getElementById('logout').addEventListener('click', function (event) { event.preventDefault(); logout(); });
load();
