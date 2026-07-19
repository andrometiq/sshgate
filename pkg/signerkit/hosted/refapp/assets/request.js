'use strict';

const requestID = new URLSearchParams(location.search).get('id') || '';
const requestPath = '/ui/request/' + encodeURIComponent(requestID);
let resolved = false;
let voted = false;
let submitting = false;
document.getElementById('request-id').textContent = requestID ? 'Request ' + neutralize(requestID) : 'No request id given';

function terminal(status) {
  return ['approved', 'denied', 'timeout', 'error'].includes(status);
}

function updateVoteControls() {
  const disabled = resolved || voted || submitting;
  document.getElementById('approve').disabled = disabled;
  document.getElementById('deny').disabled = disabled;
  document.getElementById('actions').hidden = resolved || voted;
}

async function load() {
  if (!requestID) { setStatus('No request id in the URL.', 'error'); return; }
  const result = await apiGet(requestPath);
  if (result.status === 404) { setStatus('Unknown request.', 'error'); return; }
  if (!result.ok) { setStatus('Could not load the request.', 'error'); return; }
  const request = result.data;
  const integrity = document.getElementById('integrity');
  integrity.textContent = '';
  for (const command of request.command_details || []) integrity.appendChild(renderCommand(command, {prominent: true}));
  document.getElementById('requester').textContent = neutralize(request.client_id || '—');
  document.getElementById('submitted').textContent = fmtTime(request.created_at);
  document.getElementById('request-status').textContent = neutralize(request.status || '—');
  const tally = document.getElementById('tally');
  tally.textContent = '';
  tally.appendChild(renderTally(request.tally, true));
  document.getElementById('detail').hidden = false;
  resolved = terminal(request.status);
  voted = Boolean(request.viewer_vote);
  updateVoteControls();
  if (resolved) setStatus('This request is already ' + neutralize(request.status) + '.', '');
  else if (voted) setStatus('Your ' + neutralize(request.viewer_vote) + ' vote is recorded.', '');
}

async function vote(decision) {
  if (resolved || voted || submitting) return;
  const code = document.getElementById('step-up-code').value.trim();
  const body = code ? {step_up_totp: code} : {};
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
    if (result.status === 404) { setStatus('Unknown request.', 'error'); return; }
    if (!result.ok) { setStatus((result.data && result.data.error) || 'Could not record your vote.', 'error'); return; }
    voted = true;
    const decisionState = result.data.decision;
    await load();
    if (decisionState === 'approved') setStatus('Approved — signatures minted.', 'ok');
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
