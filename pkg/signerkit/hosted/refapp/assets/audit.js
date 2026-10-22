'use strict';

const allowedStatuses = new Set(['approved', 'denied', 'timeout', 'error', 'pending']);

async function load() {
  setStatus('Loading…', '');
  const result = await apiGet('/ui/audit');
  if (!result.ok) { setStatus('Could not load the audit view.', 'error'); return; }
  const list = document.getElementById('list');
  list.textContent = '';
  const rows = result.data && Array.isArray(result.data.entries) ? result.data.entries : [];
  const v2Rows = result.data && Array.isArray(result.data.v2_entries) ? result.data.v2_entries : [];
  if (!rows.length && !v2Rows.length) list.appendChild(el('div', {class: 'empty', text: 'No decisions recorded yet.'}));
  for (const row of rows) {
    const card = el('article', {class: 'card'});
    const heading = el('div');
    const status = allowedStatuses.has(row.status) ? row.status : '';
    heading.appendChild(el('span', {class: 'rid', text: neutralize(row.request_id)}));
    heading.appendChild(document.createTextNode(' '));
    heading.appendChild(el('span', {class: 'pill ' + status, text: neutralize(row.status || '—')}));
    card.appendChild(heading);
    let meta = 'from ' + neutralize(row.client_id) + ' · submitted ' + fmtTime(row.created_at);
    if (row.resolved_at) meta += ' · resolved ' + fmtTime(row.resolved_at);
    if (row.approved_by_user) meta += ' · by ' + neutralize(row.approved_by_user);
    card.appendChild(el('div', {class: 'meta', text: meta}));
    for (const command of row.command_details || []) card.appendChild(renderCommand(command));
    list.appendChild(card);
  }
  for (const row of v2Rows) {
    const card = el('article', {class: 'card'});
    card.appendChild(el('a', {class: 'rid', href: 'request.html?h=' + encodeURIComponent(row.record_handle), text: row.record_handle}));
    for (const line of [row.sub_principal, row.decision, fmtTime(row.decided_at), row.decided_by, row.rationale_redacted]) {
      if (line) card.appendChild(el('p', {text: line}));
    }
    const assist = row.assist_bound || {};
    card.appendChild(el('p', {text: 'AI advisory: ' + assist.state + ' · revision ' + assist.revision + ' · digest ' + assist.digest}));
    card.appendChild(renderV2Votes(row.votes));
    list.appendChild(card);
  }
  setStatus('', '');
}

document.getElementById('logout').addEventListener('click', function (event) { event.preventDefault(); logout(); });
load();
