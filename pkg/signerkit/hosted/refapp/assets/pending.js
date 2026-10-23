'use strict';

let nextOffset = 0;
let nextCursor = null;
let moreV1 = true;
let moreV2 = true;
let loading = false;

async function load(reset) {
  if (loading) return;
  loading = true;
  try {
    setStatus('Loading…', '');
    const includeV1 = reset || moreV1;
    const includeV2 = reset || moreV2;
    let path = '/ui/pending?offset=' + encodeURIComponent(String(reset ? 0 : nextOffset));
    if (!reset && includeV2 && nextCursor) path += '&v2_cursor=' + encodeURIComponent(nextCursor);
    const result = await apiGet(path);
    if (!result.ok) { setStatus('Could not load pending requests.', 'error'); return; }
    const list = document.getElementById('list');
    if (reset) list.textContent = '';
    const rows = includeV1 && result.data && Array.isArray(result.data.pending) ? result.data.pending : [];
    const v2Rows = includeV2 && result.data && Array.isArray(result.data.v2_pending) ? result.data.v2_pending : [];
    if (reset && !rows.length && !v2Rows.length) list.appendChild(el('div', {class: 'empty', text: 'No pending requests.'}));
    for (const row of rows) {
      const card = el('article', {class: 'card'});
      card.appendChild(el('a', {
        class: 'rid',
        href: 'request.html?id=' + encodeURIComponent(row.request_id),
        text: neutralize(row.request_id),
      }));
      card.appendChild(el('div', {
        class: 'meta',
        text: 'from ' + neutralize(row.client_id) + ' · submitted ' + fmtTime(row.created_at),
      }));
      card.appendChild(el('p', {text: neutralize(row.legacy_label || 'Legacy v1 request')}));
      for (const command of row.command_details || []) card.appendChild(renderCommand(command));
      card.appendChild(renderTally(row.tally, false));
      list.appendChild(card);
    }
    for (const row of v2Rows) {
      const card = el('article', {class: 'card'});
      card.appendChild(el('a', {class: 'rid', href: 'request.html?h=' + encodeURIComponent(row.record_handle), text: row.record_handle}));
      card.appendChild(el('p', {text: 'from ' + (row.review && row.review.requester || '—') + ' · ' + row.approval_status}));
      card.appendChild(renderV2Review(row));
      card.appendChild(renderV2Votes(row.votes, row.required_approvals));
      list.appendChild(card);
    }
    if (includeV1) nextOffset = result.data && Number.isInteger(result.data.next_offset) ? result.data.next_offset : (reset ? 0 : nextOffset) + rows.length;
    moreV1 = includeV1 && Boolean(result.data && result.data.has_more);
    moreV2 = includeV2 && Boolean(result.data && result.data.v2_has_more);
    if (includeV2) nextCursor = result.data && result.data.v2_next_cursor;
    document.getElementById('load-more').hidden = !moreV1 && !moreV2;
    setStatus('', '');
  } finally { loading = false; }
}

document.getElementById('refresh').addEventListener('click', function () { load(true); });
document.getElementById('load-more').addEventListener('click', function () { load(false); });
document.getElementById('logout').addEventListener('click', function (event) { event.preventDefault(); logout(); });
load(true);
