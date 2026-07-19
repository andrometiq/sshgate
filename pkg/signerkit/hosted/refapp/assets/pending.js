'use strict';

let nextOffset = 0;

async function load(reset) {
  setStatus('Loading…', '');
  if (reset) nextOffset = 0;
  const result = await apiGet('/ui/pending?offset=' + encodeURIComponent(String(nextOffset)));
  if (!result.ok) { setStatus('Could not load pending requests.', 'error'); return; }
  const list = document.getElementById('list');
  if (reset) list.textContent = '';
  const rows = result.data && Array.isArray(result.data.pending) ? result.data.pending : [];
  if (reset && !rows.length) list.appendChild(el('div', {class: 'empty', text: 'No pending requests.'}));
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
    for (const command of row.command_details || []) card.appendChild(renderCommand(command));
    card.appendChild(renderTally(row.tally, false));
    list.appendChild(card);
  }
  nextOffset = result.data && Number.isInteger(result.data.next_offset) ? result.data.next_offset : nextOffset + rows.length;
  document.getElementById('load-more').hidden = !(result.data && result.data.has_more);
  setStatus('', '');
}

document.getElementById('refresh').addEventListener('click', function () { load(true); });
document.getElementById('load-more').addEventListener('click', function () { load(false); });
document.getElementById('logout').addEventListener('click', function (event) { event.preventDefault(); logout(); });
load(true);
