'use strict';

(async function () {
  const result = await apiGet('/ui/pending');
  if (result.ok) location.href = 'pending.html';
  else if (result.status !== 401) setStatus('The signer UI is unavailable.', 'error');
})();
