document.getElementById('check').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const out = document.getElementById('out');
  if (!tab || !tab.url) { out.textContent = 'No URL found for this tab.'; return; }
  const r = analyzeUrl(tab.url);
  const cls = r.verdict.startsWith('SCAM') ? 'scam' : r.verdict.startsWith('SUS') ? 'sus' : 'safe';
  out.innerHTML = '<div class="score ' + cls + '">' + r.score + '/100 — ' + r.verdict + '</div>' +
    '<div style="color:#7f8db3;word-break:break-all">' + tab.url.replace(/</g, '&lt;') + '</div>' +
    '<ul>' + r.reasons.map(x => '<li>' + x.replace(/</g, '&lt;') + '</li>').join('') + '</ul>';
});
