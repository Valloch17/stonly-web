// Guide Publisher page logic
if (typeof window.requireAdmin === 'function') {
  window.requireAdmin();
}

const __isLocal = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|.*\.local)$/i.test(window.location.hostname);
const DEFAULT_BACKEND = window.DEFAULT_BACKEND || (__isLocal ? 'http://localhost:8000' : 'https://stonly-web.onrender.com');
const BASE = (window.BASE || DEFAULT_BACKEND).replace(/\/+$/, '');
window.DEFAULT_BACKEND = DEFAULT_BACKEND;
window.BASE = BASE;

const el = (id) => document.getElementById(id);

function setStatus(msg, tone = 'muted') {
  const node = el('statusText');
  if (!node) return;
  node.textContent = msg || '';
  node.className = 'text-sm';
  if (tone === 'error') node.classList.add('text-red-600');
  else if (tone === 'success') node.classList.add('text-green-600');
  else node.classList.add('text-slate-500');
}

function logLine(msg) {
  const ta = el('logBox');
  if (!ta) return;
  const ts = new Date().toISOString().slice(11, 23);
  ta.value += `[${ts}] ${msg}\n`;
  ta.scrollTop = ta.scrollHeight;
}

function clearLog() {
  const ta = el('logBox');
  if (ta) ta.value = '';
}

function setLoading(loading) {
  const btn = el('publishBtn');
  if (!btn) return;
  btn.disabled = !!loading;
  btn.textContent = loading ? 'Publishing…' : 'Publish draft guides';
}

function renderDrafts(items) {
  const tbody = el('draftTable');
  const summary = el('summaryCounts');
  if (!tbody) return;
  tbody.innerHTML = '';
  const list = Array.isArray(items) ? items : [];
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="px-3 py-3 text-center text-slate-500">No draft guides found.</td></tr>';
    if (summary) summary.textContent = '';
    return;
  }

  list.forEach((it) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="px-3 py-2 border-b font-mono text-xs">${it.id || ''}</td>
      <td class="px-3 py-2 border-b">${it.name || ''}</td>
      <td class="px-3 py-2 border-b text-sm text-slate-600">${it.folder?.name || ''}</td>
      <td class="px-3 py-2 border-b text-sm">${Array.isArray(it.languages) ? it.languages.join(', ') : ''}</td>
      <td class="px-3 py-2 border-b text-sm capitalize">${it.status || ''}</td>
    `;
    tbody.appendChild(tr);
  });
  if (summary) summary.textContent = `${list.length} draft guide${list.length === 1 ? '' : 's'}`;
}

function collectSettings() {
  const toInt = (v) => {
    const n = parseInt(v, 10);
    return Number.isFinite(n) ? n : null;
  };
  return {
    teamId: toInt(el('teamSelect')?.value),
    folderId: toInt(el('folderId')?.value),
    user: (el('user')?.value || '').trim() || 'Undefined',
    base: (el('base')?.value || '').trim() || 'https://public.stonly.com/api/v3',
    includeSubfolders: !!el('includeSubfolders')?.checked,
  };
}

async function apiFetch(path, init) {
  const res = await fetch(BASE + path, { credentials: 'include', ...(init || {}) });
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  const text = await res.text();

  if (ct.startsWith('text/html')) {
    throw new Error(`Got HTML from ${BASE + path}. Check BASE or routing.`);
  }

  let json;
  try { if (ct.includes('application/json')) json = JSON.parse(text); } catch (_) { /* ignore */ }
  if (!res.ok) {
    const msg = json?.detail || json?.message || text || `HTTP ${res.status}`;
    throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
  }
  return json ?? text;
}

async function publishDrafts() {
  const ok = window.validateRequired?.(['teamSelect', 'folderId']);
  if (!ok) return;

  const settings = collectSettings();
  const payload = {
    folderId: settings.folderId,
    includeSubfolders: settings.includeSubfolders,
    // Fixed to the Stonly max per page (API requires page+limit even though we paginate internally)
    limit: 100,
    creds: {
      user: settings.user,
      teamId: settings.teamId,
      base: settings.base,
    },
  };

  try {
    setLoading(true);
    setStatus('Looking for draft guides...', 'info');
    logLine(`Listing drafts in folder ${settings.folderId} (recursive=${settings.includeSubfolders})`);

    const data = await apiFetch('/api/guides/publish-drafts', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });

    renderDrafts(data?.drafts || []);
    const published = data?.publishedCount || 0;
    const found = data?.draftCount || 0;
    setStatus(`Published ${published}/${found} draft guides.`, 'success');
    logLine(`Found ${found} draft guide(s). Published ${published}.`);
    if (Array.isArray(data?.publishedIds) && data.publishedIds.length) {
      logLine(`Published IDs: ${data.publishedIds.join(', ')}`);
    }
  } catch (e) {
    const msg = e?.message || 'Failed to publish drafts';
    setStatus(msg, 'error');
    logLine(`Error: ${msg}`);
  } finally {
    setLoading(false);
  }
}

(window.onReady || ((fn) => fn()))(() => {
  el('publishBtn')?.addEventListener('click', publishDrafts);
  el('clearLog')?.addEventListener('click', clearLog);
});
