// Expert mode JS: lean KB + Guide builders using existing backend endpoints
(function(){
  if (typeof window.requireAdmin === 'function') {
    window.requireAdmin();
  }
  const el = (id) => document.getElementById(id);

  function getBASE(){
    try { return (window.BASE || window.DEFAULT_BACKEND || '').replace(/\/+$/, ''); } catch { return ''; }
  }

  async function apiFetch(path, init){
    const base = getBASE();
    const url = base + path;
    const res = await fetch(url, { credentials: 'include', ...(init || {}) });
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    const text = await res.text();
    let json;
    try { if (ct.includes('application/json')) json = JSON.parse(text); } catch {}
    if (!res.ok) {
      const msg = json?.detail || json?.message || text || `HTTP ${res.status}`;
      throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
    return json ?? text;
  }

  function parseKBYaml(text){
    const kbErr = el('kbYamlError');
    if (kbErr) kbErr.textContent = '';
    let data;
    try { data = jsyaml.load((text || '').trim()); } catch(e){ throw new Error('Invalid YAML: ' + (e?.message || e)); }
    let root = Array.isArray(data) ? data : (Array.isArray(data?.root) ? data.root : null);
    if (!root) throw new Error("YAML must contain a top-level list or a 'root' list.");

    const norm = (n) => ({
      name: String(n?.name ?? ''),
      description: (n?.description ?? '') ? String(n.description) : undefined,
      children: Array.isArray(n?.children) ? n.children.map(norm) : []
    });
    root = root.map(norm);

    const invalid = [];
    const walk = (list, p='') => list.forEach(node => {
      if (!node.name || !node.name.trim()) invalid.push((p ? p + '/' : '/') + '<empty-name>');
      if (node.children?.length) walk(node.children, (p ? p + '/' : '') + node.name);
    });
    walk(root);
    if (invalid.length){ throw new Error('Invalid nodes at: ' + invalid.join(', ')); }
    return root;
  }

  function collectCommon(){
    const rawUser = (el('st_user')?.value || '').trim();
    const user = rawUser || "Undefined";
    const password = (el('st_pass')?.value || '').trim();
    const teamId = el('st_team')?.value ? Number(el('st_team').value) : null;
    const base = (el('st_base')?.value || '').trim() || 'https://public.stonly.com/api/v3';
    const parentId = el('parentId')?.value ? Number(el('parentId').value) : null;
    const publicAccess = parseInt((el('publicAccess')?.value || '1'), 10);
    const language = (el('lang')?.value || 'en').trim() || 'en';
    return { user, password, teamId, base, parentId, publicAccess, language };
  }

  function setOut(id, value){
    const out = el(id);
    if (!out) return;
    try { out.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2); }
    catch { out.textContent = String(value); }
  }

  async function onKbParse(){
    const t = (el('kbYaml')?.value || '').trim();
    const err = el('kbYamlError');
    try {
      const root = parseKBYaml(t);
      if (err) err.textContent = '';
      // Optional: quick success flash via console
    } catch(e){ if (err) err.textContent = String(e.message || e); }
  }

  async function onKbRun(){
    // Validate required settings
    if (!(window.validateRequired && window.validateRequired(['st_user','st_pass','st_team','parentId']))) {
      setOut('kbOut', 'Please fill all required fields (*).');
      return;
    }
    const yamlText = (el('kbYaml')?.value || '').trim();
    if (!yamlText){ setOut('kbOut', 'Please provide KB YAML.'); return; }

    let root;
    try { root = parseKBYaml(yamlText); } catch(e){ setOut('kbOut', String(e.message || e)); return; }

    const c = collectCommon();
    const body = {
      parentId: c.parentId,
      creds: { user: c.user, password: c.password, teamId: c.teamId, base: c.base },
      settings: { publicAccess: c.publicAccess, language: c.language },
      dryRun: false,
      root
    };

    setOut('kbOut', 'Running...');
    try {
      const data = await apiFetch('/api/apply', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
      });
      setOut('kbOut', data);
    } catch(e){ setOut('kbOut', String(e.message || e)); }
  }

  async function onGuideParse(){
    const t = (el('guideYaml')?.value || '').trim();
    const err = el('guideYamlError');
    try {
      const docs = [];
      jsyaml.loadAll(t || '', (d) => { docs.push(d); });
      if (!docs.length) throw new Error('Empty YAML');
      if (err) err.textContent = '';
    }
    catch(e){ if (err) err.textContent = 'Invalid YAML: ' + (e?.message || e); }
  }

  async function onOrganiserParse(){
    const t = (el('organiserYaml')?.value || '').trim();
    const err = el('organiserYamlError');
    if (!t) { if (err) err.textContent = ''; return; }
    try {
      const docs = [];
      jsyaml.loadAll(t, (d) => { docs.push(d); });
      if (!docs.length) throw new Error('Empty YAML');
      if (err) err.textContent = '';
    } catch(e){
      if (err) err.textContent = 'Invalid YAML: ' + (e?.message || e);
    }
  }

  function applyOrganiserMapping(guideYaml, organiserYaml){
    const orgText = (organiserYaml || '').trim();
    if (!orgText) return guideYaml;

    const guideDocs = [];
    jsyaml.loadAll(guideYaml || '', (d) => { guideDocs.push(d); });
    if (!guideDocs.length) throw new Error('No guides found in Guide YAML');

    const organiserDocs = [];
    jsyaml.loadAll(orgText, (d) => { organiserDocs.push(d); });
    if (!organiserDocs.length) return guideYaml;

    const titleTypeToFolder = new Map();
    for (const raw of organiserDocs) {
      if (!raw || typeof raw !== 'object') continue;
      const folderId = raw.folderId ?? raw.folder_id;
      const g = (raw.guide && typeof raw.guide === 'object') ? raw.guide : raw;
      const title = g && typeof g.contentTitle === 'string' ? g.contentTitle.trim() : '';
      const ct = g && typeof g.contentType === 'string' ? g.contentType.trim() : (typeof raw.contentType === 'string' ? raw.contentType.trim() : 'GUIDE');
      if (!title || !ct) continue;
      const idNum = Number(folderId);
      if (!Number.isFinite(idNum) || idNum <= 0) continue;
      const key = `${title}||${ct.toUpperCase()}`;
      if (!titleTypeToFolder.has(key)) titleTypeToFolder.set(key, idNum);
    }

    if (!titleTypeToFolder.size) return guideYaml;

    const transformed = guideDocs.map((raw) => {
      if (!raw || typeof raw !== 'object') return raw;
      const g = (raw.guide && typeof raw.guide === 'object') ? raw.guide : raw;
      const title = g && typeof g.contentTitle === 'string' ? g.contentTitle.trim() : '';
      const ct = g && typeof g.contentType === 'string'
        ? g.contentType.trim()
        : (typeof raw.contentType === 'string' ? raw.contentType.trim() : 'GUIDE');
      if (!title || !ct) return raw;
      const key = `${title}||${ct.toUpperCase()}`;
      const idNum = titleTypeToFolder.get(key);
      if (idNum == null) return raw;
      const copy = Array.isArray(raw) ? raw.slice() : { ...raw };
      copy.folderId = idNum;
      return copy;
    });

    const docsYaml = transformed.map((d) => jsyaml.dump(d, { noRefs: true }).trimEnd());
    return docsYaml.join('\n---\n');
  }

  async function onGuideRun(){
    if (!(window.validateRequired && window.validateRequired(['st_user','st_pass','st_team','parentId']))) {
      setOut('guideOut', 'Please fill all required fields (*).');
      return;
    }
    const yamlText = (el('guideYaml')?.value || '').trim();
    if (!yamlText){ setOut('guideOut', 'Please provide Guide YAML.'); return; }
    try {
      const docs = [];
      jsyaml.loadAll(yamlText, (d) => { docs.push(d); });
      if (!docs.length) throw new Error('Empty YAML');
    } catch(e){ setOut('guideOut', 'Invalid YAML: ' + (e?.message || e)); return; }

    const organiserText = (el('organiserYaml')?.value || '').trim();
    let finalYaml = yamlText;
    if (organiserText) {
      try {
        finalYaml = applyOrganiserMapping(yamlText, organiserText);
      } catch(e){
        setOut('guideOut', 'Invalid Guide Organiser YAML: ' + (e?.message || e));
        return;
      }
    }

    const c = collectCommon();
    const body = {
      dryRun: false,
      folderId: c.parentId,
      yaml: finalYaml,
      defaults: { language: c.language },
      publish: !!(el('guidePublish') && el('guidePublish').checked),
      creds: { user: c.user, password: c.password, teamId: c.teamId, base: c.base }
    };

    setOut('guideOut', 'Running...');
    try {
      const data = await apiFetch('/api/guides/build', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
      });
      setOut('guideOut', data);
      // If publish was requested and backend reports success, show a small alert
      const wantPublish = !!(el('guidePublish') && el('guidePublish').checked);
      if (wantPublish) {
        let published = false;
        let ids = [];
        try {
          if (data && typeof data === 'object') {
            if (data.publishedAll) { published = true; ids = data.publishedIds || data.createdIds || []; }
            else if (Array.isArray(data.results)) {
              const ok = data.results.filter(r => r && r.published);
              if (ok.length) { published = true; ids = ok.map(r => r.guideId).filter(Boolean); }
            } else if (data.published === true) {
              published = true; ids = [data.guideId].filter(Boolean);
            }
          }
        } catch {}
        if (published) {
          const msg = ids && ids.length ? `Guides published: ${ids.join(', ')}` : 'Guides published.';
          try { alert(msg); } catch {}
        }
      }
    } catch(e){ setOut('guideOut', String(e.message || e)); }
  }

  async function fetchLogs(){
    const ta = el('logBox');
    const content = el('logsContent');
    try {
      const textOrJson = await apiFetch('/api/debug/logs?lines=400', { method: 'GET' });
      const raw = typeof textOrJson === 'string' ? textOrJson : JSON.stringify(textOrJson, null, 2);
      const t = (raw || '').trim();
      if (ta) {
        ta.value = t ? `--- backend logs (tail) ---\n${t}\n--- end logs ---\n` : '';
      }
      if (content) {
        if (t) content.classList.remove('hidden');
        else content.classList.add('hidden');
      }
    } catch(e){
      if (ta) ta.value = String(e.message || e);
      if (content) content.classList.remove('hidden');
    }
  }
  function clearLogs(){
    const ta = el('logBox');
    const content = el('logsContent');
    if (ta) ta.value = '';
    if (content) content.classList.add('hidden');
  }

  // Wire events on DOM ready (shared.js exposes window.onReady)
  (window.onReady || ((fn)=>fn()))(() => {
    el('kbParseBtn')?.addEventListener('click', onKbParse);
    el('kbRunBtn')?.addEventListener('click', onKbRun);
    el('guideParseBtn')?.addEventListener('click', onGuideParse);
    el('organiserParseBtn')?.addEventListener('click', onOrganiserParse);
    el('guideRunBtn')?.addEventListener('click', onGuideRun);
    el('btnFetchLogs')?.addEventListener('click', fetchLogs);
    el('btnClearLogs')?.addEventListener('click', clearLogs);

    // Copy buttons
    try {
      if (typeof window.attachCopyButton === 'function') {
        window.attachCopyButton({ buttonId: 'copyKbOut', sourceId: 'kbOut', disableWhenEmpty: true });
        window.attachCopyButton({ buttonId: 'copyGuideOut', sourceId: 'guideOut', disableWhenEmpty: true });
      }
    } catch {}
  });
})();
