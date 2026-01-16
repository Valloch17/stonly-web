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
    const teamId = el('teamSelect')?.value ? Number(el('teamSelect').value) : null;
    const base = (window.getApiBase && window.getApiBase()) || 'https://public.stonly.com/api/v3';
    const parentId = el('parentId')?.value ? Number(el('parentId').value) : null;
    const publicAccess = parseInt((el('publicAccess')?.value || '1'), 10);
    const language = (el('lang')?.value || 'en').trim() || 'en';
    return { user, teamId, base, parentId, publicAccess, language };
  }

  function setOut(id, value){
    const out = el(id);
    if (!out) return;
    try { out.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2); }
    catch { out.textContent = String(value); }
  }

  function stripCodeFences(text){
    if (!text) return '';
    let s = text.trim();
    s = s.replace(/^```[a-zA-Z0-9_-]*\s*/, '');
    s = s.replace(/\s*```$/, '');
    return s.trim();
  }

  function wrapRootIfNeeded(text){
    const src = text || '';
    try {
      const data = jsyaml.load(src);
      if (data && typeof data === 'object' && !Array.isArray(data) && !('guide' in data)) {
        const keys = new Set(Object.keys(data).map((k) => String(k || '').toLowerCase()));
        if (keys.has('contenttitle') || keys.has('firststep')) {
          return jsyaml.dump({ guide: data }, { noRefs: true, sortKeys: false }).trim();
        }
      }
    } catch { /* best-effort only */ }
    return src;
  }

  function indentLen(line){
    let count = 0;
    for (let i = 0; i < line.length; i += 1) {
      const ch = line[i];
      if (ch === ' ') count += 1;
      else if (ch === '\t') count += 2;
      else break;
    }
    return count;
  }

  function fixPreBlockIndentation(text){
    if (!text) return '';
    const lines = text.split(/\r?\n/);
    const blockRe = /^(?<indent>[ \t]*)(?:-[ \t]+)?[^#\n]*:\s*[|>][0-9+-]*\s*$/;
    const out = [];
    let inBlock = false;
    let inPre = false;
    let baseIndent = 0;
    let contentIndent = null;
    let i = 0;

    while (i < lines.length) {
      let line = lines[i];
      if (!inBlock) {
        out.push(line);
        const match = line.match(blockRe);
        if (match) {
          inBlock = true;
          inPre = false;
          const indentText = match.groups ? match.groups.indent : (match[1] || '');
          baseIndent = indentLen(indentText);
          contentIndent = null;
        }
        i += 1;
        continue;
      }

      if (contentIndent === null && line.trim()) {
        const indent = indentLen(line);
        contentIndent = indent > baseIndent ? indent : baseIndent + 2;
      }

      const lineHasPre = /<\s*pre\b/i.test(line);
      const lineHasPreEnd = /<\/\s*pre\s*>/i.test(line);
      const isPreRelated = inPre || lineHasPre || lineHasPreEnd;

      const indent = indentLen(line);
      if (line.trim() && indent <= baseIndent && !isPreRelated) {
        inBlock = false;
        inPre = false;
        contentIndent = null;
        continue;
      }

      if (isPreRelated && line.trim()) {
        const targetIndent = contentIndent == null ? baseIndent + 2 : contentIndent;
        if (indent < targetIndent) {
          line = ' '.repeat(targetIndent) + line.replace(/^[ \t]*/, '');
        }
      }

      out.push(line);

      const preStarts = (line.match(/<\s*pre\b/gi) || []).length;
      const preEnds = (line.match(/<\/\s*pre\s*>/gi) || []).length;
      if (preStarts > preEnds) inPre = true;
      else if (preEnds > preStarts) inPre = false;

      i += 1;
    }

    return out.join('\n');
  }

  function normalizeAiYaml(text){
    if (text == null) return '';
    let s = stripCodeFences(text);
    s = s.replace(/\t/g, '  ');
    s = fixPreBlockIndentation(s);
    s = wrapRootIfNeeded(s);
    return s;
  }

  function parseGuideYamlWithFixes(rawText){
    const attempts = [];
    const base = (rawText || '').trim();
    attempts.push({ text: base, normalized: false });
    const normalized = normalizeAiYaml(base);
    if (normalized && normalized !== base) attempts.push({ text: normalized, normalized: true });

    const errors = [];
    for (const attempt of attempts){
      try {
        const docs = [];
        jsyaml.loadAll(attempt.text || '', (d) => { docs.push(d); });
        if (!docs.length) throw new Error('Empty YAML');
        return { docs, yamlText: attempt.text, normalized: attempt.normalized };
      } catch(e){
        errors.push(e);
      }
    }
    throw errors[0] || new Error('Invalid YAML');
  }

  async function onKbRun(){
    // Validate required settings
    if (!(window.validateRequired && window.validateRequired(['teamSelect','parentId']))) {
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
      creds: { user: c.user, teamId: c.teamId, base: c.base },
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

  function buildFolderMapping(rootNodes){
    const mapping = {};
    const walk = (nodes, parentPath) => {
      if (!Array.isArray(nodes)) return;
      for (const node of nodes) {
        if (!node || typeof node !== 'object') continue;
        const name = node.name != null ? String(node.name).trim() : '';
        if (!name) {
          if (Array.isArray(node.children) && node.children.length) {
            walk(node.children, parentPath);
          }
          continue;
        }
        const path = parentPath ? `${parentPath}/${name}` : `/${name}`;
        const rawId = node.id ?? node.folderId ?? node.entityId;
        const idNum = Number(rawId);
        if (path && Number.isFinite(idNum)) mapping[path] = idNum;
        if (Array.isArray(node.children) && node.children.length) {
          walk(node.children, path);
        }
      }
    };
    walk(rootNodes, '');
    return mapping;
  }

  async function onKbDump(){
    if (!(window.validateRequired && window.validateRequired(['teamSelect','parentId']))) {
      setOut('kbOut', 'Please fill all required fields (*).');
      return;
    }
    const c = collectCommon();
    const params = new URLSearchParams();
    params.set('teamId', String(c.teamId));
    params.set('base', c.base || 'https://public.stonly.com/api/v3');
    if (c.parentId != null) params.set('parentId', String(c.parentId));

    setOut('kbOut', 'Loading...');
    try {
      const data = await apiFetch(`/api/dump-structure?${params.toString()}`, { method: 'GET' });
      const root = data && typeof data === 'object' ? data.root : null;
      if (!Array.isArray(root)) throw new Error('Unexpected response from dump-structure.');
      const mapping = buildFolderMapping(root);
      setOut('kbOut', { ok: true, mapping });
    } catch(e){ setOut('kbOut', String(e.message || e)); }
  }

  function stripContentKeysDeep(node){
    if (Array.isArray(node)) {
      return node.map(stripContentKeysDeep);
    }
    if (node && typeof node === 'object') {
      const out = {};
      for (const key of Object.keys(node)) {
        if (key === 'content' || key === 'media') continue;
        out[key] = stripContentKeysDeep(node[key]);
      }
      return out;
    }
    return node;
  }

  function buildGuideSummaryYaml(docs){
    const chunks = [];
    for (const raw of docs) {
      if (raw == null) continue;
      const stripped = stripContentKeysDeep(raw);
      try {
        const dumped = jsyaml.dump(stripped, { noRefs: true }).trimEnd();
        if (dumped) chunks.push('---\n' + dumped);
      } catch {
        // If dumping somehow fails, skip this document
      }
    }
    return chunks.join('\n\n');
  }

  async function copyGuideSummaryToClipboard(docs){
    const summary = buildGuideSummaryYaml(docs);
    if (!summary) return;
    try {
      if (typeof navigator !== 'undefined' &&
          navigator.clipboard &&
          typeof navigator.clipboard.writeText === 'function') {
        await navigator.clipboard.writeText(summary);
      }
    } catch {
      // Swallow clipboard errors so parsing still feels smooth.
    }
  }

  async function onGuideParse(){
    const t = (el('guideYaml')?.value || '').trim();
    const err = el('guideYamlError');
    const btn = el('guideParseBtn');
    const defaultLabel = 'Parse YAML | Copy';
    const successClass = 'guide-parse-copied';
    if (btn) {
      btn.textContent = defaultLabel;
      btn.classList.remove(successClass);
    }
    try {
      const parsed = parseGuideYamlWithFixes(t);
      if (parsed.normalized) {
        const field = el('guideYaml');
        if (field) {
          field.value = parsed.yamlText;
          try { field.dispatchEvent(new Event('input', { bubbles: true })); } catch {}
        }
      }
      if (err) err.textContent = '';
      try {
        await copyGuideSummaryToClipboard(parsed.docs);
      } catch {}
      if (btn) {
        btn.textContent = 'YAML Copied';
        btn.classList.add(successClass);
        try {
          setTimeout(() => {
            const current = el('guideParseBtn');
            if (current) {
              if (current.textContent === 'YAML Copied') {
                current.textContent = defaultLabel;
              }
              current.classList.remove(successClass);
            }
          }, 1200);
        } catch {}
      }
    }
    catch(e){
      if (err) err.textContent = 'Invalid YAML: ' + (e?.message || e);
      if (btn) {
        btn.textContent = defaultLabel;
        btn.classList.remove(successClass);
      }
    }
  }

  function applyOrganiserMapping(guideYaml, organiserYaml){
    const orgText = (organiserYaml || '').trim();
    if (!orgText) return guideYaml;

    const guideDocs = [];
    const guideText = fixPreBlockIndentation((guideYaml || '').trim());
    jsyaml.loadAll(guideText, (d) => { guideDocs.push(d); });
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
    if (!(window.validateRequired && window.validateRequired(['teamSelect','parentId']))) {
      setOut('guideOut', 'Please fill all required fields (*).');
      return;
    }
    const yamlText = fixPreBlockIndentation((el('guideYaml')?.value || '').trim());
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
      creds: { user: c.user, teamId: c.teamId, base: c.base }
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
    el('kbRunBtn')?.addEventListener('click', onKbRun);
    el('kbDumpBtn')?.addEventListener('click', onKbDump);
    el('guideParseBtn')?.addEventListener('click', onGuideParse);
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

    // Persist YAML editors between refreshes (localStorage, per-field keys)
    try {
      const yamlFields = [
        { id: 'kbYaml', key: 'expert_kb_yaml' },
        { id: 'guideYaml', key: 'expert_guide_yaml' },
        { id: 'organiserYaml', key: 'expert_organiser_yaml' },
      ];
      yamlFields.forEach(({ id, key }) => {
        const field = el(id);
        if (!field) return;
        try {
          const stored = localStorage.getItem(key);
          if (typeof stored === 'string' && stored.length) {
            field.value = stored;
          }
        } catch {}
        field.addEventListener('input', () => {
          try {
            localStorage.setItem(key, field.value || '');
          } catch {}
        });
      });
    } catch {}
  });
})();
