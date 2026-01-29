// Expert mode JS: lean KB + Guide builders using existing backend endpoints
(function(){
  if (typeof window.requireAdmin === 'function') {
    window.requireAdmin();
  }
  const el = (id) => document.getElementById(id);
  const MODE_STORAGE_KEY = 'expert_mode';
  const AUTO_BRAND_KEY = 'expert_auto_brand';
  const AUTO_PROMPT_KEY = 'expert_auto_prompt';

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

  function cleanGeminiYaml(text){
    if (typeof window.cleanGeminiYaml === 'function') return window.cleanGeminiYaml(text);
    if (text == null) return '';
    return String(text).replace(/\[cite_start\]/g, '');
  }

  function cleanGuideYamlInput(updateField){
    const field = el('guideYaml');
    const raw = field?.value || '';
    const cleaned = cleanGeminiYaml(raw);
    if (updateField && field && cleaned !== raw) {
      field.value = cleaned;
      try { field.dispatchEvent(new Event('input', { bubbles: true })); } catch {}
    }
    return cleaned.trim();
  }

  function fixUnquotedColonsInScalars(text){
    if (!text) return '';
    const lines = text.split(/\r?\n/);
    if (!lines.length) return text;
    const blockRe = /^(?<indent>[ \t]*)(?:-[ \t]+)?[^#\n]*:\s*[|>][0-9+-]*\s*$/;
    const keyRe = /^(?<indent>[ \t]*)(?<dash>-\s+)?(?<key>label|title|contentTitle|name|description)\s*:\s*(?<val>.+)\s*$/;
    const out = [];
    let inBlock = false;
    let baseIndent = 0;

    for (let i = 0; i < lines.length; i += 1) {
      let line = lines[i];
      if (!inBlock) {
        const match = line.match(keyRe);
        if (match && match.groups) {
          const raw = match.groups.val || '';
          const stripped = raw.trim();
          if (stripped && !/^['"|>]/.test(stripped) && /:\s/.test(stripped)) {
            const escaped = stripped.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
            line = `${match.groups.indent || ''}${match.groups.dash || ''}${match.groups.key}: "${escaped}"`;
          }
        }
        out.push(line);
        const blockMatch = line.match(blockRe);
        if (blockMatch) {
          inBlock = true;
          baseIndent = indentLen(blockMatch.groups ? blockMatch.groups.indent || '' : '');
        }
        continue;
      }
      const currentIndent = indentLen(line);
      if (line.trim() && currentIndent <= baseIndent) {
        inBlock = false;
        i -= 1;
        continue;
      }
      out.push(line);
    }
    return out.join('\n');
  }

  function normalizeAiYaml(text){
    if (text == null) return '';
    let s = stripCodeFences(text);
    s = cleanGeminiYaml(s);
    s = s.replace(/\t/g, '  ');
    s = fixPreBlockIndentation(s);
    s = fixUnquotedColonsInScalars(s);
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

  function setExpertMode(mode){
    const manualBtn = el('expertModeManual');
    const autoBtn = el('expertModeAuto');
    const manualSection = el('expertManualSections');
    const autoSection = el('expertAutomatedSection');
    const brandSection = el('brandAssetsSection');
    const useAuto = mode === 'automated';

    if (manualSection) manualSection.classList.toggle('hidden', useAuto);
    if (autoSection) autoSection.classList.toggle('hidden', !useAuto);
    if (brandSection) brandSection.classList.toggle('hidden', !useAuto);

    if (manualBtn) {
      manualBtn.classList.toggle('is-active', !useAuto);
      manualBtn.setAttribute('aria-pressed', (!useAuto).toString());
    }
    if (autoBtn) {
      autoBtn.classList.toggle('is-active', useAuto);
      autoBtn.setAttribute('aria-pressed', useAuto.toString());
    }

    try { localStorage.setItem(MODE_STORAGE_KEY, useAuto ? 'automated' : 'manual'); } catch {}
  }

  function setAutoStatus(message, tone){
    const status = el('autoStatus');
    if (!status) return;
    status.textContent = message || '';
    status.classList.remove('text-slate-500', 'text-red-600', 'text-green-600');
    if (tone === 'error') status.classList.add('text-red-600');
    else if (tone === 'success') status.classList.add('text-green-600');
    else status.classList.add('text-slate-500');
  }

  function setAutoSpinner(active, message){
    const spinner = el('autoSpinner');
    const text = el('autoSpinnerText');
    if (!spinner) return;
    spinner.classList.toggle('hidden', !active);
    if (text && message) text.textContent = message;
  }

  function setBrandAssetsSpinner(active, message){
    const spinner = el('brandAssetsSpinner');
    const text = el('brandAssetsSpinnerText');
    if (!spinner) return;
    spinner.classList.toggle('hidden', !active);
    if (text && message) text.textContent = message;
  }

  function setBrandAssetsStatus(message, tone){
    const status = el('brandAssetsStatus');
    if (!status) return;
    status.textContent = message || '';
    status.classList.remove('text-slate-500', 'text-red-600', 'text-green-600');
    if (tone === 'error') status.classList.add('text-red-600');
    else if (tone === 'success') status.classList.add('text-green-600');
    else status.classList.add('text-slate-500');
  }

  function setBrandAssetsButtonDisabled(disabled){
    const btn = el('brandAssetsBtn');
    if (!btn) return;
    btn.disabled = !!disabled;
    btn.classList.toggle('opacity-70', !!disabled);
    btn.classList.toggle('cursor-not-allowed', !!disabled);
  }

  function isSvgUrl(url){
    if (!url) return false;
    const lower = url.toLowerCase();
    return lower.startsWith('data:image/svg+xml') || lower.includes('.svg');
  }

  function svgTextToDataUrl(svgText){
    try {
      const encoded = btoa(unescape(encodeURIComponent(svgText)));
      return `data:image/svg+xml;base64,${encoded}`;
    } catch {
      return `data:image/svg+xml,${encodeURIComponent(svgText)}`;
    }
  }

  function decodeDataUrl(dataUrl){
    const parts = dataUrl.split(',');
    if (parts.length < 2) return null;
    const meta = parts[0];
    const data = parts.slice(1).join(',');
    const isBase64 = meta.includes(';base64');
    const mime = (meta.split(':')[1] || '').split(';')[0] || 'application/octet-stream';
    return { data, isBase64, mime };
  }

  async function fetchSvgText(url){
    if (!url) return null;
    if (url.startsWith('data:')) {
      const decoded = decodeDataUrl(url);
      if (!decoded || !decoded.mime.includes('svg')) return null;
      if (decoded.isBase64) {
        try {
          return atob(decoded.data);
        } catch {
          return null;
        }
      }
      try {
        return decodeURIComponent(decoded.data);
      } catch {
        return null;
      }
    }
    const base = getBASE();
    const href = `${base}/api/brand-assets/download?url=${encodeURIComponent(url)}`;
    try {
      const res = await fetch(href, { credentials: 'include' });
      if (!res.ok) return null;
      const ct = (res.headers.get('content-type') || '').toLowerCase();
      const text = await res.text();
      if (ct.includes('image/svg+xml') || text.trim().startsWith('<svg')) {
        return text;
      }
    } catch {}
    return null;
  }

  function invertSvgColors(svgText){
    if (!svgText) return null;
    const placeholders = {
      white: '__STONLY_WHITE__',
      black: '__STONLY_BLACK__',
    };
    let text = svgText;
    text = text.replace(/#ffffff/gi, placeholders.white);
    text = text.replace(/#fff\b/gi, placeholders.white);
    text = text.replace(/rgb\s*\(\s*255\s*,\s*255\s*,\s*255\s*\)/gi, placeholders.white);
    text = text.replace(/\bwhite\b/gi, placeholders.white);

    text = text.replace(/#000000/gi, placeholders.black);
    text = text.replace(/#000\b/gi, placeholders.black);
    text = text.replace(/rgb\s*\(\s*0\s*,\s*0\s*,\s*0\s*\)/gi, placeholders.black);
    text = text.replace(/\bblack\b/gi, placeholders.black);
    text = text.replace(/currentcolor/gi, placeholders.black);

    text = text.replace(new RegExp(placeholders.white, 'g'), '#000000');
    text = text.replace(new RegExp(placeholders.black, 'g'), '#FFFFFF');
    return text;
  }

  function downloadSvgText(svgText, filename){
    if (!svgText) return;
    const blob = new Blob([svgText], { type: 'image/svg+xml' });
    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = filename || 'logo-inverted.svg';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(objectUrl);
  }

  async function downloadLogoAsset(url){
    if (!url) return;
    const base = getBASE();
    try {
      if (url.startsWith('data:')) {
        const parts = url.split(',');
        if (parts.length < 2) throw new Error('Invalid data URL');
        const meta = parts[0];
        const data = parts.slice(1).join(',');
        const isBase64 = meta.includes(';base64');
        const mime = (meta.split(':')[1] || '').split(';')[0] || 'image/svg+xml';
        let bytes;
        if (isBase64) {
          const bin = atob(data);
          bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i += 1) {
            bytes[i] = bin.charCodeAt(i);
          }
        } else {
          const decoded = decodeURIComponent(data);
          bytes = new TextEncoder().encode(decoded);
        }
        const blob = new Blob([bytes], { type: mime });
        const objectUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = objectUrl;
        a.download = mime.includes('svg') ? 'logo.svg' : 'logo';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(objectUrl);
        return;
      }
      const href = `${base}/api/brand-assets/download?url=${encodeURIComponent(url)}`;
      const res = await fetch(href, { credentials: 'include' });
      if (!res.ok) {
        throw new Error(`Download failed (${res.status})`);
      }
      const blob = await res.blob();
      const disposition = res.headers.get('content-disposition') || '';
      const match = disposition.match(/filename=\"?([^\";]+)\"?/i);
      let filename = match && match[1] ? match[1] : '';
      if (!filename) {
        try {
          const parsed = new URL(url);
          filename = parsed.pathname.split('/').pop() || 'logo';
        } catch {
          filename = 'logo';
        }
      }
      const objectUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objectUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(objectUrl);
    } catch (e) {
      setBrandAssetsStatus(e?.message || 'Logo download failed.', 'error');
    }
  }

  function setBrandWebsiteText(url){
    const target = el('brandWebsite');
    if (!target) return;
    if (!url) {
      target.textContent = '';
      return;
    }
    target.innerHTML = '';
    const label = document.createElement('span');
    label.textContent = 'Using website: ';
    const link = document.createElement('a');
    link.href = url;
    link.textContent = url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.className = 'underline';
    target.appendChild(label);
    target.appendChild(link);
  }

  function renderLogoCards(urls){
    const container = el('brandLogos');
    if (!container) return;
    container.innerHTML = '';
    if (!urls || !urls.length) {
      const msg = document.createElement('p');
      msg.className = 'text-sm text-slate-500';
      msg.textContent = 'No logos found.';
      container.appendChild(msg);
      return;
    }
    urls.forEach((url) => {
      let currentUrl = url;
      const card = document.createElement('div');
      card.className = 'border rounded-lg p-3 bg-card space-y-2';
      const wrap = document.createElement('div');
      wrap.className = 'space-y-2';
      const imgWrap = document.createElement('div');
      imgWrap.className = 'h-24 flex items-center justify-center bg-slate-100/80 rounded overflow-hidden';
      const link = document.createElement('a');
      link.href = `/api/brand-assets/download?url=${encodeURIComponent(currentUrl)}`;
      link.dataset.logoUrl = currentUrl;
      link.setAttribute('rel', 'noopener noreferrer');
      link.title = 'Download logo';
      link.className = 'flex items-center justify-center w-full h-full';
      link.addEventListener('click', (event) => {
        event.preventDefault();
        const targetUrl = link.dataset.logoUrl || currentUrl;
        downloadLogoAsset(targetUrl);
      });
      const img = document.createElement('img');
      img.src = currentUrl;
      img.alt = 'Logo candidate';
      img.className = 'max-h-full max-w-full object-contain';
      img.loading = 'lazy';
      link.appendChild(img);
      imgWrap.appendChild(link);
      card.appendChild(imgWrap);
      wrap.appendChild(card);
      if (isSvgUrl(url)) {
        const actions = document.createElement('div');
        actions.className = 'flex items-center justify-center';
        const invertBtn = document.createElement('button');
        invertBtn.type = 'button';
        invertBtn.className = 'text-xs px-3 py-1 rounded-md border bg-card hover:bg-slate-50 transition';
        invertBtn.textContent = 'Invert colors';
        let originalSvgText = null;
        let invertedUrl = null;
        let inverted = false;
        invertBtn.addEventListener('click', async (event) => {
          event.preventDefault();
          invertBtn.disabled = true;
          invertBtn.classList.add('opacity-70', 'cursor-not-allowed');
          try {
            if (!originalSvgText) {
              originalSvgText = await fetchSvgText(currentUrl);
            }
            if (!originalSvgText) {
              setBrandAssetsStatus('Unable to load SVG for inversion.', 'error');
              return;
            }
            if (!invertedUrl) {
              const invertedText = invertSvgColors(originalSvgText);
              if (!invertedText) {
                setBrandAssetsStatus('Unable to invert SVG colors.', 'error');
                return;
              }
              invertedUrl = svgTextToDataUrl(invertedText);
            }
            if (!invertedUrl) {
              setBrandAssetsStatus('Unable to invert SVG colors.', 'error');
              return;
            }
            inverted = !inverted;
            const nextUrl = inverted ? invertedUrl : url;
            currentUrl = nextUrl;
            img.src = nextUrl;
            link.dataset.logoUrl = nextUrl;
            invertBtn.textContent = inverted ? 'Show original' : 'Invert colors';
          } finally {
            invertBtn.disabled = false;
            invertBtn.classList.remove('opacity-70', 'cursor-not-allowed');
          }
        });
        actions.appendChild(invertBtn);
        wrap.appendChild(actions);
      }
      container.appendChild(wrap);
    });
  }

  function renderColorCards(colors, opts = {}){
    const containerId = opts.containerId || 'brandColorsAi';
    const emptyMessage = opts.emptyMessage || 'No colors generated.';
    const container = el(containerId);
    if (!container) return;
    container.innerHTML = '';
    if (!colors) {
      const msg = document.createElement('p');
      msg.className = 'text-sm text-slate-500';
      msg.textContent = emptyMessage;
      container.appendChild(msg);
      return;
    }
    let entries = [];
    if (Array.isArray(colors)) {
      entries = colors.map((value, idx) => ({
        label: `Color ${idx + 1}`,
        value,
      }));
    } else if (colors && typeof colors === 'object') {
      entries = [
        { key: 'highlightColor', label: 'Highlight color', value: colors.highlightColor },
        { key: 'iconColor', label: 'Icon color', value: colors.iconColor },
        { key: 'headerBackground', label: 'Header background', value: colors.headerBackground },
      ].filter((entry) => entry.value);
    }
    if (!entries.length) {
      const msg = document.createElement('p');
      msg.className = 'text-sm text-slate-500';
      msg.textContent = emptyMessage;
      container.appendChild(msg);
      return;
    }
    entries.forEach(({ label, value }) => {
      const card = document.createElement('div');
      card.className = 'border rounded-lg p-3 bg-card space-y-2 cursor-pointer';
      card.title = 'Click to copy hex';
      const swatch = document.createElement('div');
      swatch.className = 'h-10 rounded';
      swatch.style.background = value;
      const meta = document.createElement('div');
      meta.className = 'text-xs text-slate-500';
      meta.textContent = `${label} · ${value}`;
      card.addEventListener('click', async () => {
        const stripped = String(value).replace('#', '');
        let copied = false;
        try {
          if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(stripped);
            copied = true;
          }
        } catch {}
        if (copied) {
          const original = meta.textContent;
          meta.textContent = `${label} · ${value} (copied)`;
          card.classList.add('ring-2', 'ring-green-400');
          setTimeout(() => {
            meta.textContent = original || `${label} · ${value}`;
            card.classList.remove('ring-2', 'ring-green-400');
          }, 1200);
        }
      });
      card.appendChild(swatch);
      card.appendChild(meta);
      container.appendChild(card);
    });
  }

  function setSettingsLocked(locked){
    const section = el('expertSettingsSection');
    if (section) {
      section.classList.toggle('opacity-60', locked);
      section.classList.toggle('cursor-not-allowed', locked);
      section.classList.toggle('pointer-events-none', locked);
    }
    const ids = ['teamSelect', 'parentId', 'publicAccess', 'lang'];
    ids.forEach((id) => {
      const field = el(id);
      if (!field) return;
      if (locked) {
        field.setAttribute('disabled', 'disabled');
        field.classList.add('prompt-locked', 'cursor-not-allowed');
      } else {
        field.removeAttribute('disabled');
        field.classList.remove('prompt-locked', 'cursor-not-allowed');
      }
    });
  }

  function clearAutoOutput(){
    const out = el('autoOut');
    if (out) out.textContent = '';
  }

  function appendAutoLog(line, extra){
    const out = el('autoOut');
    if (!out) return;
    const current = (out.textContent || '').trimEnd();
    const lines = current ? [current] : [];
    if (line) lines.push(line);
    if (extra != null) {
      if (typeof extra === 'string') lines.push(extra);
      else lines.push(JSON.stringify(extra, null, 2));
    }
    out.textContent = lines.join('\n');
    try { out.scrollTop = out.scrollHeight; } catch {}
  }

  function setAutoRunDisabled(disabled){
    const btn = el('autoRunBtn');
    if (!btn) return;
    btn.disabled = !!disabled;
    btn.classList.toggle('opacity-70', !!disabled);
    btn.classList.toggle('cursor-not-allowed', !!disabled);
  }

  function buildKbPrompt(brand, instructions){
    const name = (brand || '').trim();
    const details = (instructions || '').trim();
    const intro = name ? `Based on these detailed notes, can you create a KB structure for ${name}?` : 'Based on these detailed notes, can you create a KB structure?';
    return `${intro} ${details}`.trim();
  }

  function buildGuidePrompt(brand, instructions, kbYaml){
    const name = (brand || '').trim();
    const details = (instructions || '').trim();
    const kbBlock = (kbYaml || '').trim();
    const focusLine = name
      ? `Can you focus on the guide/article building piece for ${name}?`
      : 'Can you focus on the guide/article building piece?';
    return [
      'Based on these detailed notes, and knowing the KB has already been built and looks like this:',
      kbBlock,
      '',
      `${focusLine} ${details}`.trim(),
    ].join('\n').trim();
  }

  function buildOrganiserInput(mappingPayload, guideSummary){
    const mappingText = typeof mappingPayload === 'string'
      ? mappingPayload.trim()
      : JSON.stringify(mappingPayload, null, 2);
    const guideText = (guideSummary || '').trim();
    return `${mappingText}\n\n${guideText}`.trim();
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
    const t = cleanGuideYamlInput(true);
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
    const guideText = fixPreBlockIndentation(cleanGeminiYaml((guideYaml || '').trim()));
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

  async function onAutomatedRun(){
    if (!(window.validateRequired && window.validateRequired(['teamSelect', 'parentId', 'autoBrand', 'autoPrompt']))) {
      setAutoStatus('Please fill all required fields (*).', 'error');
      return;
    }
    const brand = (el('autoBrand')?.value || '').trim();
    const instructions = (el('autoPrompt')?.value || '').trim();
    const c = collectCommon();
    if (!c.teamId || !c.parentId) {
      setAutoStatus('Missing team or parent folder settings.', 'error');
      return;
    }

    clearAutoOutput();
    setAutoStatus('Starting automation...', 'info');
    appendAutoLog('Starting automation.');
    setAutoRunDisabled(true);
    setAutoSpinner(true, 'Generating KB YAML...');
    setSettingsLocked(true);

    try {
      appendAutoLog('1/5 Generating KB YAML...');
      const kbPrompt = buildKbPrompt(brand, instructions);
      const kbResp = await apiFetch('/api/ai-kb/generate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ prompt: kbPrompt }),
      });
      const kbYamlRaw = normalizeAiYaml(kbResp?.yaml || '');
      if (!kbYamlRaw) throw new Error('KB gem returned empty YAML.');
      if (el('kbYaml')) {
        el('kbYaml').value = kbYamlRaw;
        try { el('kbYaml').dispatchEvent(new Event('input', { bubbles: true })); } catch {}
      }

      let kbRoot;
      try { kbRoot = parseKBYaml(kbYamlRaw); }
      catch (e) { throw new Error(e?.message || 'Invalid KB YAML.'); }
      appendAutoLog(`KB YAML generated (${kbRoot.length} top-level folders).`);

      setAutoSpinner(true, 'Creating KB in Stonly...');
      appendAutoLog('2/5 Creating KB in Stonly...');
      const kbApplyBody = {
        parentId: c.parentId,
        creds: { user: c.user, teamId: c.teamId, base: c.base },
        settings: { publicAccess: c.publicAccess, language: c.language },
        dryRun: false,
        root: kbRoot,
      };
      const kbApplyResp = await apiFetch('/api/apply', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(kbApplyBody),
      });
      const mapping = kbApplyResp?.mapping;
      if (!mapping || typeof mapping !== 'object') {
        throw new Error('KB creation response missing mapping.');
      }
      setOut('kbOut', kbApplyResp);
      appendAutoLog(`KB created (${Object.keys(mapping).length} folders mapped).`);

      setAutoSpinner(true, 'Generating Guides YAML...');
      appendAutoLog('3/5 Generating Guides YAML...');
      const guidePrompt = buildGuidePrompt(brand, instructions, kbYamlRaw);
      const guideResp = await apiFetch('/api/ai-guides/build', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          prompt: guidePrompt,
          teamId: c.teamId,
          folderId: c.parentId,
          publish: false,
          previewOnly: true,
          base: c.base,
        }),
      });
      const guideYamlRaw = normalizeAiYaml(guideResp?.yaml || '');
      if (!guideYamlRaw) throw new Error('Guide gem returned empty YAML.');
      if (el('guideYaml')) {
        el('guideYaml').value = guideYamlRaw;
        try { el('guideYaml').dispatchEvent(new Event('input', { bubbles: true })); } catch {}
      }
      const parsedGuides = parseGuideYamlWithFixes(guideYamlRaw);
      const guideSummary = buildGuideSummaryYaml(parsedGuides.docs);
      if (!guideSummary) throw new Error('Failed to build Guide YAML summary.');
      appendAutoLog(`Guides YAML generated (${parsedGuides.docs.length} guides).`);

      setAutoSpinner(true, 'Generating organiser mapping...');
      appendAutoLog('4/5 Generating organiser mapping...');
      const organiserInput = buildOrganiserInput({ ok: true, mapping }, guideSummary);
      const organiserResp = await apiFetch('/api/ai-organiser/generate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ prompt: organiserInput }),
      });
      const organiserYamlRaw = normalizeAiYaml(organiserResp?.yaml || '');
      if (!organiserYamlRaw) throw new Error('Organiser gem returned empty YAML.');
      if (el('organiserYaml')) {
        el('organiserYaml').value = organiserYamlRaw;
        try { el('organiserYaml').dispatchEvent(new Event('input', { bubbles: true })); } catch {}
      }
      appendAutoLog('Organiser mapping generated.');

      setAutoSpinner(true, 'Building & publishing guides...');
      appendAutoLog('5/5 Building & publishing guides...');
      let finalYaml;
      try {
        finalYaml = applyOrganiserMapping(parsedGuides.yamlText, organiserYamlRaw);
      } catch (e) {
        throw new Error(e?.message || 'Failed to apply organiser mapping.');
      }
      const publish = el('guidePublish') ? !!el('guidePublish').checked : true;
      const buildResp = await apiFetch('/api/guides/build', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          dryRun: false,
          folderId: c.parentId,
          yaml: finalYaml,
          defaults: { language: c.language },
          publish,
          creds: { user: c.user, teamId: c.teamId, base: c.base },
        }),
      });
      setOut('guideOut', buildResp);
      const summary = buildResp?.summary;
      const results = Array.isArray(buildResp?.results) ? buildResp.results : null;
      let count = summary && typeof summary.count === 'number' ? summary.count : null;
      let succeeded = summary && typeof summary.succeeded === 'number' ? summary.succeeded : null;
      let failed = summary && typeof summary.failed === 'number' ? summary.failed : null;

      if (count == null && results) count = results.length;
      if (succeeded == null && results) succeeded = results.filter((r) => r && r.ok).length;
      if (failed == null && results) failed = results.filter((r) => r && r.ok === false).length;

      if (count == null && (buildResp?.guideId || buildResp?.firstStepId)) {
        count = 1;
        succeeded = 1;
        failed = 0;
      }

      if (count != null && succeeded != null && failed != null) {
        appendAutoLog(`Guides built: ${succeeded}/${count} (failed: ${failed}).`);
      } else {
        appendAutoLog('Guides build completed.');
      }
      setAutoStatus('Automation complete.', 'success');
      setAutoSpinner(false);
    } catch (e) {
      const msg = e?.message || 'Automation failed.';
      setAutoStatus(msg, 'error');
      appendAutoLog(`Error: ${msg}`);
    } finally {
      setAutoRunDisabled(false);
      setAutoSpinner(false);
      setSettingsLocked(false);
    }
  }

  async function onBrandAssetsRun(){
    const brandName = (el('autoBrand')?.value || '').trim();
    if (!brandName) {
      setBrandAssetsStatus('Please enter a brand name first.', 'error');
      return;
    }
    setBrandAssetsStatus('Starting...', 'info');
    setBrandAssetsSpinner(true, 'Resolving website...');
    setBrandAssetsButtonDisabled(true);
    renderLogoCards([]);
    renderColorCards(null, { containerId: 'brandColorsAi', emptyMessage: 'No AI colors generated.' });
    renderColorCards(null, { containerId: 'brandColorsSite', emptyMessage: 'No website colors found.' });
    setBrandWebsiteText('');

    try {
      let url = (el('brandUrl')?.value || '').trim();
      if (!url) {
        const websiteResp = await apiFetch('/api/ai-brand-website', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ brandName }),
        });
        url = (websiteResp?.url || '').trim();
        if (!url) throw new Error('Could not infer website URL.');
        if (el('brandUrl')) el('brandUrl').value = url;
      }
      setBrandWebsiteText(url);

      setBrandAssetsSpinner(true, 'Finding logo candidates...');
      const logoResp = await apiFetch('/api/brand-assets/scrape', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const logos = Array.isArray(logoResp?.logos) ? logoResp.logos.slice(0, 3) : [];
      renderLogoCards(logos);
      renderColorCards(logoResp?.siteColors, { containerId: 'brandColorsSite', emptyMessage: 'No website colors found.' });

      setBrandAssetsSpinner(true, 'Generating colors...');
      const colorsResp = await apiFetch('/api/ai-brand-colors', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ brandName, url }),
      });
      renderColorCards(colorsResp?.colors || null, { containerId: 'brandColorsAi', emptyMessage: 'No AI colors generated.' });
      setBrandAssetsStatus('Brand assets ready.', 'success');
    } catch (e) {
      const msg = e?.message || 'Failed to load brand assets.';
      setBrandAssetsStatus(msg, 'error');
    } finally {
      setBrandAssetsSpinner(false);
      setBrandAssetsButtonDisabled(false);
    }
  }

  async function onGuideRun(){
    if (!(window.validateRequired && window.validateRequired(['teamSelect','parentId']))) {
      setOut('guideOut', 'Please fill all required fields (*).');
      return;
    }
    const yamlText = fixPreBlockIndentation(cleanGeminiYaml((el('guideYaml')?.value || '').trim()));
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
    el('autoRunBtn')?.addEventListener('click', onAutomatedRun);
    el('brandAssetsBtn')?.addEventListener('click', onBrandAssetsRun);
    el('btnFetchLogs')?.addEventListener('click', fetchLogs);
    el('btnClearLogs')?.addEventListener('click', clearLogs);
    el('expertModeManual')?.addEventListener('click', () => setExpertMode('manual'));
    el('expertModeAuto')?.addEventListener('click', () => setExpertMode('automated'));

    // Copy buttons
    try {
      if (typeof window.attachCopyButton === 'function') {
        window.attachCopyButton({ buttonId: 'copyKbOut', sourceId: 'kbOut', disableWhenEmpty: true });
        window.attachCopyButton({ buttonId: 'copyGuideOut', sourceId: 'guideOut', disableWhenEmpty: true });
        window.attachCopyButton({ buttonId: 'autoCopyOut', sourceId: 'autoOut', disableWhenEmpty: true });
      }
    } catch {}

    try {
      const storedMode = (localStorage.getItem(MODE_STORAGE_KEY) || 'manual').toLowerCase();
      setExpertMode(storedMode === 'automated' ? 'automated' : 'manual');
    } catch {
      setExpertMode('manual');
    }

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

    try {
      const autoFields = [
        { id: 'autoBrand', key: AUTO_BRAND_KEY },
        { id: 'autoPrompt', key: AUTO_PROMPT_KEY },
      ];
      autoFields.forEach(({ id, key }) => {
        const field = el(id);
        if (!field) return;
        try {
          const stored = localStorage.getItem(key);
          if (typeof stored === 'string' && stored.length && !field.value) {
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
