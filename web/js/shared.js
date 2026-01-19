// shared.js — common code used by both KB and Guide builders
// - Dark mode init + toggle
// - Stonly widget bootstrap
// - Shared persistence for Stonly creds (user, team, folder)

(function () {
  // Small DOM-ready helper (scoped)
  function onReady(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn, { once: true });
    } else {
      try { fn(); } catch (_) {}
    }
  }
  // Expose on window so app scripts can reuse
  window.onReady = onReady;

  // 1) Stonly widget bootstrap (id is shared across pages)
  onReady(function initStonlyWidget() {
    try {
      if (!window.STONLY_WID) {
        window.STONLY_WID = "8fcc56d8-0450-11ee-a0af-0a52ff1ec764";
      }
      if (window.StonlyWidget) return; // already present
      (function (s, t, o, n, l, y, w, g, d, e) {
        s.StonlyWidget || ((d = s.StonlyWidget = function () {
          d._api ? d._api.apply(d, arguments) : d.queue.push(arguments)
        }).scriptPath = n, d.apiPath = l, d.sPath = y, d.queue = [],
          (g = t.createElement(o)).async = !0, (e = new XMLHttpRequest).open("GET", n + "version?v=" + Date.now(), !0),
          e.onreadystatechange = function () {
            if (4 === e.readyState) {
              g.src = n + "stonly-widget.js?v=" + (200 === e.status ? e.responseText : Date.now());
              (w = t.getElementsByTagName(o)[0]).parentNode.insertBefore(g, w);
            }
          }, e.send())
      })(window, document, "script", "https://stonly.com/js/widget/v2/");
    } catch (_) { /* no-op */ }
  });

  // 2) Dark mode init + toggle (shared)
  onReady(function initTheme() {
    try {
      const STORAGE_KEY = "stonly_theme";
      const root = document.documentElement;
      const saved = localStorage.getItem(STORAGE_KEY);
      const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
      const current = saved || (prefersDark ? "dark" : "light");
      root.setAttribute("data-theme", current);
      updateToggleUI(current);

      const toggle = document.getElementById("themeToggle");
      if (toggle) {
        toggle.addEventListener("click", () => {
          const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
          root.setAttribute("data-theme", next);
          try { localStorage.setItem(STORAGE_KEY, next); } catch {}
          updateToggleUI(next);
        });
      }

      function updateToggleUI(mode) {
        const icon = document.getElementById("themeIcon");
        const label = document.getElementById("themeLabel");
        if (!icon || !label) return;
        if (mode === "dark") {
          icon.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
          label.textContent = "Light";
        } else {
          icon.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M6.76 4.84 5.34 3.42 3.92 4.84l1.42 1.42L6.76 4.84zM1 13h3v-2H1v2zm10 10h2v-3h-2v3zm7.66-2.58 1.42-1.42-1.42-1.42-1.42 1.42 1.42 1.42zM20 13h3v-2h-3v2zM11 1h2v3h-2V1zM4.84 17.24 3.42 18.66l1.42 1.42 1.42-1.42-1.42-1.42zM17.24 4.84l1.42-1.42 1.42 1.42-1.42 1.42-1.42-1.42zM12 6a6 6 0 1 0 0 12 6 6 0 0 0 0-12z"/></svg>';
          label.textContent = "Dark";
        }
      }
    } catch (_) { /* no-op */ }
  });

  // 3) Shared required-field highlighter
  window.validateRequired = function validateRequired(ids) {
    let ok = true;
    const invalidEls = [];
    (ids || []).forEach(id => {
      const el = document.getElementById(id);
      const val = (el && typeof el.value === 'string') ? el.value.trim() : '';
      const empty = !el || !val;
      if (el) {
        el.classList.toggle('ring-2', empty);
        el.classList.toggle('ring-red-500', empty);
        el.setAttribute('aria-invalid', empty ? 'true' : 'false');
      }
      if (el && el.dataset.proxy) {
        const proxy = document.getElementById(el.dataset.proxy);
        if (proxy) {
          proxy.classList.toggle('ring-2', empty);
          proxy.classList.toggle('ring-red-500', empty);
          proxy.setAttribute('aria-invalid', empty ? 'true' : 'false');
        }
      }
      if (empty) { ok = false; if (el) invalidEls.push(el); }
    });
    if (!ok) {
      try {
        // Focus the first invalid field (without scrolling to it), then scroll page to top
        const first = invalidEls[0];
        if (first && typeof first.focus === 'function') {
          try { first.focus({ preventScroll: true }); } catch { first.focus(); }
        }
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } catch { /* no-op */ }
    }
    return ok;
  };

  // 3) Shared persistence for team selection + folder IDs between apps
  onReady(function initSharedPersistence() {
    const groups = [
      { key: 'st_selected_team', ids: ['teamSelect'] },
      { key: 'st_shared_folder', ids: ['parentId', 'folderId'] },
      { key: 'st_shared_user', ids: ['st_user', 'user'] },
    ];

    groups.forEach(({ key, ids }) => {
      try {
        const v = localStorage.getItem(key);
        ids.forEach(id => {
          const el = document.getElementById(id);
          if (!el) return;
          if (typeof el.value === 'string' && v && !el.value) el.value = v;
          el.addEventListener('input', () => {
            try { localStorage.setItem(key, (el.value || '').trim()); } catch {}
          });
        });
      } catch (_) { /* ignore */ }
    });
  });

  // 4) Shared API base settings (account-level)
  const API_BASE_KEY = 'st_api_base';
  const DEFAULT_API_BASE = 'https://public.stonly.com/api/v3';

  window.getApiBase = function getApiBase() {
    try {
      const saved = localStorage.getItem(API_BASE_KEY);
      if (saved) return saved;
    } catch {}
    const base = (window.__apiBase || '').trim();
    return base || DEFAULT_API_BASE;
  };

  onReady(function initApiBaseSetting() {
    try {
      const saved = localStorage.getItem(API_BASE_KEY);
      if (saved) window.__apiBase = saved;
    } catch {}

    const base = (window.BASE || window.DEFAULT_BACKEND || '').replace(/\/+$/, '');
    if (!base) return;
    fetch(base + '/api/settings', { credentials: 'include' })
      .then((res) => {
        if (!res.ok) return null;
        return res.json();
      })
      .then((data) => {
        if (!data) return;
        const apiBase = (data.apiBase || '').trim();
        window.__apiBase = apiBase;
        try {
          if (apiBase) localStorage.setItem(API_BASE_KEY, apiBase);
          else localStorage.removeItem(API_BASE_KEY);
        } catch {}
      })
      .catch(() => {});
  });

  // 5) Shared guide preview renderer (AI Builder + Guide Builder)
  window.summarizeGuidePreviewContent = function summarizeGuidePreviewContent(html, maxLen = 160) {
    if (!html) return "";
    const tmp = document.createElement("div");
    let normalized = String(html);
    // Ensure paragraph boundaries contribute visible spacing in summaries.
    normalized = normalized.replace(/<\s*p\b[^>]*>/gi, "<p> ");
    // Add missing spaces around tags when content normalization removed them.
    normalized = normalized
      .replace(/([A-Za-z0-9])(<[a-z][^>]*>)/gi, "$1 $2")
      .replace(/(<\/[^>]+>)([A-Za-z0-9])/gi, "$1 $2");
    tmp.innerHTML = normalized;
    const text = (tmp.textContent || "").replace(/\s+/g, " ").trim();
    if (!text) return "";
    return text.length > maxLen ? text.slice(0, maxLen) + "…" : text;
  };

  window.createGuidePreviewTree = function createGuidePreviewTree(step, depth, options) {
    const summarize = options && typeof options.summarize === "function"
      ? options.summarize
      : window.summarizeGuidePreviewContent;
    const container = document.createElement("div");
    container.className = depth
      ? "guide-preview-step border-l pl-4 space-y-2"
      : "guide-preview-step space-y-2";

    const heading = document.createElement("div");
    heading.className = "space-y-1";
    const titleEl = document.createElement("div");
    titleEl.className = "guide-preview-step-title font-medium";
    const titleText = document.createElement("span");
    titleText.textContent = step?.title || "(Untitled step)";
    titleEl.appendChild(titleText);
    if (step?.key) {
      const keyBadge = document.createElement("span");
      keyBadge.className = "guide-preview-step-key";
      keyBadge.textContent = `Key → ${step.key}`;
      titleEl.appendChild(keyBadge);
    }
    heading.appendChild(titleEl);

    const summary = summarize ? summarize(step?.content) : "";
    if (summary) {
      const summaryEl = document.createElement("div");
      summaryEl.className = "guide-preview-summary text-xs";
      summaryEl.textContent = summary;
      heading.appendChild(summaryEl);
    }
    container.appendChild(heading);

    const choices = Array.isArray(step?.choices) ? step.choices : [];
    if (choices.length) {
      const choiceList = document.createElement("div");
      choiceList.className = "space-y-2";
      choices.forEach((choice) => {
        const wrap = document.createElement("div");
        wrap.className = "guide-preview-choice space-y-1";
        const label = document.createElement("div");
        label.className = "guide-preview-choice-label text-sm font-semibold";
        label.textContent = choice?.label ? `Choice: ${choice.label}` : "Choice";
        wrap.appendChild(label);
        if (choice?.step) {
          wrap.appendChild(window.createGuidePreviewTree(choice.step, depth + 1, options));
        } else if (choice?.ref) {
          const refEl = document.createElement("div");
          refEl.className = "guide-preview-choice-ref text-xs";
          refEl.textContent = `Ref → ${choice.ref}`;
          wrap.appendChild(refEl);
        }
        choiceList.appendChild(wrap);
      });
      container.appendChild(choiceList);
    }
    return container;
  };

  window.createGuidePreviewCard = function createGuidePreviewCard(guide, index, options) {
    const getTitle = options && typeof options.getTitle === "function"
      ? options.getTitle
      : (g) => g?.contentTitle || g?.info?.contentTitle || g?.firstStep?.title || "(Untitled guide)";
    const getContentType = options && typeof options.getContentType === "function"
      ? options.getContentType
      : (g) => g?.contentType || g?.info?.contentType || "GUIDE";
    const label = options && options.label ? String(options.label) : "Guide";
    const card = document.createElement("div");
    card.className = "guide-preview-card border rounded-lg p-4 space-y-3";
    const header = document.createElement("div");
    header.className = "space-y-1";
    const meta = document.createElement("div");
    meta.className = "guide-preview-meta text-xs font-semibold uppercase";
    meta.textContent = `${label} ${index}`;
    const title = document.createElement("div");
    title.className = "guide-preview-title text-base font-semibold";
    const contentTitle = String(getTitle(guide) || "").trim() || "(Untitled guide)";
    const rawCt = getContentType(guide);
    const ct = rawCt ? String(rawCt).toUpperCase() : "GUIDE";
    title.textContent = `${contentTitle} · ${ct}`;
    header.appendChild(meta);
    header.appendChild(title);
    card.appendChild(header);
    if (guide?.firstStep) {
      card.appendChild(window.createGuidePreviewTree(guide.firstStep, 0, options));
    } else {
      const empty = document.createElement("p");
      empty.className = "guide-preview-empty text-sm";
      empty.textContent = "Missing first step.";
      card.appendChild(empty);
    }
    return card;
  };

  // (Guide YAML persistence lives in guide.js)
})();

// Dev-only: persist sensitive tokens locally when running on localhost
(function devTokenPersistence(){
  try {
    const isLocal = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|.*\.local)$/i.test(window.location.hostname);
    if (!isLocal) return; // never persist tokens on non-local hosts

    const pairs = [
      { id: 'signupAdminToken', key: 'dev_admin_token' }, // Admin token (signup only)
      { id: 'teamModalToken', key: 'dev_team_token' },    // Team token (local only)
    ];

    pairs.forEach(({ id, key }) => {
      const el = document.getElementById(id);
      if (!el) return;
      try {
        const v = localStorage.getItem(key);
        if (typeof el.value === 'string' && v && !el.value) el.value = v;
      } catch {}
      el.addEventListener('input', () => {
        try { localStorage.setItem(key, (el.value || '').trim()); } catch {}
      });
    });
  } catch {}
})();
  // 4) Generic copy-to-clipboard helper that pages can use
  window.attachCopyButton = function attachCopyButton(opts) {
    const {
      buttonId,
      sourceId,
      labels = { copied: 'Copied', failed: 'Copy failed', empty: 'Nothing to copy' },
      flashClasses = { success: 'bg-green-100', fail: 'bg-red-100' },
      disableWhenEmpty = false,
    } = opts || {};
    const btn = document.getElementById(buttonId);
    const src = document.getElementById(sourceId);
    if (!btn || !src) return;

    const original = btn.innerHTML;
    const setFlash = (ok, msg) => {
      if (msg) btn.textContent = msg;
      else btn.textContent = ok ? labels.copied : labels.failed;
      if (flashClasses.success || flashClasses.fail) {
        btn.classList.toggle(flashClasses.success, !!ok);
        btn.classList.toggle(flashClasses.fail, !ok);
      }
      setTimeout(() => {
        btn.innerHTML = original;
        if (flashClasses.success) btn.classList.remove(flashClasses.success);
        if (flashClasses.fail) btn.classList.remove(flashClasses.fail);
      }, 1200);
    };

    btn.addEventListener('click', async () => {
      const text = (src.innerText || src.textContent || '').trim();
      if (!text) { setFlash(false, labels.empty); return; }
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(text);
        } else {
          const ta = document.createElement('textarea');
          ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
          document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
        }
        setFlash(true);
      } catch {
        setFlash(false);
      }
    });

    if (disableWhenEmpty) {
      const updateDisabled = () => { btn.disabled = !((src.textContent || '').trim()); };
      updateDisabled();
      const mo = new MutationObserver(updateDisabled);
      mo.observe(src, { childList: true, characterData: true, subtree: true });
    }
  };

  // 5) Shared backend BASE detection (sets window.BASE if not present)
  try {
    if (!window.BASE) {
      const isLocal = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|.*\.local)$/i.test(window.location.hostname);
      const DEFAULT_BACKEND = isLocal ? 'http://localhost:8000' : 'https://stonly-web.onrender.com';
      const base = (window.location.origin.includes('stonly-web.onrender.com')
        ? window.location.origin
        : DEFAULT_BACKEND).replace(/\/+$/, '');
      window.DEFAULT_BACKEND = DEFAULT_BACKEND;
      window.BASE = base;
    }
  } catch (_) {}

  // 6) Account-session guard for builder pages
  const AUTH_PENDING_CLASS = 'auth-check-pending';
  const AUTH_READY_CLASS = 'auth-check-ready';
  function markAuthPending() {
    const root = document.documentElement;
    if (!root) return;
    root.classList.add(AUTH_PENDING_CLASS);
    root.classList.remove(AUTH_READY_CLASS);
  }
  function markAuthReady() {
    const root = document.documentElement;
    if (!root) return;
    root.classList.remove(AUTH_PENDING_CLASS);
    root.classList.add(AUTH_READY_CLASS);
  }

  window.requireAccount = function requireAccount() {
    if (window.__authCheckPromise) {
      return window.__authCheckPromise;
    }
    markAuthPending();
    const base = (window.BASE || window.DEFAULT_BACKEND || '').replace(/\/+$/, '');
    const here = window.location.pathname + window.location.search;
    window.__authCheckPromise = (async function runAuthCheck() {
      try {
        const res = await fetch(base + '/api/auth/status', { method: 'GET', credentials: 'include' });
        if (!res.ok) throw new Error('unauthorized');
        const data = await res.json().catch(() => null);
        if (!data || data.ok !== true) throw new Error('unauthorized');
        if (data && data.email) {
          window.__authUserEmail = data.email;
        }
        markAuthReady();
      } catch (_) {
        window.location.replace('/login.html?next=' + encodeURIComponent(here || '/'));
      }
    })();
    return window.__authCheckPromise;
  };
  window.requireAdmin = window.requireAccount;

  // 7) Team selector + modal creation (shared across builder pages)
  onReady(function initTeamSelector() {
    const select = document.getElementById('teamSelect');
    const meta = document.getElementById('teamMeta');
    const base = (window.BASE || window.DEFAULT_BACKEND || '').replace(/\/+$/, '');
    let teams = [];
    let lastValidTeamId = '';
    let pendingSelectId = '';
    let customButton = null;
    let customPanel = null;
    let customLabel = null;

    function ensureCustomTeamSelect() {
      if (!select) return;
      if (select.dataset.customized === '1') {
        customButton = document.getElementById('teamSelectButton');
        customPanel = document.getElementById('teamSelectPanel');
        customLabel = customButton?.querySelector('.team-select-value') || null;
        return;
      }
      select.dataset.customized = '1';
      select.classList.add('team-select-native');

      const wrapper = document.createElement('div');
      wrapper.className = 'team-select-custom';
      select.parentNode?.insertBefore(wrapper, select);
      wrapper.appendChild(select);

      const button = document.createElement('button');
      button.type = 'button';
      button.id = 'teamSelectButton';
      button.className = 'team-select-button';
      button.setAttribute('aria-haspopup', 'listbox');
      button.setAttribute('aria-expanded', 'false');

      const label = document.createElement('span');
      label.className = 'team-select-value';
      label.textContent = 'Select a team';

      const chevron = document.createElement('span');
      chevron.className = 'team-select-chevron';
      chevron.innerHTML = '<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 0 1 1.06.02L10 11.17l3.71-3.94a.75.75 0 1 1 1.08 1.04l-4.24 4.5a.75.75 0 0 1-1.08 0l-4.24-4.5a.75.75 0 0 1 .02-1.06z" clip-rule="evenodd" /></svg>';

      button.appendChild(label);
      button.appendChild(chevron);

      const panel = document.createElement('div');
      panel.id = 'teamSelectPanel';
      panel.className = 'team-select-panel hidden';
      panel.setAttribute('role', 'listbox');

      wrapper.appendChild(button);
      wrapper.appendChild(panel);

      select.dataset.proxy = button.id;
      customButton = button;
      customPanel = panel;
      customLabel = label;

      function setOpen(isOpen) {
        panel.classList.toggle('hidden', !isOpen);
        button.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      }

      button.addEventListener('click', (e) => {
        e.preventDefault();
        setOpen(panel.classList.contains('hidden'));
      });
      button.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          setOpen(true);
          const first = panel.querySelector('.team-select-option:not([data-disabled="1"])');
          first?.focus?.();
        }
      });
      panel.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          e.preventDefault();
          setOpen(false);
          button.focus();
        }
      });
      panel.addEventListener('click', (e) => {
        const item = e.target?.closest?.('[data-value]');
        if (!item || item.dataset.disabled === '1') return;
        const value = item.dataset.value || '';
        select.value = value;
        select.dispatchEvent(new Event('change', { bubbles: true }));
        setOpen(false);
        button.focus();
      });
      document.addEventListener('click', (e) => {
        if (!panel.contains(e.target) && !button.contains(e.target)) {
          setOpen(false);
        }
      });
    }

    function ensureTeamModal() {
      let overlay = document.getElementById('teamModal');
      if (overlay) return overlay;
      overlay = document.createElement('div');
      overlay.id = 'teamModal';
      overlay.className = 'modal-overlay hidden';
      overlay.innerHTML = `
        <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="teamModalTitle">
          <div class="modal-header">
            <div>
              <h2 id="teamModalTitle" class="text-lg font-semibold">Create team</h2>
              <p id="teamModalSubtitle" class="text-sm text-slate-500">Store a team token for quick access.</p>
            </div>
            <button id="teamModalClose" type="button" class="modal-close" aria-label="Close">&times;</button>
          </div>
          <form id="teamModalForm" class="space-y-3">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label class="block text-sm font-medium">Team name <span class="text-red-600">*</span></label>
                <input id="teamModalName" type="text" class="mt-1 w-full border rounded-lg p-2 text-sm" placeholder="Acme Support" required />
              </div>
              <div>
                <label class="block text-sm font-medium">Team ID <span class="text-red-600">*</span></label>
                <input id="teamModalId" type="number" class="mt-1 w-full border rounded-lg p-2 text-sm" placeholder="12345" />
              </div>
              <div>
                <label class="block text-sm font-medium">Team token <span class="text-red-600">*</span></label>
                <input id="teamModalToken" type="password" class="mt-1 w-full border rounded-lg p-2 text-sm" placeholder="Stonly team token" autocomplete="off" />
                <p id="teamModalTokenHint" class="text-xs text-slate-500 mt-1 hidden">Leave blank to keep the current token.</p>
              </div>
              <div>
                <label class="block text-sm font-medium">Root folder</label>
                <input id="teamModalRoot" type="number" class="mt-1 w-full border rounded-lg p-2 text-sm" placeholder="Optional root folder ID" />
              </div>
            </div>
            <p id="teamModalError" class="text-sm text-red-600 min-h-[1.25rem]"></p>
            <div class="modal-actions">
              <button id="teamModalCancel" type="button" class="px-3 py-2 rounded-lg border text-sm">Cancel</button>
              <button id="teamModalSave" type="submit" class="px-3 py-2 rounded-lg bg-slate-900 text-white text-sm font-medium">Save team</button>
            </div>
          </form>
        </div>
      `;
      document.body.appendChild(overlay);
      return overlay;
    }

    const modalState = { mode: 'create', team: null, onSaved: null };

    function openTeamModal({ mode = 'create', team = null, onSaved = null } = {}) {
      const overlay = ensureTeamModal();
      const title = overlay.querySelector('#teamModalTitle');
      const subtitle = overlay.querySelector('#teamModalSubtitle');
      const error = overlay.querySelector('#teamModalError');
      const tokenHint = overlay.querySelector('#teamModalTokenHint');
      overlay.dataset.mode = mode;
      overlay.dataset.teamRowId = team?.id ? String(team.id) : '';
      modalState.mode = mode;
      modalState.team = team;
      modalState.onSaved = onSaved;

      overlay.querySelector('#teamModalId').value = team?.teamId ?? '';
      overlay.querySelector('#teamModalName').value = team?.name ?? '';
      overlay.querySelector('#teamModalRoot').value = team?.rootFolder ?? '';
      const tokenInput = overlay.querySelector('#teamModalToken');
      if (tokenInput) tokenInput.value = '';
      if (error) error.textContent = '';
      try {
        const isLocal = /^(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|.*\\.local)$/i.test(window.location.hostname);
        if (isLocal && tokenInput && !tokenInput.value) {
          const saved = localStorage.getItem('dev_team_token');
          if (saved) tokenInput.value = saved;
        }
        if (isLocal && tokenInput && !tokenInput.dataset.persistBound) {
          tokenInput.dataset.persistBound = '1';
          tokenInput.addEventListener('input', () => {
            try { localStorage.setItem('dev_team_token', (tokenInput.value || '').trim()); } catch {}
          });
        }
      } catch {}

      if (mode === 'edit') {
        if (title) title.textContent = 'Edit team';
        if (subtitle) subtitle.textContent = 'Update the stored team details.';
        if (tokenHint) tokenHint.classList.remove('hidden');
      } else {
        if (title) title.textContent = 'Create team';
        if (subtitle) subtitle.textContent = 'Store a team token for quick access.';
        if (tokenHint) tokenHint.classList.add('hidden');
      }

      overlay.classList.remove('hidden');
    }

    function closeTeamModal() {
      const overlay = document.getElementById('teamModal');
      if (!overlay) return;
      overlay.classList.add('hidden');
    }

    async function saveTeamFromModal(e) {
      if (e) e.preventDefault();
      const overlay = ensureTeamModal();
      const error = overlay.querySelector('#teamModalError');
      if (error) error.textContent = '';

      const teamId = parseInt(overlay.querySelector('#teamModalId').value || '', 10);
      const name = overlay.querySelector('#teamModalName').value.trim();
      const rootFolderRaw = overlay.querySelector('#teamModalRoot').value;
      const token = overlay.querySelector('#teamModalToken').value.trim();
      const rootFolder = parseInt(rootFolderRaw, 10);
      if (!name) {
        if (error) error.textContent = 'Team name is required.';
        return;
      }
      if (!Number.isFinite(teamId)) {
        if (error) error.textContent = 'Team ID is required.';
        return;
      }

      const payload = { teamId, name };
      if (Number.isFinite(rootFolder)) payload.rootFolder = rootFolder;
      if (modalState.mode === 'create') {
        if (!token) {
          if (error) error.textContent = 'Team token is required.';
          return;
        }
        payload.teamToken = token;
      } else if (token) {
        payload.teamToken = token;
      }

      try {
        let res;
        if (modalState.mode === 'edit') {
          const rowId = overlay.dataset.teamRowId;
          res = await fetch(base + `/api/teams/${rowId}`, {
            method: 'PUT',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload),
            credentials: 'include',
          });
        } else {
          res = await fetch(base + '/api/teams', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload),
            credentials: 'include',
          });
        }
        if (!res.ok) {
          const msg = res.status === 409 ? 'Team already exists.' : 'Failed to save team.';
          if (error) error.textContent = msg;
          return;
        }
        const data = await res.json().catch(() => null);
        closeTeamModal();
        const savedTeam = data?.team || payload;
        if (modalState.mode === 'create' && savedTeam?.teamId) {
          pendingSelectId = String(savedTeam.teamId);
        }
        if (typeof modalState.onSaved === 'function') {
          modalState.onSaved(savedTeam);
        }
        if (typeof window.__reloadTeamSelect === 'function') {
          window.__reloadTeamSelect(pendingSelectId);
        }
      } catch (_) {
        if (error) error.textContent = 'Failed to save team.';
      }
    }

    function setMeta(team) {
      if (!meta) return;
      if (!team) {
        meta.textContent = 'No team selected.';
        return;
      }
      const name = team.name ? `${team.name} · ` : '';
      const root = team.rootFolder ? ` · Root folder ${team.rootFolder}` : '';
      meta.textContent = `${name}Team ID ${team.teamId}${root}`;
    }

    function applyRootFolder(team) {
      if (!team || !team.rootFolder) return;
      ['folderId', 'parentId'].forEach((id) => {
        const el = document.getElementById(id);
        if (el && !String(el.value || '').trim()) {
          el.value = String(team.rootFolder);
        }
      });
    }

    function updateSelection() {
      const selectedId = String(select.value || '');
      if (selectedId === '__create__') {
        select.value = lastValidTeamId;
        syncCustomLabel();
        syncCustomSelection();
        openTeamModal({ mode: 'create' });
        return;
      }
      if (selectedId === '__manage__') {
        select.value = lastValidTeamId;
        syncCustomLabel();
        syncCustomSelection();
        window.location.href = '/team-settings.html';
        return;
      }
      const team = teams.find((t) => String(t.teamId) === selectedId) || null;
      window.__selectedTeam = team;
      if (selectedId) {
        lastValidTeamId = selectedId;
        try { localStorage.setItem('st_selected_team', selectedId); } catch {}
      }
      setMeta(team);
      applyRootFolder(team);
      syncCustomLabel();
      syncCustomSelection();
    }

    function teamLabel(team) {
      if (!team) return 'Select a team';
      return team.name ? `${team.name} (${team.teamId})` : `Team ${team.teamId}`;
    }

    function syncCustomLabel() {
      if (!customLabel) return;
      const selectedId = String(select.value || '');
      const team = teams.find((t) => String(t.teamId) === selectedId) || null;
      customLabel.textContent = team ? teamLabel(team) : 'Select a team';
    }

    function syncCustomSelection() {
      if (!customPanel) return;
      const selectedId = String(select.value || '');
      const items = customPanel.querySelectorAll('[data-value]');
      items.forEach((item) => {
        item.classList.toggle('is-selected', item.dataset.value === selectedId);
      });
    }

    function renderCustomOptions() {
      if (!customPanel) return;
      customPanel.innerHTML = '';

      if (teams.length) {
        teams.forEach((team) => {
          const item = document.createElement('button');
          item.type = 'button';
          item.className = 'team-select-option';
          item.dataset.value = String(team.teamId);
          item.textContent = teamLabel(team);
          customPanel.appendChild(item);
        });
      }

      const separator = document.createElement('div');
      separator.className = 'team-select-separator';
      separator.setAttribute('role', 'separator');
      customPanel.appendChild(separator);

      if (teams.length) {
        const manage = document.createElement('button');
        manage.type = 'button';
        manage.className = 'team-select-option';
        manage.dataset.value = '__manage__';
        manage.textContent = 'Manage teams';
        customPanel.appendChild(manage);
      }

      const create = document.createElement('button');
      create.type = 'button';
      create.className = 'team-select-option team-select-create';
      create.dataset.value = '__create__';
      create.textContent = '+ Create team';
      customPanel.appendChild(create);

      if (!teams.length) {
        const empty = document.createElement('div');
        empty.className = 'team-select-empty';
        empty.textContent = 'Team list is empty, please create one';
        customPanel.appendChild(empty);
      }

      syncCustomLabel();
      syncCustomSelection();
    }

    function renderTeams(list, preferredTeamId) {
      teams = Array.isArray(list) ? list : [];
      select.innerHTML = '';

      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = 'Select a team';
      placeholder.disabled = true;
      select.appendChild(placeholder);

      if (teams.length) {
        teams.forEach((team) => {
          const opt = document.createElement('option');
          opt.value = String(team.teamId);
          opt.textContent = team.name ? `${team.name} (${team.teamId})` : `Team ${team.teamId}`;
          select.appendChild(opt);
        });
      }

      const separator = document.createElement('option');
      separator.value = '__separator__';
      separator.textContent = '---------------------';
      separator.disabled = true;
      select.appendChild(separator);

      if (teams.length) {
        const manageOpt = document.createElement('option');
        manageOpt.value = '__manage__';
        manageOpt.textContent = 'Manage teams';
        select.appendChild(manageOpt);
      }

      const createOpt = document.createElement('option');
      createOpt.value = '__create__';
      createOpt.textContent = '+ Create team';
      select.appendChild(createOpt);

      if (!teams.length) {
        const emptyOpt = document.createElement('option');
        emptyOpt.value = '__empty__';
        emptyOpt.textContent = 'Team list is empty, please create one';
        emptyOpt.disabled = true;
        emptyOpt.style.color = '#94a3b8';
        emptyOpt.style.fontStyle = 'italic';
        select.appendChild(emptyOpt);
      }

      let preferred = preferredTeamId || '';
      if (!preferred) {
        try { preferred = localStorage.getItem('st_selected_team') || ''; } catch {}
      }
      if (preferred && teams.some((t) => String(t.teamId) === preferred)) {
        select.value = preferred;
      } else if (teams.length) {
        select.value = String(teams[0].teamId);
      } else {
        select.value = '';
      }
      updateSelection();
      pendingSelectId = '';
      renderCustomOptions();
    }

    async function loadTeams(preferredTeamId) {
      try {
        const res = await fetch(base + '/api/teams', { credentials: 'include' });
        if (res.status === 401) {
          window.location.replace('/login.html?next=' + encodeURIComponent(window.location.pathname + window.location.search));
          return;
        }
        const data = await res.json().catch(() => null);
        renderTeams(data?.teams || [], preferredTeamId);
      } catch (e) {
        if (meta) meta.textContent = 'Failed to load teams.';
      }
    }

    window.openTeamModal = openTeamModal;

    document.addEventListener('click', (event) => {
      if (event.target?.id === 'teamModalClose' || event.target?.id === 'teamModalCancel') {
        closeTeamModal();
      }
    });
    document.addEventListener('submit', (event) => {
      if (event.target?.id === 'teamModalForm') {
        saveTeamFromModal(event);
      }
    });
    if (!select) return;

    ensureCustomTeamSelect();

    window.getSelectedTeam = function getSelectedTeam() {
      return window.__selectedTeam || null;
    };
    window.getSelectedTeamId = function getSelectedTeamId() {
      return window.__selectedTeam ? window.__selectedTeam.teamId : null;
    };
    window.__reloadTeamSelect = loadTeams;

    select.addEventListener('change', updateSelection);

    loadTeams();
  });

  // 8) User menu (shared across builder pages)
  onReady(function initUserMenu() {
    const button = document.getElementById('userMenuButton');
    const panel = document.getElementById('userMenuPanel');
    if (!button || !panel) return;
    const emailNode = document.getElementById('userMenuEmail');
    const logoutBtn = document.getElementById('userMenuLogout');
    const base = (window.BASE || window.DEFAULT_BACKEND || '').replace(/\/+$/, '');

    function setEmail(value) {
      if (!emailNode) return;
      emailNode.textContent = value || 'Signed in';
    }

    function setAvatar(email) {
      const value = (email || '').trim();
      if (!value) return;
      const letter = value.charAt(0).toUpperCase();
      button.textContent = '';
      const span = document.createElement('span');
      span.className = 'user-menu-initial';
      span.textContent = letter || 'U';
      button.appendChild(span);
    }

    if (window.__authUserEmail) {
      setEmail(window.__authUserEmail);
      setAvatar(window.__authUserEmail);
    }
    else {
      fetch(base + '/api/auth/status', { credentials: 'include' })
        .then((res) => res.json())
        .then((data) => {
          if (data?.email) {
            window.__authUserEmail = data.email;
            setEmail(data.email);
            setAvatar(data.email);
          }
        })
        .catch(() => {});
    }

    button.addEventListener('click', (e) => {
      e.preventDefault();
      panel.classList.toggle('hidden');
    });
    document.addEventListener('click', (e) => {
      if (!panel.contains(e.target) && !button.contains(e.target)) {
        panel.classList.add('hidden');
      }
    });
    logoutBtn?.addEventListener('click', async (e) => {
      e.preventDefault();
      try {
        await fetch(base + '/api/logout', { method: 'POST', credentials: 'include' });
      } catch {}
      window.location.href = '/login.html';
    });
  });

  // 9) Builder tools dropdown
  onReady(function initToolMenu() {
    const button = document.getElementById('toolMenuButton');
    const panel = document.getElementById('toolMenuPanel');
    if (!button || !panel) return;

    function setOpen(isOpen) {
      panel.classList.toggle('hidden', !isOpen);
      button.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    }

    button.addEventListener('click', (e) => {
      e.preventDefault();
      setOpen(panel.classList.contains('hidden'));
    });
    panel.addEventListener('click', (e) => {
      if (e.target?.closest('a')) setOpen(false);
    });
    document.addEventListener('click', (e) => {
      if (!panel.contains(e.target) && !button.contains(e.target)) {
        setOpen(false);
      }
    });
  });
