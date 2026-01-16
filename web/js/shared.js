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
            <button id="teamModalClose" type="button" class="modal-close" aria-label="Close">x</button>
          </div>
          <form id="teamModalForm" class="space-y-3">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label class="block text-sm font-medium">Team ID <span class="text-red-600">*</span></label>
                <input id="teamModalId" type="number" class="mt-1 w-full border rounded-lg p-2 text-sm" placeholder="e.g. 39539" />
              </div>
              <div>
                <label class="block text-sm font-medium">Root folder</label>
                <input id="teamModalRoot" type="number" class="mt-1 w-full border rounded-lg p-2 text-sm" placeholder="Optional folder ID" />
              </div>
              <div>
                <label class="block text-sm font-medium">Team name</label>
                <input id="teamModalName" type="text" class="mt-1 w-full border rounded-lg p-2 text-sm" placeholder="Optional label" />
              </div>
              <div>
                <label class="block text-sm font-medium">Team token <span class="text-red-600">*</span></label>
                <input id="teamModalToken" type="password" class="mt-1 w-full border rounded-lg p-2 text-sm" placeholder="Stonly team token" autocomplete="off" />
                <p id="teamModalTokenHint" class="text-xs text-slate-500 mt-1 hidden">Leave blank to keep the current token.</p>
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
      if (!Number.isFinite(teamId)) {
        if (error) error.textContent = 'Team ID is required.';
        return;
      }

      const payload = { teamId };
      if (name) payload.name = name;
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
        openTeamModal({ mode: 'create' });
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
      const overlay = document.getElementById('teamModal');
      if (!overlay || overlay.classList.contains('hidden')) return;
      if (event.target === overlay) closeTeamModal();
    });
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

    if (window.__authUserEmail) setEmail(window.__authUserEmail);
    else {
      fetch(base + '/api/auth/status', { credentials: 'include' })
        .then((res) => res.json())
        .then((data) => {
          if (data?.email) {
            window.__authUserEmail = data.email;
            setEmail(data.email);
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
