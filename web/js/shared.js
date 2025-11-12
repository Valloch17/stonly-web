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

  // 3) Shared persistence for Stonly user/team/folder between apps (no legacy migration)
  onReady(function initSharedPersistence() {
    const groups = [
      { key: 'st_shared_team', ids: ['st_team', 'teamId'] },
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
      { id: 'token', key: 'dev_admin_token' },          // Admin token (backend auth)
      { id: 'password', key: 'dev_stonly_password' },   // Guide Builder credential
      { id: 'st_pass', key: 'dev_stonly_password' },    // KB Builder credential
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
