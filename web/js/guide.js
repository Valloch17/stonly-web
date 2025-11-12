const EXAMPLES = {
    article: `# ARTICLE — single step (simple HTML, no choices)
        guide:
          contentTitle: Company Security Policy (Quick Read)
          contentType: ARTICLE
          language: en
          firstStep:
            title: Security Policy Overview
            content: |
              <h3>Welcome</h3>
              <p>This article summarizes the core security practices.</p>
              <ul>
                <li><strong>MFA</strong> required for all accounts</li>
                <li>Use a <em>password manager</em></li>
                <li>Report phishing via the <code>Phish Alert</code> button</li>
              </ul>
              <p>For details, see the full handbook.</p>`,

    guide_media: `# GUIDE — branching sub-steps with media
        guide:
          contentTitle: Laptop Setup Wizard
          contentType: GUIDE
          language: en
          firstStep:
            title: Choose Your OS
            content: |
              <p>Pick your operating system to see tailored steps.</p>
            media:
              - https://upload.wikimedia.org/wikipedia/commons/thumb/e/e2/Windows_logo_and_wordmark_-_2021.svg/langfr-500px-Windows_logo_and_wordmark_-_2021.svg.png
              - https://upload.wikimedia.org/wikipedia/commons/f/fa/Apple_logo_black.svg
            choices:
              - label: macOS
                step:
                  title: macOS Setup
                  content: |
                    <ol>
                      <li>Open <strong>System Settings</strong> → <em>Privacy & Security</em></li>
                      <li>Enable FileVault</li>
                      <li>Install Rosetta if prompted</li>
                    </ol>
                  media:
                    - https://upload.wikimedia.org/wikipedia/commons/f/fa/Apple_logo_black.svg
              - label: Windows
                step:
                  title: Windows Setup
                  content: |
                    <ol>
                      <li>Run <code>Windows Update</code> until fully patched</li>
                      <li>Turn on BitLocker</li>
                      <li>Install company apps from the portal</li>
                    </ol>
                  media: https://upload.wikimedia.org/wikipedia/commons/thumb/e/e2/Windows_logo_and_wordmark_-_2021.svg/langfr-500px-Windows_logo_and_wordmark_-_2021.svg.png`,

    tour: `# GUIDED_TOUR — linear "Next" steps
        guide:
          contentTitle: Product Onboarding Tour
          contentType: GUIDED_TOUR
          language: en
          firstStep:
            title: Welcome to the Dashboard
            content: "<p>This brief tour highlights key areas of the product.</p>"
            choices:
              - label: Next
                step:
                  title: Create Your First Project
                  content: "<p>Click <strong>New Project</strong> in the top right.</p>"
                  choices:
                    - label: Next
                      step:
                        title: Invite Your Team
                        content: "<p>Open <em>Settings → Members</em> and invite colleagues.</p>"`,

    troubleshoot: `# GUIDE — rich HTML (table + pre/code) + media
        guide:
          contentTitle: Troubleshoot VPN Issues
          contentType: GUIDE
          language: en
          firstStep:
            title: Check Basics
            content: |
              <p>Before advanced steps, verify:</p>
              <table border="1" cellpadding="6">
                <tr><th>Item</th><th>Expected</th></tr>
                <tr><td>Internet</td><td>Working</td></tr>
                <tr><td>Credentials</td><td>Valid</td></tr>
              </table>
              <p>Then try reconnecting.</p>
            media:
              - https://upload.wikimedia.org/wikipedia/commons/1/17/OOjs_UI_icon_reload.svg
            choices:
              - label: Still not working
                step:
                  title: Reset Configuration
                  content: |
                    <p>Run this command and retry:</p>
                    <pre><code>vpncli reset --profile default</code></pre>
                  media:
                    - https://upload.wikimedia.org/wikipedia/commons/e/ed/Cog.png
        `
};

function setupExamplesDropdown() {
    const btn = document.getElementById('btnExample');
    const menu = document.getElementById('examplesMenu');
    const area = document.getElementById('guideYaml');
    const parseBtn = document.getElementById('parseYamlBtn');
    if (!btn || !menu || !area) return;

    const openMenu = () => {
        menu.classList.remove('hidden');
        btn.setAttribute('aria-expanded', 'true');
    };
    const closeMenu = () => {
        menu.classList.add('hidden');
        btn.setAttribute('aria-expanded', 'false');
    };

    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = !menu.classList.contains('hidden');
        (isOpen ? closeMenu : openMenu)();
    });

    menu.querySelectorAll('button[data-example]').forEach(item => {
        item.addEventListener('click', () => {
            const key = item.getAttribute('data-example');
            const yaml = EXAMPLES[key];
            if (yaml) {
                area.value = yaml;
                closeMenu();
                if (parseBtn) parseBtn.click();
            }
        });
    });

    // click outside to close
    document.addEventListener('click', (e) => {
        if (!menu.classList.contains('hidden')) closeMenu();
    });
}
// Dynamically add a MULTI example and menu entry
function addMultiExample() {
    try {
        const multiYaml = `# Multiple guides in one YAML (multi-document)\n---\n# Per-guide overrides at the document level\n# These apply ONLY to this document's guide below\nfolderId: 123456\npublish: true\nguide:\n  contentTitle: Welcome Wizard\n  # contentType/language belong inside 'guide' (have priority)\n  contentType: GUIDE\n  language: en\n  firstStep:\n    title: Welcome\n    content: |\n      <p>Thanks for joining!</p>\n    choices:\n      - label: Set up\n        step:\n          title: Setup\n          content: "<p>Configure your workspace.</p>"\n\n---\n# Second guide — inherits from UI defaults when not set here\nguide:\n  contentTitle: Product Tour\n  contentType: GUIDED_TOUR\n  language: en\n  firstStep:\n    title: Tour Intro\n    content: "<p>Quick overview.</p>"\n    choices:\n      - label: Next\n        step:\n          title: Feature A\n          content: "<p>About Feature A.</p>"`;
        // attach to EXAMPLES map if not present
        if (typeof EXAMPLES === 'object' && !EXAMPLES.multi) {
            EXAMPLES.multi = multiYaml;
        }
        const menu = document.getElementById('examplesMenu');
        const btn = document.getElementById('btnExample');
        const area = document.getElementById('guideYaml');
        const parseBtn = document.getElementById('parseYamlBtn');
        if (!menu || !btn || !area) return;
        if (!menu.querySelector('button[data-example="multi"]')) {
            const sep = document.createElement('div');
            sep.className = 'border-t my-1';
            const b = document.createElement('button');
            b.className = 'w-full text-left px-3 py-2 text-sm hover:bg-neutral/10';
            b.setAttribute('data-example', 'multi');
            b.textContent = 'MULTI — multiple guides';
            b.addEventListener('click', () => {
                area.value = multiYaml;
                menu.classList.add('hidden');
                btn.setAttribute('aria-expanded', 'false');
                if (parseBtn) parseBtn.click();
            });
            menu.appendChild(sep);
            menu.appendChild(b);
        }
    } catch { /* no-op */ }
}

// Dynamically add an anonymized, rich HTML example with emojis
function addGuideRichExample() {
    try {
        const richYaml = `guide:\n  contentTitle: Account Portal | Access Reset (Example)\n  contentType: GUIDE\n  language: en\n  firstStep:\n    title: 🧭 Overview\n    content: |\n      <p>This workflow is for <strong>Tier 2 Support</strong> teams handling escalated <strong>account access reset</strong> requests.</p>\n      <p>Use it when Tier 1 confirms the situation, and the user needs a reset or 2FA reconfiguration.</p>\n      <aside class=\"tip\"><p>📌 <strong>Before you begin:</strong> Check in your admin tool that the user’s <strong>Status</strong> is <strong><span style=\"color:#16a34a\">Active</span></strong>.</p></aside>\n    media:\n      - https://upload.wikimedia.org/wikipedia/commons/7/71/Portal.svg\n    choices:\n      - label: 🪪 Step 1 — Verify Identity\n        step:\n          title: 🪪 Step 1 – Verify Identity\n          content: |\n            <p>Identity requirements depend on how the request arrived.</p>\n            <h4>🧩 Phone or Video</h4>\n            <ul>\n              <li>Verify the user’s <strong>full name</strong> and <strong>email address</strong> verbally.</li>\n            </ul>\n            <h4>🧩 Email Request</h4>\n            <ul>\n              <li>Send a template that confirms the request and explains the next steps.</li>\n              <li>Reference your internal macros (e.g., <code>Support::Access Reset::Verify Identity</code>).</li>\n            </ul>\n            <h4>🔒 Redact Sensitive Data Before Merging</h4>\n            <ol>\n              <li>Select text or attachments containing sensitive info and mark them for redaction.</li>\n              <li>Finalize redactions before merging related tickets.</li>\n            </ol>\n            <aside class=\"warning\"><p>⚠️ <strong><span style=\"color:#dc2626\">Never request a user’s secret key or OTP code.</span></strong> They must enter secrets only on their device.</p></aside>\n          media:\n            - https://upload.wikimedia.org/wikipedia/commons/6/6e/Ionicons_id-card.svg\n\n      - label: 🔁 Step 2 — Perform Reset\n        step:\n          title: 🔁 Step 2 – Perform Reset\n          content: |\n            <ol>\n              <li>Open the <strong>Admin Console</strong> and locate the user by <em>name</em>, <em>email</em>, or <em>ID</em>.</li>\n              <li>Choose <strong>Reset login</strong> or <strong>Initiate password reset</strong> as appropriate.</li>\n              <li>Confirm all prerequisites (identity verification, eligibility, etc.) have been completed.</li>\n              <li>Click <strong><span style=\"color:#3b82f6\">Confirm reset</span></strong>.</li>\n            </ol>\n            <p>Inform the user that they will receive a <strong>temporary password</strong> or a reset link. They must sign in, change their password, and reconfigure <strong>MFA</strong> if needed.</p>\n            <aside class=\"tip\"><p>✅ <b>Note:</b> If the user specifically requests a <b><span style=\"color:#3b82f6\">manual 2FA secret key</span></b> method, provide instructions only if your policy allows it.</p></aside>\n          media:\n            - https://upload.wikimedia.org/wikipedia/commons/1/1f/Reset_Icon.svg\n\n      - label: ✅ Step 3 — Confirm & Close\n        step:\n          title: ✅ Step 3 – Confirm & Close\n          content: |\n            <p>After the user regains access:</p>\n            <ul>\n              <li>Confirm successful sign-in and that MFA is configured.</li>\n              <li>Apply the correct closing macro for your team.</li>\n            </ul>\n            <table>\n              <tr><th>Team</th><th>Macro</th></tr>\n              <tr><td><strong>Support A</strong></td><td><code>Support A::Account Reset::Solved</code></td></tr>\n              <tr><td><strong>Support B</strong></td><td><code>Support B::Account Reset::Solved</code></td></tr>\n            </table>\n            <aside class=\"tip\"><p><strong>🎯 End of Workflow – Account Access Reset</strong></p></aside>\n          media:\n            - https://upload.wikimedia.org/wikipedia/commons/b/bd/Green_check.svg`;

        if (typeof EXAMPLES === 'object' && !EXAMPLES.guide_rich) {
            EXAMPLES.guide_rich = richYaml;
        }
        const menu = document.getElementById('examplesMenu');
        const btn = document.getElementById('btnExample');
        const area = document.getElementById('guideYaml');
        const parseBtn = document.getElementById('parseYamlBtn');
        if (!menu || !btn || !area) return;
        if (!menu.querySelector('button[data-example="guide_rich"]')) {
            const b = document.createElement('button');
            b.className = 'w-full text-left px-3 py-2 text-sm hover:bg-neutral/10';
            b.setAttribute('data-example', 'guide_rich');
            b.textContent = 'GUIDE — rich HTML & emojis';
            b.addEventListener('click', () => {
                area.value = richYaml;
                menu.classList.add('hidden');
                btn.setAttribute('aria-expanded', 'false');
                if (parseBtn) parseBtn.click();
            });
            // Insert into the first group (before the MULTI separator if present)
            const firstSep = menu.querySelector('div.border-t.my-1');
            if (firstSep) menu.insertBefore(b, firstSep); else menu.appendChild(b);
        }
    } catch { /* no-op */ }
}
// Strong HTML-aware newline/whitespace normalizer
function normalizeContent(html) {
    let s = String(html ?? '');

    // Normalize line endings and common whitespace
    s = s.replace(/\r\n?/g, '\n')        // CRLF/CR -> LF
        .replace(/\u00A0/g, ' ')        // NBSP -> space
        .replace(/[ \t]+\n/g, '\n')     // trim end-of-line spaces
        .trim();

    // Remove whitespace between tags to avoid empty text nodes
    // e.g. "<p>..</p>\n  <ul>" => "<p>..</p><ul>"
    s = s.replace(/>\s+\n\s*</g, '><')
        .replace(/>\s+</g, '><');

    // Collapse multiple blank lines to a single '\n'
    s = s.replace(/\n{2,}/g, '\n');

    // If there's no <pre>/<code>/<textarea>, replace remaining newlines with spaces
    // (so paragraph HTML written on multiple lines becomes a single flow)
    if (!/<\s*(pre|code|textarea)\b/i.test(s)) {
        s = s.replace(/\n+/g, ' ');
    }

    // Final tidy around tags: avoid stray spaces at tag boundaries
    s = s.replace(/>\s+/g, '>')
        .replace(/\s+</g, '<');

    return s;
}

// Execution plan show/hide
function setupPlanToggle() {
    const btn = document.getElementById('togglePlan');
    const box = document.getElementById('planContainer');
    if (!btn || !box) return;
    btn.addEventListener('click', () => {
        const hidden = box.classList.toggle('hidden');
        btn.textContent = hidden ? 'Show' : 'Hide';
    });
}
// Prefer same-origin if we are on the API host; otherwise hard-code your backend
const DEFAULT_BACKEND = "https://stonly-web.onrender.com";
const BASE = (window.location.origin.includes("stonly-web.onrender.com")
    ? window.location.origin
    : DEFAULT_BACKEND).replace(/\/+$/, '');
// Expose on window to avoid scope surprises in handlers
window.DEFAULT_BACKEND = DEFAULT_BACKEND;
window.BASE = BASE;

async function apiFetch(path, init) {
    const res = await fetch(BASE + path, init);
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    const text = await res.text();

    // Helpful guard: 200 HTML means you hit a static host/proxy, not the API
    if (ct.startsWith('text/html')) {
        throw new Error(`Got HTML from ${BASE + path}. Check BASE or routing.`);
    }

    let json;
    try { if (ct.includes('application/json')) json = JSON.parse(text); } catch (_) { }
    if (!res.ok) {
        // Bubble up a readable error
        const msg = json?.detail || json?.message || text || `HTTP ${res.status}`;
        throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
    return json ?? text;
}

function logLine(msg) {
    const ta = document.getElementById('logBox');
    const ts = new Date().toISOString().slice(11, 23);
    ta.value += `[${ts}] ${msg}\n`;
    ta.scrollTop = ta.scrollHeight;
}

function setLogsVisible(show) {
    const c = document.getElementById('logsContent');
    if (!c) return;
    if (show) c.classList.remove('hidden'); else c.classList.add('hidden');
}

async function fetchLogs() {
    const ta = document.getElementById('logBox');
    try {
        const textOrJson = await apiFetch('/api/debug/logs?lines=400', { method: 'GET' });
        const raw = typeof textOrJson === 'string' ? textOrJson : JSON.stringify(textOrJson, null, 2);
        const t = (raw || '').trim();
        // Only show the box if we really have logs
        if (t && !/^no log file yet\.?$/i.test(t)) {
            if (ta) ta.value = `--- backend logs (tail) ---\n${t}\n--- end logs ---\n`;
            setLogsVisible(true);
        } else {
            if (ta) ta.value = '';
            setLogsVisible(false);
        }
    } catch (e) {
        // On failure, keep the box hidden
        if (ta) ta.value = '';
        setLogsVisible(false);
    }
}
document.getElementById('btnFetchLogs')?.addEventListener('click', fetchLogs);
function clearLogs() {
    const ta = document.getElementById('logBox');
    if (ta) ta.value = '';
    setLogsVisible(false);
}
document.getElementById('btnClearLogs')?.addEventListener('click', clearLogs);


// Dark mode handled by shared.js

const el = (id) => document.getElementById(id);
const STORAGE_KEYS = { yaml: "guide_builder_yaml" };

function initPersistence() {
    // Persist Guide YAML locally for this page
    loadPersisted('guideYaml', STORAGE_KEYS.yaml, (value) => value);
    const yamlInput = el('guideYaml');
    if (yamlInput) {
        yamlInput.addEventListener('input', () => {
            persistValue(STORAGE_KEYS.yaml, yamlInput.value);
        });
    }
}
// Also expose globally in case any inline or external code references it
window.apiFetch = apiFetch;

// Simple DOM-ready helper
function onReady(fn) {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', fn, { once: true });
    } else {
        fn();
    }
}

onReady(initPersistence);
onReady(setupExamplesDropdown);
onReady(addMultiExample);
onReady(addGuideRichExample);
onReady(setupPlanToggle);

function loadPersisted(id, key, parser) {
    try {
        const value = localStorage.getItem(key);
        if (value !== null && el(id)) {
            el(id).value = parser ? parser(value) : value;
        }
    } catch {
        /* ignore storage errors */
    }
}

function persistValue(key, value) {
    try {
        localStorage.setItem(key, value ?? "");
    } catch {
        /* ignore storage errors */
    }
}

function getGuideYamlText() {
    return (el('guideYaml')?.value || '').trim();
}

function collectSettings() {
    return {
        token: (el('token')?.value || '').trim(),
        dryRun: !!el('dryRun')?.checked,
        base: (el('base')?.value || '').trim(),
        teamId: el('teamId')?.value ? Number(el('teamId').value) : null,
        user: (el('user')?.value || '').trim(),
        password: (el('password')?.value || '').trim(),
        folderId: el('folderId')?.value ? Number(el('folderId').value) : null,
        contentTitle: (el('contentTitle')?.value || '').trim(),
        contentType: (el('contentType')?.value || 'GUIDE').trim(),
        language: (el('language')?.value || '').trim() || null,
    };
}

function normalizeStep(step, path) {
    if (!step || typeof step !== 'object') {
        throw new Error(`${path} must be an object`);
    }
    const title = typeof step.title === 'string' && step.title.trim();
    if (!title) {
        throw new Error(`${path}.title is required`);
    }
    const content = typeof step.content === 'string';
    if (!content) {
        throw new Error(`${path}.content is required and must be a string`);
    }
    const node = {
        title: step.title.trim(),
        content: normalizeContent(step.content),
        language: typeof step.language === 'string' && step.language.trim() ? step.language.trim() : null,
        media: (() => {
            if (Array.isArray(step.media)) {
                return step.media.map(x => String(x).trim()).filter(Boolean).slice(0, 3);
            }
            if (typeof step.media === 'string' && step.media.trim()) {
                return [step.media.trim()];
            }
            return [];
        })(),

        position: Number.isFinite(step.position) ? Number(step.position) : null,
        choices: []
    };
    if (node.media.length > 3) {
        throw new Error(`${path}.media accepts up to 3 URLs`);
    }
    if (step.choices === undefined || step.choices === null) {
        return node;
    }
    if (!Array.isArray(step.choices)) {
        throw new Error(`${path}.choices must be an array`);
    }
    node.choices = step.choices.map((choice, idx) => {
        if (!choice || typeof choice !== 'object') {
            throw new Error(`${path}.choices[${idx}] must be an object`);
        }
        const nested = choice.step || choice.nextStep;
        if (!nested) {
            throw new Error(`${path}.choices[${idx}] is missing a nested step`);
        }
        const label = choice.label != null ? String(choice.label) : null;
        const position = choice.position != null ? Number(choice.position) : null;
        return {
            label,
            position: Number.isFinite(position) ? position : null,
            step: normalizeStep(nested, `${path}.choices[${idx}].step`)
        };
    });
    return node;
}

function parseGuideYaml(source) {
    const err = el('yamlError');
    err.textContent = '';
    const text = (typeof source === 'string' ? source : getGuideYamlText()).trim();
    if (!text) {
        err.textContent = 'YAML input is required.';
        return null;
    }
    let docs = [];
    try {
        jsyaml.loadAll(text, (d) => { docs.push(d); });
    } catch (e) {
        err.textContent = e.message || 'Unable to parse YAML.';
        return null;
    }
    if (!docs.length) {
        err.textContent = 'No YAML documents found.';
        return null;
    }
    // Support single document with top-level guides: []
    if (docs.length === 1 && docs[0] && typeof docs[0] === 'object' && Array.isArray(docs[0].guides)) {
        docs = docs[0].guides;
    }
    const results = [];
    try {
        docs.forEach((raw, idx) => {
            if (!raw || typeof raw !== 'object') throw new Error(`Document ${idx} must be a mapping`);
            const topCT = (typeof raw.contentType === 'string' && raw.contentType.trim()) ? raw.contentType.trim() : '';
            const topLang = (typeof raw.language === 'string' && raw.language.trim()) ? raw.language.trim() : '';
            const overrides = {
                folderId: (raw.folderId != null ? Number(raw.folderId) : null),
                publish: (raw.publish != null ? !!raw.publish : null),
                contentType: topCT || null,
                language: topLang || null,
            };
            const guide = (raw.guide && typeof raw.guide === 'object') ? raw.guide : raw;
            const info = {
                contentTitle: typeof guide.contentTitle === 'string' ? guide.contentTitle.trim() : '',
                // Priority: value inside guide > doc-level topCT
                contentType: (typeof guide.contentType === 'string' && guide.contentType.trim()) ? guide.contentType.trim() : (topCT || ''),
                language: (typeof guide.language === 'string' && guide.language.trim()) ? guide.language.trim() : (topLang || ''),
            };
            if (!guide.firstStep) throw new Error(`guide.firstStep is required (document ${idx})`);
            const firstStep = normalizeStep(guide.firstStep, `doc[${idx}].guide.firstStep`);
            results.push({ info, firstStep, overrides });
        });
    } catch (e) {
        err.textContent = e?.message || String(e);
        return null;
    }
    return results;
}

function renderPreviewStep(step, depth) {
    const container = document.createElement('div');
    container.className = depth === 0 ? '' : 'pl-4 border-l border-dashed border-neutral space-y-2';

    const heading = document.createElement('div');
    heading.className = 'flex items-start justify-between gap-3';
    heading.innerHTML = `
        <div>
            <div class="font-medium">${step.title}</div>
            <div class="text-xs text-slate-500">Content length: ${step.content.length} chars</div>
        </div>
        ${step.language ? `<span class="text-xs text-slate-500 uppercase">${step.language}</span>` : ''}
    `;
    container.appendChild(heading);

    // Show media badge if present
    if (Array.isArray(step.media) && step.media.length) {
        const badge = document.createElement('div');
        badge.className = 'mt-1 text-xs text-slate-500';
        badge.textContent = `Media: ${step.media.length} URL${step.media.length > 1 ? 's' : ''}`;
        container.appendChild(badge);
    }


    if (step.choices.length) {
        const list = document.createElement('div');
        list.className = 'space-y-3 mt-2';
        step.choices.forEach((choice, idx) => {
            const choiceBlock = document.createElement('div');
            choiceBlock.className = 'rounded-md border border-dashed border-neutral p-3 bg-card/60 dark:bg-slate-900/40 space-y-2';
            const label = choice.label ? choice.label : `Choice ${idx + 1}`;
            const pos = choice.position != null ? `· position ${choice.position}` : '';
            choiceBlock.innerHTML = `<div class="text-xs font-semibold uppercase tracking-wide text-slate-500">${label} ${pos}</div>`;
            choiceBlock.appendChild(renderPreviewStep(choice.step, depth + 1));
            list.appendChild(choiceBlock);
        });
        container.appendChild(list);
    }
    return container;
}

function renderPreview(parsed) {
    const tree = el('previewTree');
    const status = el('previewStatus');
    if (!parsed) {
        tree.innerHTML = '';
        status.textContent = 'Waiting for YAML.';
        return;
    }
    tree.innerHTML = '';
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    arr.forEach((p, i) => {
        const section = document.createElement('div');
        section.className = 'space-y-2';
        const title = (p.info?.contentTitle || p.firstStep?.title || `Item ${i + 1}`);
        const ct = String(p.info?.contentType || '').toUpperCase();
        const typeName = ct === 'ARTICLE' ? 'Article'
            : ct === 'GUIDED_TOUR' ? 'Guided tour'
                : 'Guide';
        const header = document.createElement('div');
        header.className = 'text-sm font-semibold';
        header.textContent = `${typeName}: ${title}`;
        section.appendChild(header);
        section.appendChild(renderPreviewStep(p.firstStep, 0));
        tree.appendChild(section);
    });
    status.textContent = `${arr.length} guide(s) parsed. Review before creating.`;
}

function collectPlan(parsed, settings) {
    if (!parsed) return null;
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    const plans = arr.map((p, i) => {
        const summarizeContent = (htmlOrText, chars = 30) => {
            if (typeof htmlOrText !== 'string') return htmlOrText;
            const s = htmlOrText;
            return s.length > chars ? s.slice(0, chars) + ' …' : s;
        };
        const merged = {
            token: settings.token,
            dryRun: settings.dryRun,
            base: settings.base,
            teamId: settings.teamId,
            user: settings.user,
            password: settings.password,
            folderId: (p.overrides?.folderId ?? settings.folderId),
            contentTitle: p.info.contentTitle || settings.contentTitle || p.firstStep.title,
            // Priority for plan: value inside guide info > doc-level overrides > UI defaults
            contentType: (p.info.contentType || p.overrides?.contentType || settings.contentType || 'GUIDE'),
            language: (p.info.language || p.overrides?.language || settings.language || p.firstStep.language || 'en-US'),
        };
        const plan = [];
        plan.push({
            action: 'Create guide',
            endpoint: 'POST /guide',
            payload: {
                folderId: merged.folderId,
                contentType: merged.contentType,
                contentTitle: merged.contentTitle,
                firstStepTitle: p.firstStep.title,
                content: summarizeContent(p.firstStep.content),
                language: p.firstStep.language || merged.language,
                media: (merged.contentType === 'ARTICLE' ? undefined : p.firstStep.media)
            }
        });

        const queue = [...p.firstStep.choices.map((choice, index) => ({
            parentTitle: p.firstStep.title,
            parentPath: 'firstStep',
            choice,
            index
        }))];

        while (queue.length) {
            const { parentTitle, parentPath, choice, index } = queue.shift();
            const defaultPosition = choice.position ?? choice.step?.position ?? index ?? 0;
            plan.push({
                action: `Append step: ${choice.step.title}`,
                endpoint: 'POST /guide/step',
                note: `Parent step: ${parentTitle} (${parentPath})`,
                payload: {
                    guideId: '<from create guide response>',
                    parentStepId: `<stepId for "${parentTitle}">`,
                    title: choice.step.title,
                    choiceLabel: choice.label || null,
                    content: summarizeContent(choice.step.content),
                    language: choice.step.language || merged.language,
                    position: defaultPosition,
                    media: (merged.contentType === 'ARTICLE' ? undefined : choice.step.media)
                }
            });
            choice.step.choices.forEach((child, idx) => {
                queue.push({
                    parentTitle: choice.step.title,
                    parentPath: `${parentPath}.choices[${idx}]`,
                    choice: child,
                    index: idx
                });
            });
        }
        return { index: i, settings: merged, plan };
    });
    return { guides: plans };
}

function maskSecretsDeep(obj) {
    // returns a deep-cloned, masked copy
    const SENSITIVE_KEYS = new Set(['token', 'password', 'pass', 'apiKey', 'authorization']);
    const mask = (val) => {
        if (typeof val !== 'string') return val;
        const s = val.trim();
        if (s.length <= 8) return '***';
        return s.slice(0, 2) + '***' + s.slice(-4); // keep first 2 + last 4
    };
    const walk = (v) => {
        if (Array.isArray(v)) return v.map(walk);
        if (v && typeof v === 'object') {
            const out = {};
            for (const k of Object.keys(v)) {
                if (SENSITIVE_KEYS.has(k)) out[k] = mask(v[k]);
                else out[k] = walk(v[k]);
            }
            return out;
        }
        return v;
    };
    return walk(obj);
}

function updateOut(result) {
    const out = document.getElementById('out');
    if (!out) return;
    if (!result) {
        out.textContent = '';
        return;
    }
    try {
        const safe = maskSecretsDeep(result);
        out.textContent = JSON.stringify(safe, null, 2);
    } catch {
        // Fallback
        out.textContent = JSON.stringify(result, null, 2);
    }
}


function setupCopyOut() {
    if (typeof window.attachCopyButton === 'function') {
        window.attachCopyButton({
            buttonId: 'copyOut',
            sourceId: 'out',
            labels: { copied: 'Copied', failed: 'Copy failed', empty: 'Nothing to copy' },
            flashClasses: { success: '', fail: '' },
            disableWhenEmpty: false
        });
    }
}

// KB-style highlighting is performed via shared.js: window.validateRequired

function describeError(payload, status) {
    if (!payload) return `HTTP ${status}`;
    if (typeof payload === 'string') return payload;
    if (payload.error) return payload.error;
    if (payload.message) return payload.message;
    if (payload.detail) {
        if (typeof payload.detail === 'string') return payload.detail;
        try {
            return JSON.stringify(payload.detail, null, 2);
        } catch {
            return String(payload.detail);
        }
    }
    try {
        return JSON.stringify(payload, null, 2);
    } catch {
        return String(payload);
    }
}

function buildGuidePayload(settings, yamlText) {
    return {
        token: settings.token,
        dryRun: settings.dryRun,
        folderId: settings.folderId,
        yaml: yamlText,
        defaults: {
            contentTitle: settings.contentTitle,
            contentType: settings.contentType,
            language: settings.language
        },
        publish: !!document.getElementById('publishAfter').checked,
        creds: {
            user: settings.user,
            password: settings.password,
            teamId: settings.teamId,
            base: settings.base || 'https://public.stonly.com/api/v3'
        }
    };
}

async function buildGuideRequest(settings, yamlText) {
    const btn = el('createGuideBtn');
    const original = btn?.textContent || 'Create guide';
    if (btn) {
        btn.disabled = true;
        btn.textContent = settings.dryRun ? 'Simulating...' : 'Creating...';
    }

    let status = null;
    let rawText = null;
    try {
        // ✅ Build the payload you intended to send
        const body = buildGuidePayload(settings, yamlText);

        // ✅ apiFetch returns parsed JSON (or throws on non-2xx); no need to re-parse
        const data = await apiFetch('/api/guides/build', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (data?.guideId) {
            const pub = data.published ? " (published ✅)" : "";
            alert(`Guide created: ${data.guideId}${pub}`);
        }


        // Keep the shape expected by the caller
        status = 200;
        rawText = JSON.stringify(data);
        return { status, body: data, rawText };
    } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        // Preserve what the caller prints into the “Execution plan / response” box
        e.status = e.status ?? status;
        e.rawText = e.rawText ?? rawText;
        throw e;
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = original;
        }
    }
}


onReady(() => el('parseYamlBtn')?.addEventListener('click', () => {
    const yamlText = getGuideYamlText();
    const parsed = parseGuideYaml(yamlText);
    renderPreview(parsed);
    if (!parsed) {
        updateOut(null);
        return;
    }
    const settings = collectSettings();
    const plan = collectPlan(parsed, settings);
    updateOut({ dryRun: settings.dryRun, plan });
}));

onReady(() => el('createGuideBtn')?.addEventListener('click', async () => {
    const settings = collectSettings();
    if (!(window.validateRequired && window.validateRequired(["token","teamId","folderId","user","password"]))) {
        const out = el('out');
        if (out) out.textContent = 'Please fill all required fields (*).';
        return;
    }
    const yamlText = getGuideYamlText();
    const parsed = parseGuideYaml(yamlText);
    if (!parsed) {
        return;
    }
    renderPreview(parsed);
    const plan = collectPlan(parsed, settings);
    updateOut({ dryRun: settings.dryRun, plan });
    try {
        const { body, status, rawText } = await buildGuideRequest(settings, yamlText);
        if (body) {
            updateOut({ dryRun: settings.dryRun, status, plan, response: body, raw: rawText });
            if (settings.dryRun) {
                alert('Dry-run complete. See the response panel for the simulated steps.');
            } else if (Array.isArray(body?.results)) {
                const total = body.summary?.count ?? body.results.length;
                const ok = body.summary?.succeeded ?? body.results.filter(r => r.ok).length;
                const failed = body.summary?.failed ?? (total - ok);
                const pubAll = body.publishedAll ? ' All requested guides were published.' : '';
                alert(`Batch complete: ${ok}/${total} succeeded, ${failed} failed.${pubAll}`);
            } else {
                alert(`Guide ${body.guideId} created with ${body.summary.stepCount} steps.`);
            }
        }
    } catch (err) {
        const message = err?.message || 'Guide build failed';
        const errorPayload = err && typeof err === 'object' ? err.payload : null;
        const status = err && typeof err === 'object' && 'status' in err ? err.status : null;
        const rawText = err && typeof err === 'object' && 'rawText' in err ? err.rawText : null;
        updateOut({
            dryRun: settings.dryRun,
            status,
            plan,
            error: message,
            errorPayload,
            raw: rawText
        });
        alert(`Guide build failed: ${message}`);
    }
}));

onReady(() => { try { setupCopyOut(); } catch {} });
