// Extracted from web/index.html (all inline <script> tags, in order)
// Stonly widget bootstrap moved to shared.js

if (typeof window.requireAdmin === 'function') {
    window.requireAdmin();
}

// Reset tree button handler
document.getElementById('resetTree')?.addEventListener('click', () => {
    localStorage.removeItem(STORAGE_KEY_NODES);
    window.location.reload();
});

const KB_BASE = (window.BASE || "https://ai-builder-api.stonly.com").replace(/\/+$/, '');
// --- Persistence helpers ---
const STORAGE_KEY_NODES = "stonly_ui_nodes";
const STORAGE_KEY_YAML = "stonly_yaml"; // optionnel si tu veux sauver le YAML
const STORAGE_KEYS_MISC = {
    st_team: "kb_st_team",
    parentId: "kb_parent_id",
};

function loadPersistedValue(id, key) {
    try {
        const v = localStorage.getItem(key);
        if (v != null) {
            const el = document.getElementById(id);
            if (el) el.value = v;
        }
    } catch { }
}
function persistOnInput(id, key) {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('input', () => {
        try { localStorage.setItem(key, el.value.trim()); } catch { }
    });
}

// Load on startup
// Team/Folder persistence moved to shared.js (uses unified keys)

// Depth-based styling
function depthBgClass(depth) {
    // even levels = layer-0, odd = layer-1
    return (depth % 2 === 0) ? "layer-0" : "layer-1";
}

function depthBorderClass(depth) {
    // slightly darker border on gray rows for contrast
    return (depth % 2 === 0) ? "border-gray-200" : "border-gray-300";
}

// --- Stable IDs for tree nodes ---
function genId() {
    return (Date.now().toString(36) + Math.random().toString(36).slice(2, 8));
}

function ensureId(n) {
    return {
        _id: n?._id || genId(),
        name: String(n?.name ?? ""),
        description: (n?.description ?? "") ? String(n.description) : undefined,
        children: Array.isArray(n?.children) ? n.children.map(ensureId) : []
    };
}

// If you already had normalizeNode/normalizeNodes, replace them with ensureId(*) equivalents:
function normalizeNodes(nodes) {
    if (!Array.isArray(nodes)) return [];
    return nodes.map(ensureId);
}


function loadNodesFromStorage() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY_NODES);
        if (!raw) return [];
        const arr = JSON.parse(raw);
        if (!Array.isArray(arr)) return [];
        // migration-safe: ensure description is preserved/added
        return normalizeNodes(arr);
    } catch {
        return [];
    }
}

function saveNodesToStorage(nodes) {
    try {
        // store exactly what UI has, including `description`
        localStorage.setItem(STORAGE_KEY_NODES, JSON.stringify(nodes));
    } catch { }
}

function loadYamlFromStorage() {
    try { return localStorage.getItem(STORAGE_KEY_YAML) || ""; } catch { return ""; }
}
function saveYamlToStorage(text) {
    try { localStorage.setItem(STORAGE_KEY_YAML, text || ""); } catch { }
}


/** Essaie de lire le textarea YAML et renvoie root[] si valide, sinon null */
function getRootFromYamlOrNull() {
    const el = document.getElementById('yaml');
    const err = document.getElementById('yamlError');
    err.textContent = "";
    const text = (el?.value || "").trim();
    if (!text) return null;

    // Parse YAML separately, so only YAML errors are labeled as such
    let data;
    try {
        data = jsyaml.load(text);
    } catch (e) {
        err.textContent = "Invalid YAML: " + (e?.message || e);
        return null;
    }

    try {
        let root = Array.isArray(data) ? data : (Array.isArray(data?.root) ? data.root : null);
        if (!root) throw new Error("YAML must contain a top-level list or a 'root' list.");

        root = normalizeNodes(root);

        // basic validation: names present
        const invalid = [];
        const walk = (list, p = "") => list.forEach(n => {
            if (!n.name || !n.name.trim()) invalid.push((p ? p + "/" : "/") + "<empty-name>");
            if (n.children?.length) walk(n.children, (p ? p + "/" : "") + n.name);
        });
        walk(root);
        if (invalid.length) throw new Error("Missing names at: " + invalid.slice(0, 3).join(", ") + (invalid.length > 3 ? "�?�" : ""));

        return root;
    } catch (e) {
        err.textContent = (e?.message || String(e));
        return null;
    }
}

const html = htm.bind(React.createElement);

function NodeEditor({ node, onChange, onRemove, depth = 0 }) {
    const [local, setLocal] = React.useState(node);
    const [showDesc, setShowDesc] = React.useState(Boolean(node?.description));

    React.useEffect(() => setLocal(node), [node]);

    const update = (patch) => {
        const next = { ...local, ...patch };
        setLocal(next);
        onChange(next);
    };

    const addChild = () => {
        const next = {
            ...local,
            children: [...(local.children || []), { _id: genId(), name: "", children: [] }]
        };
        setLocal(next);
        onChange(next);
    };

    const updateChildById = (id, nv) => {
        const arr = (local.children || []).map(c =>
            c._id === id ? { ...nv, _id: id } : c
        );
        update({ children: arr });
    };


    const removeChildById = (id) => {
        const arr = (local.children || []).filter(c => c._id !== id);
        update({ children: arr });
    };

    const wrapperClasses =
        ["rounded", "p-2", depthBgClass(depth), "border", depthBorderClass(depth)].join(" ");

    return html`
        <div class=${wrapperClasses}>
        <div class="flex items-center gap-1.5">
            <input
            class="border rounded p-1 text-sm flex-1"
            placeholder="Folder name"
            value=${local.name || ""}
            onInput=${e => update({ name: e.target.value })}
            />
            <button class="px-2 py-1 text-xs md:text-sm rounded bg-black text-white" type="button" onClick=${addChild}>+ Child</button>
            <button class="px-2 py-1 text-xs md:text-sm rounded border" type="button" onClick=${() => setShowDesc(v => !v)}>
            ${showDesc ? 'Hide description' : '+ Description'}
            </button>
            <button class="px-2 py-1 text-xs md:text-sm rounded border border-red-300 text-red-600" type="button" onClick=${onRemove}>Remove</button>
        </div>

        ${showDesc && html`
            <div class="mt-2">
            <input
                class="border rounded p-1 text-sm w-full"
                placeholder="Description (optional)"
                value=${local.description || ""}
                onInput=${e => {
                const val = e.target.value;
                update({ description: val?.trim() ? val : undefined });
            }}
            />
            </div>
        `}

        ${(local.children || []).length > 0 && html`
            <div class="pl-3 mt-2 space-y-1.5 border-l ${depthBorderClass(depth)}">
            ${(local.children || []).map((c) => html`
                <${NodeEditor}
                key=${c._id}
                node=${c}
                depth=${depth + 1}
                onChange=${nv => updateChildById(c._id, nv)}
                onRemove=${() => removeChildById(c._id)}
                />
            `)}
            </div>
        `}
        </div>
    `;
}


function getRoot(nodesFromUI) {
    const fromYaml = getRootFromYamlOrNull();
    return fromYaml ?? normalizeNodes(nodesFromUI);
}

// Ajoute/retire un liserǸ rouge sur les champs vides requis
// Use shared validateRequired from shared.js


function App() {
    const [nodes, setNodes] = React.useState(() => loadNodesFromStorage());

    // expose l'Ǹtat pour Apply/Verify si tu l'utilises ailleurs
    React.useEffect(() => { window.__UI_NODES__ = nodes; }, [nodes]);

    // ��΋�? sauve �� chaque changement
    React.useEffect(() => { saveNodesToStorage(nodes); }, [nodes]);

    // ADD root using stable ID
    const addRoot = React.useCallback(() => {
        setNodes(prev => [...prev, { _id: genId(), name: "", description: undefined, children: [] }]);
    }, []);

    // UPDATE root by id (not index)
    const updateRoot = React.useCallback((id, n) => {
        setNodes(prev => prev.map(x => x._id === id ? n : x));
    }, []);

    // REMOVE root by id
    const removeRoot = React.useCallback((id) => {
        setNodes(prev => prev.filter(x => x._id !== id));
    }, []);

    React.useEffect(() => {
        const btn = document.getElementById('addRoot');
        if (btn) btn.onclick = addRoot;
        return () => { if (btn) btn.onclick = null; };
    }, [addRoot]);




    const getCommon = () => ({
        parentId: (() => { const v = document.getElementById('parentId').value; return v ? Number(v) : null; })(),
        creds: {
            user: (() => {
                const el = document.getElementById('st_user');
                const v = (el && typeof el.value === 'string') ? el.value.trim() : '';
                return v || "Undefined";
            })(),
            teamId: (() => { const v = document.getElementById('teamSelect')?.value; return v ? Number(v) : null; })(),
            base: (window.getApiBase && window.getApiBase()) || "https://public.stonly.com/api/v3"
        }
    });
    // --- Init + bind YAML persistence (ajoute ce bloc ici) ---
    (function initYamlPersistence() {
        const y = document.getElementById('yaml');
        if (!y) return;

        // Remplit depuis localStorage si le champ est vide
        const prev = loadYamlFromStorage();
        if (prev && !y.value) y.value = prev;

        // Sauvegarde �� chaque saisie
        y.addEventListener('input', () => saveYamlToStorage(y.value));
    })();

    // ... le reste de ton script: composant App(), NodeEditor, handlers boutons, etc.



    async function call(path, bodyOrParams) {
        const out = document.getElementById('out');
        out.textContent = '...';

        try {
            let res;

            if (path === '/api/dump-structure') {
                const url = new URL(KB_BASE + path);
                const c = bodyOrParams.creds;
                url.searchParams.set('teamId', c.teamId);
                if (c.base) url.searchParams.set('base', c.base);
                if (bodyOrParams.parentId != null) url.searchParams.set('parentId', bodyOrParams.parentId);
                res = await fetch(url.toString(), { method: 'GET', credentials: 'include' });
            } else {
                res = await fetch(KB_BASE + path, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(bodyOrParams),
                    credentials: 'include',
                });
            }

            const statusLine = `HTTP ${res.status} ${res.statusText}`;
            const text = await res.text();

            // Try parse JSON, else show raw text + status
            try {
                const data = JSON.parse(text);
                out.textContent = JSON.stringify(data, null, 2);
            } catch {
                out.textContent = `${statusLine}\n${text}`;
            }
        } catch (e) {
            // True network issues (CORS/mixed content/offline) end up here
            document.getElementById('out').textContent = String(e);
        }
    }


    React.useEffect(() => {
        document.getElementById('addRoot').onclick = addRoot;
        document.getElementById('btnApply').onclick = () => {
            if (!(window.validateRequired && window.validateRequired(["parentId","teamSelect"]))) {
                document.getElementById('out').textContent = "Please fill all required fields (*).";
                return;
            }
            const common = getCommon();
            const root = getRoot(window.__UI_NODES__ || []);
            const settings = {
                publicAccess: parseInt(document.getElementById('publicAccess').value, 10),
                language: (document.getElementById('lang').value || "en").trim() || "en",
            };
            call('/api/apply', { ...common, dryRun: document.getElementById('dryRun').checked, root, settings });
        };


        document.getElementById('btnVerify').onclick = () => {
            if (!(window.validateRequired && window.validateRequired(["parentId","teamSelect"]))) {
                document.getElementById('out').textContent = "Please fill all required fields (*).";
                return;
            }
            const common = getCommon();
            const root = getRoot(window.__UI_NODES__ || []);
            call('/api/verify', { ...common, root });
        };

        document.getElementById('btnDump').onclick = () => {
            if (!(window.validateRequired && window.validateRequired(["parentId","teamSelect"]))) {
                document.getElementById('out').textContent = "Please fill all required fields (*).";
                return;
            }
            call('/api/dump-structure', getCommon());
        };
    }, []);

    return html`<div class="space-y-2">
        ${nodes.map(n => html`
        <${NodeEditor}
            key=${n._id}
            node=${n}
            depth=${0}
            onChange=${nv => updateRoot(n._id, nv)}
            onRemove=${() => removeRoot(n._id)}
        />
        `)}
    </div>`;


}

ReactDOM.createRoot(document.getElementById('tree')).render(html`<${App}/>`);

// Bouton "Copier la rǸponse"
// Copy response button wired using shared helper
try {
  (window.onReady || ((fn)=>fn()))(() => {
    if (typeof window.attachCopyButton === 'function') {
      window.attachCopyButton({
        buttonId: 'copyOut',
        sourceId: 'out',
        labels: { copied: 'Copied', failed: 'Copy failed', empty: 'Nothing to copy' },
        flashClasses: { success: 'bg-green-100', fail: 'bg-red-100' },
        disableWhenEmpty: true
      });
    }
  });
} catch {};

// Dark mode moved to shared.js
