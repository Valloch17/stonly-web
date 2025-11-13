# Stonly Builders (Folders + Guides)

This repository contains two small tools built on the Stonly public API:

- Folder Builder (knowledge base folders)
- Guide Builder (create Guides/Articles/Guided Tours from YAML)

Both are simple static pages backed by the same FastAPI server.

---

## Features

* **Visual Tree Editor**

  * Multiple roots, nested children
  * Optional **per-folder description** (toggle “+ Description”)
  * Compact layout with alternating row backgrounds by depth
  * Stable edits (add/remove; safe keys to avoid UI glitches)

* **YAML Import (priority source)**

  * Paste a `structure.yaml` to define the tree at once
  * YAML takes precedence over UI if provided
  * Supports `description` fields

* **Dry-run & Apply**

  * **Dry-run**: no writes, returns a mapping of what would be created
    (existing IDs are real; new nodes show `"(dry-run)"`)
  * **Apply**: creates **only missing** folders under a parent in Stonly
  * Global **Visibility (`publicAccess`)** and **Language** defaults per apply

* **Verify**

  * Compares your desired tree with Stonly under a given parent
  * Reports **missing** and **unexpected** folders

* **Dump Structure**

  * Reads the existing tree under a parent and returns a normalized structure
  * Handy to snapshot current state and iterate

* **Quality of life**

  * **Copy** button in Response panel
  * Persistent UI: tree + descriptions survive page refresh
  * Bottom-right **Contact** + **GitHub** quick links

---

## Live

* **Frontend**: `https://api-stonly-internal.onrender.com`
* **Backend (API)**: `https://stonly-web.onrender.com`

> In `web/index.html`, set:
>
> ```js
> const BASE = "https://stonly-web.onrender.com";
> ```

---

## Screenshots (optional)

*(Add screenshots/GIFs of the editor, Verify/Apply responses if you wish.)*

---

## Quick Start (Local)

### Prerequisites

* Python **3.11** or **3.12** (recommended; avoids compiling pydantic-core)
* Node not required (frontend is static HTML)
* Stonly credentials & team ID

### 1) Backend (FastAPI)

```bash
cd server
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

# Required env
set APP_ADMIN_TOKEN=your_admin_token          # Windows PowerShell
# export APP_ADMIN_TOKEN=your_admin_token     # macOS/Linux

# Run locally
uvicorn main:app --reload
# API at http://127.0.0.1:8000
```

### 2) Frontend (static)

Open `web/index.html` in a browser, **or** serve it:

```bash
# any simple static server
python -m http.server --directory web 8080
# then open http://127.0.0.1:8080
```

Set the backend URL at the top of `index.html`:

```html
<script>
  const BASE = "http://127.0.0.1:8000";
</script>
```

---

## Usage

1. Open **Settings**:

   * **Admin token** (must match backend’s `APP_ADMIN_TOKEN`)
   * **Parent folder ID** (target node under which the tree is managed)
   * **Team ID**, **Stonly user**, **password/token**
   * Optional: **Visibility (publicAccess)** and **Language** defaults

2. Define your tree:

   * Build visually in **Tree**, adding roots/children and (optionally) **Description**
   * Or paste a **YAML** structure in the `structure.yaml` box
     (YAML **overrides** the UI for Apply/Verify if present)

3. Click **Verify** (safe read-only) to see **missing/unexpected**.

4. Toggle **Dry-run** on/off and click **Apply**.

5. Use **Dump structure** to snapshot the current Stonly hierarchy.

---

## YAML Format

```yaml
root:
  - name: Support
    description: "Public info & help center"   # optional
    children:
      - name: FAQs
        description: "Common questions"        # optional
        children: []
      - name: Tutorials
        children:
          - name: Web
            children: []
          - name: Mobile
            description: "iOS & Android guides"
            children: []
```

* `name` (required), `description` (optional), `children` (list; can be empty)
* YAML takes priority over UI entries when both are present

---

## Guide Builder (YAML → Guides)

Create and publish Stonly Guides from YAML with nested steps, choices, optional media, multi‑guide batches, and step reuse (linking existing steps).

### Key features

- Parse and preview YAML as a visual tree with an execution plan
- Dry‑run mode (no API calls) and real mode with optional publish
- Multi‑guide YAML via `---` or a top‑level `guides: []`
- Per‑guide overrides (`folderId`, `publish`, `contentType`, `language`)
- Step reuse via Stonly’s `POST /guide/step/link`:
  - Add `key` on any step you want to jump to later
  - In a choice, set `ref: <key>` to link the parent step to that step
  - Use for cross‑branch jumps or multi‑step returns (avoid one‑step “Back”) 
- Examples menu includes a full multi‑guide prompt: `web/assets/prompt.yaml`

### Running locally

1) Start the backend at `http://localhost:8000` (see Quick Start above).
2) Open `web/guide-builder.html` or serve the `web/` folder. On localhost the page auto‑targets `http://localhost:8000`.
3) Fill Admin token + Stonly credentials. On localhost, tokens persist across refresh.

### YAML schema (short)

- `guide`: `{ contentTitle, contentType, language, firstStep }`
- `Step`: `{ title, content, language?, media[≤3]?, position?, key?, choices? }`
- `Choice`: `{ label?, position?, step? | ref? }` (exactly one of `step` or `ref`)
- `contentType`: `GUIDE | ARTICLE | GUIDED_TOUR`

See `samples/prompt.yaml` and the Examples menu for full patterns.

---

## API (Backend)

Base URL = your backend (e.g., `https://stonly-web.onrender.com`)

### `GET /api/dump-structure`

Query parameters:

* `token`, `user`, `password`, `teamId`, `base` (default `https://public.stonly.com/api/v3`), `parentId`

Returns:

```json
{ "root": [ { "name": "Support", "children": [ ... ] } ] }
```

### `POST /api/verify`

Body:

```json
{
  "token": "APP_ADMIN_TOKEN",
  "creds": { "user":"...", "password":"...", "teamId": 39539, "base": "https://public.stonly.com/api/v3" },
  "parentId": 494710,
  "root": [ { "name": "Support", "children": [ ... ] } ]
}
```

Returns either:

```json
{ "ok": true }
```

or

```json
{ "missing": ["/Support/FAQs"], "unexpected": ["/OldStuff"] }
```

### `POST /api/apply`

Body:

```json
{
  "token": "APP_ADMIN_TOKEN",
  "creds": { "user":"...", "password":"...", "teamId": 39539, "base": "https://public.stonly.com/api/v3" },
  "parentId": 494710,
  "dryRun": true,
  "settings": { "publicAccess": 1, "language": "en" },
  "root": [ { "name": "Support", "description": "…", "children": [ ... ] } ]
}
```

Returns:

```json
{
  "ok": true,
  "mapping": {
    "/Support": 494921,
    "/Support/FAQs": "(dry-run)",
    "/Support/Tutorials/Web": "(dry-run)"
  }
}
```

> In non-dry runs, created IDs are returned as integers.

---

## Deployment (Render)

### Backend

* **Environment**: set `APP_ADMIN_TOKEN`
* **Build Command**: `pip install -r requirements.txt`
* **Start Command**: `uvicorn main:app --host 0.0.0.0 --port 10000`
* **Python version**: pin to 3.11 (Render `runtime.txt` or env `PYTHON_VERSION=3.11.x`)
* **CORS**: backend allows the frontend origin (configured in FastAPI middleware)

### Frontend

* Static site (no build); just serve `web/` (Render static site or any CDN)
* The pages are `index.html` (Folder Builder) and `guide-builder.html` (Guide Builder).
* In production, serve both with the same backend origin or set `window.BASE` with a small inline script if needed.

---

## CI / Quality Gates

* **Tests** (`server/tests`) use `pytest` and a **fake Stonly client**:

  * Test suite covers: `dump-structure`, `apply` (dry & real), `verify`
  * No external calls; in-memory stub shares state between requests
* **GitHub Actions** (example):

  ```yaml
  name: Server CI
  on: [push, pull_request]
  jobs:
    test-server:
      defaults:
        run:
          working-directory: server
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-python@v5
          with:
            python-version: "3.11"
        - run: pip install -r requirements.txt
        - run: pytest -q
  ```
* **Render Auto-Deploy**: set to **Only if checks pass** (waits for green GitHub checks)

---

## Security Notes

* **Admin token** protects all backend routes; keep it secret.
* Credentials are provided at runtime via the UI and forwarded to the Stonly API.
* Prefer scoped service accounts for Stonly where possible.
* Do not commit secrets; use environment variables and repository secrets.

---

## Troubleshooting

* **“NetworkError when attempting to fetch resource.”**

  * The UI prints HTTP status + body in the Response panel. Check upstream error.
* **Dry-run mapping empty**

  * Fixed: mapping shows existing IDs; new nodes marked `"(dry-run)"`.
* **Descriptions not appearing in Stonly**

  * Ensure backend models include `description` and you’re on the latest deployment.
* **Tree lost on refresh / edits mirror across nodes**

  * Fixed via stable `_id`, deep clones, and robust localStorage logic.
* **YAML errors**

  * UI shows precise parser errors; ensure top-level is a list or `root:` list.

---

## Project Structure

```
.
├─ server/
│  ├─ main.py                 # FastAPI app (apply/verify/dump)
│  ├─ requirements.txt
│  └─ tests/
│     ├─ conftest.py          # Fake Stonly + TestClient
│     └─ test_api.py          # API tests
└─ web/
   └─ index.html              # Single-file frontend (no build needed)
```

---

## Roadmap (ideas)

* Per-folder overrides for visibility/language in YAML
* Reordering support (drag & drop)
* Compare descriptions and other metadata in Verify
* Export as downloadable `structure.yaml`

---

## Contact

* **Owner**: Stonly internal tooling
* **Contact**: [valentin.bourrelier@stonly.com](mailto:valentin.bourrelier@stonly.com)
* **Repository**: [https://github.com/Valloch17/stonly-web](https://github.com/Valloch17/stonly-web)

---

### Guide Builder Files

```
web/
├─ guide-builder.html       # Guide Builder UI
├─ assets/
│  └─ prompt.yaml           # Full multi‑guide example (keys/refs)
├─ js/
│  ├─ guide.js              # Guide Builder logic (parsing, preview, plan)
│  └─ shared.js             # Shared: BASE autodetect, token persistence, widget boot
└─ shared.css               # Theme + preview styling
```
