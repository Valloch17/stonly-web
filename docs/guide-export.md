# Guide Export API (Stonly guide → YAML / Markdown / JSON)

Turns an **existing** Stonly guide into either:

- **Guide Builder YAML** you can paste back into Expert mode → Guide YAML (or `POST
  /api/guides/build`) to rebuild the guide, or
- a **Markdown / JSON** document to feed an AI, a RAG pipeline, or a git repo.

It wraps the Stonly public `GET /guide/export` endpoint
([docs](https://docs.stonly.com/#/guide/guideExport)) and adds what a raw export is missing:
the guide title, the target step title on each transition, the tree structure the build API
needs, and HTML→Markdown conversion for the documentation view.

In the app this is **Expert mode → Guide export**.

Base URL for direct backend calls: `https://ai-builder-api.stonly.com`

## Authentication

Same two modes as the build endpoints:

1. **Headless importer admin auth**: `X-Admin-Token: <token>` (or `Authorization: Bearer`,
   or body field `adminToken`) plus the Stonly team token as `creds.teamToken`.
2. **Normal session auth**: the app session cookie; the stored team token is used.

`401` if neither is present, `400` if the admin token is valid but `creds.teamToken` is missing.

---

## 1. Export guides

`POST /api/guides/export`

### Request body

- `creds.teamId` number (required)
- `creds.teamToken` string (required for admin auth)
- `creds.base` string (optional; defaults to the EU Stonly base)
- `guide` string (required unless `guides` is used): guide id **or** URL. Accepted forms:
  - `U9RM3Ewtgo`
  - `https://app.stonly.com/app/guide/U9RM3Ewtgo/editor/4999083`
  - `https://stonly.com/kb/guide/en/some-slug-U9RM3Ewtgo/Steps/85968`
  - any URL carrying `?guideId=` / `?contentId=`
- `guides` string[] (optional): several ids/URLs (max 25). Strings may also be
  comma/newline separated.
- `format` (default `yaml`) — **also decides the step content format**:
  | format | document | step content | re-importable |
  |---|---|---|---|
  | `yaml` | Guide Builder schema (`guide.firstStep` + nested `choices`) | HTML | yes |
  | `markdown` | docs view (front matter, flow, one section per step) | Markdown | no |
  | `json` | docs view (flat steps, ids, transitions) | Markdown | no |
- `version` `last_published_version` | `last_saved_version` | `last_saved`
  (default `last_published_version`)
- `language` string (optional): language code; omit for the guide's default language
- `purpose` `EXPORT` | `BPA` (default `BPA`, which also returns input/form/automation modules)
- `includeModules` boolean (default `true`): keep raw modules in the Markdown/JSON views
  (the YAML view always turns them into notes instead)
- `folderId` number (optional): folder used to resolve guide names; defaults to the team's
  root folder under session auth
- `resolveTitles` boolean (default `true`): set `false` to skip the name lookup (one less
  API round trip; the first step title is then used as the guide title)
- `adminToken` string (optional): alternative to the header

### Fallbacks

Stonly answers `404` for combinations that don't exist, which this endpoint retries rather
than failing:

- **Draft guides** have no published version → retried with `last_saved_version`, then
  `last_saved`.
- **`language` not present on the guide** → retried with the guide's own languages, then
  with no language (Stonly's default).
- **`purpose=BPA` refused** → retried with `EXPORT` (module details are then missing).

Every retry is reported in `warnings`.

### Response

```json
{
  "ok": true,
  "format": "yaml",
  "reimportable": true,
  "filename": "stonly-guide-U9RM3Ewtgo.yaml",
  "content": "# Stonly guide export ...\nguide:\n  contentTitle: ...",
  "guides": [{ "guideId": "U9RM3Ewtgo", "title": "...", "stepCount": 9, "content": "..." }],
  "documents": [{ "guide": {} }],
  "failures": [],
  "warnings": []
}
```

- `content` is the ready-to-save document (multi-document YAML separated by `---`,
  `---`-separated Markdown, or a JSON array when several guides are requested).
- `guides[].content` is the same rendering per guide.
- `documents` is the structured form behind `content`.
- A guide that cannot be exported lands in `failures` while the others still succeed. If none
  succeed, the response is a `4xx` (or `502`) with the failures in `detail`.

### Example

```bash
curl -X POST https://ai-builder-api.stonly.com/api/guides/export \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $IMPORTER_ADMIN_TOKEN" \
  -d '{
    "creds": { "teamId": 39539, "teamToken": "stonly-team-token" },
    "guide": "https://app.stonly.com/app/guide/U9RM3Ewtgo/editor/4999083",
    "format": "yaml"
  }' | python -c "import json,sys; print(json.load(sys.stdin)['content'])"
```

---

## 2. YAML output: round-tripping a guide

The YAML export is the Guide Builder input format, so exporting and re-importing rebuilds the
guide:

```yaml
# Stonly guide export - re-importable Guide Builder YAML.
# Paste into Expert mode > Guide YAML (or POST /api/guides/build) to rebuild this guide.
# Source: guide U9RM3Ewtgo, team 39539, folder 509360 (Anderson America)
# Version: last_published_version | Language: en | Steps: 9
# contentType is assumed to be GUIDE - change it to ARTICLE or GUIDED_TOUR if needed.
guide:
  contentTitle: Stratos Pro Machine Unloading and Installation Procedures
  contentType: GUIDE
  language: en
  firstStep:
    title: 📦 Overview and Prerequisites
    content: <h3>Introduction</h3><p>This guide details the procedures...</p>
    choices:
      - label: Start Unloading Procedure
        step:
          title: 🏗️ Unloading the Main Unit
          content: <h3>Lifting the Main Unit</h3><ol><li>Use a forklift...</li></ol>
```

### Graphs become trees

A Stonly guide is a graph (a step can have several parents, and branches can loop back); the
build API takes a tree. Steps that more than one transition points to are emitted **once**
with a `key`, and the other transitions become `ref` choices:

```yaml
    choices:
      - label: Back to start
        ref: overview-and-prerequisites   # links instead of duplicating the step
```

Other structural rules:

- Transitions with no label (automatic transitions on automation steps, for example) get the
  label `Next`, because a choice needs a label to exist.
- Transitions pointing at no step are dropped and counted in `warnings`.
- Steps not reachable from the first step are kept and attached to the first step with an
  `[Unlinked] <title>` choice, so nothing is silently lost.
- Step tags are not supported by the build API and are dropped (reported in the header).
- `contentType` is not returned by the export API, so it is always written as `GUIDE`.

### Special steps become regular steps

The build API only creates regular steps. Automations, contact forms, NPS/surveys,
checklists, embedded guides, iframes, link steps, widget actions, AI steps — and input
modules on otherwise regular steps — are exported as **regular steps carrying a callout** that
names what to rebuild:

```html
<aside class="warning">
  <p><strong>Converted from a "Contact form" step</strong></p>
  <p>The build API only creates regular steps, so this one was imported as a regular step.
     Re-create it in the editor, then delete this note.</p>
  <ul>
    <li>Contact form module - success message: "Thanks!"</li>
    <li>Input field "Email address" (email, required)</li>
  </ul>
</aside>
```

The note uses the same `<aside class="warning">` callout Stonly itself uses, so it shows up as
a yellow block in the editor: rebuild the real step type, then delete the note. The step's
original content is kept below the note.

### What a round trip preserves

Verified by exporting real guides, re-importing them, and re-exporting the copy: step titles,
step content, choice labels, branch order, loops, and shared steps all come back identical.
Stonly adds its own markup on save (tables get a `table-container` wrapper, links get an inner
`<span>`), which is the only difference in the re-exported HTML.

---

## 3. List guides in a folder (guide picker)

`GET /api/guides/list`

Session auth only — this backs the guide picklist in the UI.

Query parameters:

- `teamId` number (required)
- `folderId` number (optional; defaults to the team's root folder, `400` if neither is set)
- `recursive` boolean (default `true`)
- `status` `draft` | `published` (optional)
- `limit` number (optional; capped at 2000)

```json
{
  "folderId": 338453,
  "recursive": true,
  "count": 393,
  "truncated": false,
  "items": [
    {
      "id": "U9RM3Ewtgo",
      "name": "Stratos Pro Machine Unloading and Installation Procedures",
      "status": "published",
      "folderId": 509360,
      "folderName": "Anderson America",
      "languages": ["en"]
    }
  ]
}
```

## Notes and limits

- Guide ids are per team: exporting with the wrong team selected returns `404 Not Found`.
- Markdown conversion covers headings, lists (incl. nesting), tables, links, images, code
  blocks, and Stonly's `<aside>` callouts (rendered as blockquotes with a **Warning** /
  **Tip** / **Note** label). Inline `data:` images become an `<inline-data-omitted>` marker
  instead of dumping base64 into the export.
- Media hosted by Stonly stays as absolute URLs, so both views still link to it.
- Max 25 guides per request; use several calls for a whole knowledge base.
