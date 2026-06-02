# Headless Build API (Guides + KB from YAML)

These endpoints let a tool (e.g. the Claude cowork plugin) build Stonly content **without a
browser session** by sending the admin token. They accept the YAML your plugin already
generates — no AI generation step involved.

Base URL for direct backend calls: `https://ai-builder-api.stonly.com`

## Authentication

Both endpoints support two modes:

1. **Headless importer admin auth** (for programmatic use):
   - Send `X-Admin-Token: <token>` (or `Authorization: Bearer <token>`, or body field `adminToken`).
   - The token must equal the server's `IMPORTER_ADMIN_TOKEN` (falls back to `ADMIN_TOKEN`).
   - Send the Stonly team token as `creds.teamToken` in the body.
   - The backend bypasses user-session auth and builds a Stonly client directly from
     `creds.teamId` + `creds.teamToken`.
2. **Normal session auth**: send the app session cookie; the stored team token is used and
   `creds.teamToken` is not required.

`401` if neither a valid session nor a valid admin token is present.
`400` if the admin token is valid but `creds.teamToken` is missing.

---

## 1. Build guides from YAML

`POST /api/guides/build`

Builds one or many guides from guide YAML (`guide:` + `firstStep`, or a multi-document /
`guides:` list). Supports per-guide `folderId` / `publish` overrides inside the YAML.

### Request body

- `creds.teamId` number (required)
- `creds.teamToken` string (required for admin auth)
- `creds.base` string (optional; defaults to the EU Stonly base)
- `creds.user` string (optional label; default `Importer`)
- `folderId` number (required): default folder for guides that don't override it
- `yaml` string (required): guide YAML
- `publish` boolean (optional, default `false`)
- `dryRun` boolean (optional): parse only, do not call Stonly
- `adminToken` string (optional): alternative to the header

### Example

```bash
curl -X POST https://ai-builder-api.stonly.com/api/guides/build \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $IMPORTER_ADMIN_TOKEN" \
  -d '{
    "creds": { "teamId": 39539, "teamToken": "stonly-team-token" },
    "folderId": 2000,
    "publish": true,
    "yaml": "guide:\n  contentTitle: Password Reset\n  contentType: GUIDE\n  firstStep:\n    title: Start\n    content: \"<p>Follow these steps.</p>\""
  }'
```

Response is the standard build result (single-guide shape with `guideId`, or multi-guide
`results` + `summary`).

---

## 2. Build KB folder structure from YAML

`POST /api/kb/build`

Creates a folder tree from KB YAML — the same shape `/api/ai-kb/generate` produces: a
top-level `root:` list of `{name, description, children}` nodes. Existing folders with the
same name are reused (idempotent); missing ones are created.

### Request body

- `creds.teamId` number (required) + `creds.teamToken` (required for admin auth)
- `yaml` string (required): KB YAML with a top-level `root:` list
- `parentId` number (**required**): destination folder id to nest the tree under.
  Stonly's public API cannot create folders at the team root — it returns `403 Forbidden`
  when `parentFolderId` is omitted — so a parent is mandatory.
- `dryRun` boolean (optional): compute the mapping without creating folders
- `settings.publicAccess` (0/1) and `settings.language` (optional)
- `adminToken` string (optional): alternative to the header

### Example

```bash
curl -X POST https://ai-builder-api.stonly.com/api/kb/build \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $IMPORTER_ADMIN_TOKEN" \
  -d '{
    "creds": { "teamId": 39539, "teamToken": "stonly-team-token" },
    "parentId": 381916,
    "yaml": "root:\n  - name: Acme Knowledge Base\n    children:\n      - name: FAQs\n        children: []\n      - name: Tutorials\n        children: []"
  }'
```

### Response

```json
{
  "ok": true,
  "authMode": "admin_token",
  "mapping": {
    "/Acme Knowledge Base": 499700,
    "/Acme Knowledge Base/FAQs": 499701,
    "/Acme Knowledge Base/Tutorials": 499702
  }
}
```

In `dryRun` mode, created folders show `"(dry-run)"` instead of an id.

---

## Recommended plugin flow

1. `POST /api/kb/build` with the KB YAML → get the path→folderId `mapping`.
2. For each guide, set `folderId` (from the mapping) in the guide YAML, then
   `POST /api/guides/build` (or send all guides in one multi-document YAML with per-guide
   `folderId` overrides).
3. Use `dryRun: true` on both first to validate parsing before writing to Stonly.
