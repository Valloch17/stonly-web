# HTML Importer API

## Endpoint

`POST /api/importer/html-to-guide`

Base URL for direct backend calls: `https://ai-builder-api.stonly.com`

Converts one HTML document into one Stonly guide using the selected AI model, then optionally creates and publishes that guide in Stonly.

## What it does

1. Accepts an HTML document.
2. Sends that HTML to the selected AI model.
3. Converts the result into Stonly guide YAML.
4. Builds the guide through the existing Stonly guide pipeline.
5. Optionally publishes the created guide.

The endpoint always expects `html`. Plain `content` is not supported.

## Request body

### Required fields

- `teamId` number: Stonly team ID.
- `folderId` number: Stonly folder where the guide should be created.
- `html` string: Full HTML document or HTML fragment to convert.
- `aiModel` string: `gemini`, `gpt51`, or `gpt52`.

### Optional fields

- `documentName` string: Original source document name. Used as AI context and as the preferred final guide title.
- `sourceUrl` string: Original source URL, used as AI context.
- `contentType` string: `GUIDE`, `ARTICLE`, or `GUIDED_TOUR`. Default: `GUIDE`.
- `language` string: Stonly language code. Default: `en-US`.
- `publish` boolean: Publish the guide after creation. Default: `false`.
- `previewOnly` boolean: Return generated YAML only, without building in Stonly. Default: `false`.
- `base` string: Override the Stonly API base URL. Usually leave unset.
- `user` string: Optional label used when authenticating directly to Stonly. Default: `Importer`.
- `teamToken` string: Required only for headless importer auth.
- `adminToken` string: Optional alternative to sending the admin token in headers.

## Authentication

The endpoint supports two auth modes.

### 1. Normal session auth

Use the existing app session cookie.

In this mode:
- no `teamToken` is needed in the request
- the backend uses the team token already stored in the app

### 2. Headless importer auth

Use this when the importer should call the endpoint without a logged-in browser session.

Send:
- `X-Admin-Token: <token>` or `Authorization: Bearer <token>`
- `teamToken` in the JSON body

In this mode:
- the backend bypasses user session auth
- the backend creates a Stonly client directly from `teamId` + `teamToken`


## Example request

```bash
curl -X POST https://ai-builder-api.stonly.com/api/importer/html-to-guide \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $IMPORTER_TOKEN" \
  -d '{
    "teamId": 39539,
    "teamToken": "stonly-team-token",
    "folderId": 2000,
    "html": "<html><head><title>Password Reset</title></head><body><h1>Password Reset</h1><p>Follow these steps.</p></body></html>",
    "aiModel": "gpt52",
    "documentName": "Password Reset",
    "contentType": "GUIDE",
    "language": "en-US",
    "publish": true
  }'
```

## Example preview request

```bash
curl -X POST https://ai-builder-api.stonly.com/api/importer/html-to-guide \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $IMPORTER_ADMIN_TOKEN" \
  -d '{
    "teamId": 39539,
    "teamToken": "stonly-team-token",
    "folderId": 2000,
    "html": "<html><body><h1>Password Reset</h1></body></html>",
    "aiModel": "gemini",
    "previewOnly": true
  }'
```

## Response shape

### Success response

```json
{
  "ok": true,
  "yaml": "...generated guide yaml...",
  "build": {
    "ok": true,
    "guideId": "12345"
  },
  "modelUsed": "gpt52",
  "authMode": "admin_token"
}
```

Notes:
- when `previewOnly` is `true`, the response contains `yaml`, `previewOnly`, `modelUsed`, and `authMode`, but no `build`

## Validation and failure cases

- `400` if `html` is missing or empty
- `400` if `teamToken` is missing while using headless importer auth
- `401` if neither a valid session nor a valid importer admin token is provided
- `502` if the AI output does not resolve to exactly one valid guide
- upstream Stonly errors are forwarded with details when guide creation fails

## Practical guidance

- Prefer `previewOnly: true` when first validating a new importer flow.
- Prefer sending `documentName`, `contentType`, and `language` from the importer when those values are already known.
- Send clean article/body HTML where possible; remove unrelated page chrome before calling the endpoint for better results.
