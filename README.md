# Stonly Builder Suite

Create, refine, and publish Stonly knowledge base content and guides from one place. The suite includes multiple builder tools that share the same account and team settings, so you can switch between workflows without re-entering credentials.

## Getting started

- Open `https://ai-builder.stonly.com`.
- Log in with email/password or Google (stonly.com).
- New users sign up with an admin token provided by a Stonly admin.
- Select a team in the Team selector. If you have no teams, create one first.

## Builder tools

### AI Builder

Turn a prompt into a guide draft quickly. Use the refine steps to iterate and improve the result. Best for fast, lightweight guide creation.

### Guide Builder

Prompt-to-guide with an extra Gemini enrichment step for more complex builds, including attachments. Use this when you need richer outputs or supporting files.

### KB Builder

Build knowledge base structures using Gemini. Ideal for generating or reorganizing folder trees and content foundations.

### Guide Publisher

Publish guides in bulk. Use it to push multiple guides live in one pass.

### Expert Mode

Combines KB Builder and Guide Builder into one workflow for full, end-to-end builds. Includes:
- Automated mode for one-prompt KB + guides + organiser runs.
- Markdown mode for long `.md` documents with a 2-step AI flow:
  1. Structure generation/review.
  2. Batched step-content generation (configurable batch size), then build/publish.
- Guide export mode to convert existing guides into re-importable YAML, or into Markdown/JSON.

## Accounts and access

- Email/password and Google login both map to the same account if the email matches.
- Password reset requires the admin token.
- Admin tokens are used only for signup and reset; they are not stored in your account.

## Teams and settings

Teams are saved to your account so you can reuse them without re-entering tokens.

- Team fields: Team name, Team ID, Team token, Team origin (EU or US), optional Root folder.
- Team token is required when creating or editing a team.
- The Team selector is always available; use "+ Create team" in the dropdown.
- Manage teams in Team Settings to create, edit, or delete entries.
- EU and US API base URLs are advanced account settings. Most users should leave them unchanged.

## Typical workflow

- Log in.
- Select or create a team.
- Open the builder tool you need.
- Build, refine, and publish.

## Support

For access issues or admin tokens, contact valentin.bourrelier@stonly.com.

## Guide export

Expert Mode also exports the other way round: paste a guide URL from the editor (or pick a
guide from the team's guide list) and get it back as a file. The output format decides what
you get:

- **YAML**: Guide Builder YAML with HTML step content, so you can paste it into Guide YAML to
  rebuild the guide. Loops and shared steps are re-linked with `key`/`ref`, and special steps
  (automations, contact forms, input fields...) become regular steps with a callout naming
  what to rebuild in the editor.
- **Markdown / JSON**: a documentation view with Markdown step content, a flow overview, and
  step metadata, for feeding an AI or keeping guides in a repo.

Multiple guides can be exported in one pass. See `docs/guide-export.md`.

## Additional docs

- Importer endpoint: `docs/importer-html-to-guide.md`
- Guide export endpoint: `docs/guide-export.md`
