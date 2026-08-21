import json
import pytest
import yaml
from fastapi import HTTPException
from fastapi.testclient import TestClient
try:
    import server.main as main
except ModuleNotFoundError:
    import main as main

PARENT_ID = 1000           # matches FakeStonly root parent
SUPPORT_ID = 2000          # existing Support in FakeStonly
FAQS_ID = 2001             # existing FAQs in FakeStonly

def _payload(creds, root, *, dry=False, settings=None, parent=PARENT_ID):
    body = {
        "creds": creds,
        "parentId": parent,
        "dryRun": dry,
        "root": root,
    }
    if settings:
        body["settings"] = settings
    return body

# server/tests/test_api.py
def _collect_paths(tree, prefix=""):
    paths = set()
    for n in tree:
        name = n.get("name")
        if not name:
            continue
        p = f"{prefix}/{name}" if prefix else f"/{name}"
        paths.add(p)
        for c in n.get("children", []) or []:
            paths |= _collect_paths([c], p)
    return paths
def test_dump_structure_with_parent(client, creds):
    r = client.get(
        "/api/dump-structure",
        params={
            "teamId": creds["teamId"],
            "base": creds["base"],
            "parentId": PARENT_ID,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "root" in data

    # Invariant minimal: le premier niveau contient 'Support'
    root = data["root"] or []
    names = [n.get("name") for n in root if isinstance(n, dict)]
    assert "Support" in names


def test_settings_defaults_and_save_region_bases(client):
    r = client.get("/api/settings")
    assert r.status_code == 200
    assert r.json() == {
        "ok": True,
        "euApiBase": "https://public.stonly.com/api/v3",
        "usApiBase": "https://public.us.stonly.com/api/v3",
    }

    r = client.put("/api/settings", json={
        "euApiBase": "https://eu.example.test/api/v4",
        "usApiBase": "https://us.example.test/api/v4",
    })
    assert r.status_code == 200
    assert r.json() == {
        "ok": True,
        "euApiBase": "https://eu.example.test/api/v4",
        "usApiBase": "https://us.example.test/api/v4",
    }


def test_gemini_model_name_defaults_to_current_replacement():
    assert main.GEMINI_MODEL_NAME_DEFAULT == "gemini-3.1-pro-preview"
    assert main._normalize_gemini_model_name(None) == "gemini-3.1-pro-preview"
    assert main._normalize_gemini_model_name("gemini-3-pro-preview") == "gemini-3.1-pro-preview"
    assert main._normalize_gemini_model_name("gemini-3-pro") == "gemini-3.1-pro-preview"
    assert main._normalize_gemini_model_name("gemini-3.5-flash") == "gemini-3.5-flash"
    assert main._normalize_ai_model("gemini-3.1-pro-preview") == main.AI_MODEL_GEMINI


def test_create_team_uses_selected_origin_base_and_persists_origin(client, monkeypatch):
    captured = {}

    r = client.put("/api/settings", json={
        "euApiBase": "https://eu.example.test/api/v4",
        "usApiBase": "https://us.example.test/api/v4",
    })
    assert r.status_code == 200

    def fake_validate(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(main, "_validate_team_access", fake_validate)

    r = client.post("/api/teams", json={
        "teamId": 48307,
        "teamToken": "us-token",
        "name": "US Team",
        "origin": "US",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["team"]["origin"] == "US"
    assert captured == {
        "base": "https://us.example.test/api/v4",
        "user_label": "Validator",
        "team_id": 48307,
        "team_token": "us-token",
    }

    r = client.get("/api/teams")
    assert r.status_code == 200
    teams = {team["teamId"]: team for team in r.json()["teams"]}
    assert teams[48307]["origin"] == "US"
    assert teams[39539]["origin"] == "EU"


def test_create_team_rejects_invalid_token_for_selected_origin(client):
    r = client.post("/api/teams", json={
        "teamId": 50001,
        "teamToken": "invalid-token",
        "name": "Broken Team",
        "origin": "US",
    })
    assert r.status_code == 400
    assert "selected region" in r.json()["detail"]


def test_build_guide_uses_team_origin_base_not_payload_base(client, monkeypatch):
    captured = {}

    r = client.put("/api/settings", json={
        "usApiBase": "https://us.example.test/api/v4",
    })
    assert r.status_code == 200

    monkeypatch.setattr(main, "_validate_team_access", lambda **kwargs: None)
    r = client.post("/api/teams", json={
        "teamId": 48308,
        "teamToken": "us-token",
        "name": "US Build Team",
        "origin": "US",
    })
    assert r.status_code == 200

    def fake_build_one_guide(*, st, team_id, folder_id, definition, dry_run, publish):
        captured["base"] = st.base
        captured["team_id"] = team_id
        captured["folder_id"] = folder_id
        return {
            "guideId": "g-1",
            "firstStepId": "s-1",
            "summary": {"stepCount": 1},
            "steps": [],
        }

    monkeypatch.setattr(main, "_build_one_guide", fake_build_one_guide)

    r = client.post("/api/guides/build", json={
        "creds": {
            "user": "tester@example.com",
            "teamId": 48308,
            "base": "https://wrong.example.test/api/v9",
        },
        "folderId": 2000,
        "yaml": """guide:
  contentTitle: Test guide
  contentType: GUIDE
  language: en-US
  firstStep:
    title: Start
    content: "<p>Hello</p>"
""",
    })
    assert r.status_code == 200
    assert captured["base"] == "https://us.example.test/api/v4"
    assert captured["team_id"] == 48308
    assert captured["folder_id"] == 2000


def test_apply_dry_run_no_creation_and_mapping_present(client, creds):
    # Dry-run must not create but should resolve existing ids into mapping
    root = [
        {"name": "Support", "children": [{"name": "FAQs", "children": []}]}
    ]
    r = client.post("/api/apply", json=_payload(creds, root, dry=True))
    assert r.status_code == 200
    data = r.json()
    assert data.get("ok") is True
    mapping = data.get("mapping", {})
    # Existing "/Support" should be in mapping with known id
    assert mapping.get("/Support") == SUPPORT_ID

def test_apply_real_creates_missing_with_settings_and_description(client, creds):
    # Create a missing child under Support; ensure global settings + description are passed
    root = [
        {"name": "Support",
         "children": [
             {"name": "Tutorials", "description": "How-to content", "children": []}
         ]}
    ]
    settings = {"publicAccess": 1, "language": "en"}
    r = client.post("/api/apply", json=_payload(creds, root, dry=False, settings=settings))
    assert r.status_code == 200
    data = r.json()
    assert data.get("ok") is True
    mapping = data.get("mapping", {})
    # New path should exist in mapping
    assert "/Support/Tutorials" in mapping

    # Introspect the FakeStonly instance used by the app:
    # We can’t access it directly, but we can call apply again and ensure mapping grows, or
    # better, rely on behavior: since FakeStonly stores created nodes and list_children sees them,
    # a second dry-run verify should find no missing.
    vr = client.post("/api/verify", json={
        "creds": creds, "parentId": PARENT_ID,
        "root": [{"name": "Support", "children": [{"name": "Tutorials", "children": []}]}]
    })
    assert vr.status_code == 200
    vdata = vr.json()
    # Accept either shape: {"ok":true} or {"missing":[],"unexpected":[]}
    if "ok" in vdata:
        assert vdata["ok"] is True
    if "missing" in vdata:
        assert vdata["missing"] in ([], {})
    if "unexpected" in vdata:
        assert vdata["unexpected"] in ([], {})

def test_verify_no_diffs_when_tree_matches(client, creds):
    # Verify that existing Support/FAQs is considered up-to-date
    root = [{"name": "Support", "children": [{"name": "FAQs", "children": []}]}]
    r = client.post("/api/verify", json={
        "creds": creds, "parentId": PARENT_ID, "root": root
    })
    assert r.status_code == 200
    data = r.json()
    if "ok" in data:
        assert data["ok"] is True
    if "missing" in data:
        assert data["missing"] in ([], {})
    if "unexpected" in data:
        assert data["unexpected"] in ([], {})


def test_ai_kb_generate_uses_selected_model(client, monkeypatch):
    captured = {}

    def fake_generate(prompt, *, ai_model):
        captured["prompt"] = prompt
        captured["ai_model"] = ai_model
        return "- name: Support"

    monkeypatch.setattr(main, "generate_kb_yaml_with_ai", fake_generate)

    r = client.post("/api/ai-kb/generate", json={
        "prompt": "Build a KB",
        "aiModel": "gpt51",
    })

    assert r.status_code == 200
    assert r.json()["yaml"] == "- name: Support"
    assert captured == {
        "prompt": "Build a KB",
        "ai_model": "gpt51",
    }


def test_ai_organiser_generate_uses_selected_model(client, monkeypatch):
    captured = {}

    def fake_generate(prompt, *, ai_model):
        captured["prompt"] = prompt
        captured["ai_model"] = ai_model
        return "- title: Guide\n  folderId: 123"

    monkeypatch.setattr(main, "generate_organiser_yaml_with_ai", fake_generate)

    r = client.post("/api/ai-organiser/generate", json={
        "prompt": "Map guides",
        "aiModel": "gpt52",
    })

    assert r.status_code == 200
    assert r.json()["yaml"] == "- title: Guide\n  folderId: 123"
    assert captured == {
        "prompt": "Map guides",
        "ai_model": "gpt52",
    }


def test_ai_kb_generate_accepts_prompt_longer_than_40k(client, monkeypatch):
    captured = {}

    def fake_generate(prompt, *, ai_model):
        captured["prompt_len"] = len(prompt)
        captured["ai_model"] = ai_model
        return "- name: Support"

    monkeypatch.setattr(main, "generate_kb_yaml_with_ai", fake_generate)
    prompt = "A" * 50000

    r = client.post("/api/ai-kb/generate", json={
        "prompt": prompt,
        "aiModel": "gpt51",
    })

    assert r.status_code == 200
    assert r.json()["yaml"] == "- name: Support"
    assert captured == {
        "prompt_len": 50000,
        "ai_model": "gpt51",
    }


def test_ai_kb_generate_rejects_prompt_above_max(client, monkeypatch):
    monkeypatch.setattr(main, "generate_kb_yaml_with_ai", lambda *args, **kwargs: "- name: Support")
    prompt = "A" * (main.AI_PROMPT_MAX_CHARS + 1)

    r = client.post("/api/ai-kb/generate", json={
        "prompt": prompt,
        "aiModel": "gpt51",
    })

    assert r.status_code == 422
    assert f"max {main.AI_PROMPT_MAX_CHARS} characters" in json.dumps(r.json())


def test_brand_assets_resolve_accepts_admin_token_without_session(monkeypatch):
    monkeypatch.setattr(main, "generate_brand_website_with_gemini", lambda brand_name: "https://accuris.com")
    monkeypatch.setattr(
        main,
        "_scrape_brand_assets",
        lambda url: {
            "ok": True,
            "url": "https://accuris.com",
            "logos": ["https://cdn.accuris.com/logo.svg"],
            "siteColors": ["#112233", "#445566", "#778899"],
        },
    )
    monkeypatch.setattr(
        main,
        "generate_brand_colors_with_gemini",
        lambda brand_name, url=None: {
            "headerBackground": "#0F172A",
            "iconColor": "#2563EB",
            "highlightColor": "#22C55E",
        },
    )

    with TestClient(main.app) as raw_client:
        r = raw_client.post(
            "/api/brand-assets/resolve",
            headers={"x-admin-token": "secret"},
            json={"brandName": "Accuris"},
        )

    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["authMode"] == "admin_token"
    assert body["brandName"] == "Accuris"
    assert body["url"] == "https://accuris.com"
    assert body["logoUrl"] == "https://cdn.accuris.com/logo.svg"
    assert body["logoDownloadUrl"] == "http://testserver/api/brand-assets/download?url=https%3A%2F%2Fcdn.accuris.com%2Flogo.svg"
    assert body["colors"] == {
        "headerBackground": "#0F172A",
        "iconColor": "#2563EB",
        "highlightColor": "#22C55E",
    }


def test_brand_assets_scrape_returns_fallback_logos_on_upstream_403(client, monkeypatch):
    calls = []

    class FakeResponse:
        def __init__(self, url):
            self.status_code = 403
            self.url = url
            self.ok = False
            self.headers = {"content-type": "text/html; charset=UTF-8"}
            self.text = ""

    def fake_get(url, headers=None, timeout=None, allow_redirects=None):
        calls.append({
            "url": url,
            "headers": headers,
            "timeout": timeout,
            "allow_redirects": allow_redirects,
        })
        return FakeResponse("https://ever.ag/")

    monkeypatch.setattr(main.requests, "get", fake_get)

    r = client.post("/api/brand-assets/scrape", json={
        "url": "https://ever.ag",
    })

    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["url"] == "https://ever.ag/"
    assert body["logos"] == [
        "https://ever.ag/apple-touch-icon.png",
        "https://ever.ag/favicon.ico",
    ]
    assert body["siteColors"] == []
    assert "HTTP 403" in body["warning"]
    assert len(calls) == 2


def test_importer_html_to_guide_accepts_admin_token_without_session(monkeypatch):
    captured = {}

    def fake_generate_html_import_yaml_with_ai(**kwargs):
        captured["generate"] = kwargs
        return """guide:
  contentTitle: Imported guide
  contentType: GUIDE
  language: en-US
  firstStep:
    title: Start
    content: "<p>Imported from HTML</p>"
"""

    def fake_build(payload, *, user_id=None, stonly_client=None):
        captured["build"] = {
            "yaml": payload.yaml,
            "teamId": payload.creds.teamId,
            "folderId": payload.folderId,
            "publish": payload.publish,
            "user_id": user_id,
            "team_id": getattr(stonly_client, "team_id", None),
            "user": getattr(stonly_client, "user", None),
            "password": getattr(stonly_client, "password", None),
        }
        return {"ok": True, "guideId": "g-1"}

    monkeypatch.setattr(main, "generate_html_import_yaml_with_ai", fake_generate_html_import_yaml_with_ai)
    monkeypatch.setattr(main, "api_build_guide", fake_build)

    with TestClient(main.app) as raw_client:
        r = raw_client.post(
            "/api/importer/html-to-guide",
            headers={"x-admin-token": "secret"},
            json={
                "teamId": 39539,
                "teamToken": "importer-team-token",
                "folderId": 2000,
                "html": "<html><head><title>Imported Doc</title></head><body><h1>Hello</h1></body></html>",
                "aiModel": "gpt51",
                "publish": True,
                "documentName": "Forced title",
            },
        )

    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["authMode"] == "admin_token"
    assert body["modelUsed"] == "gpt51"
    assert captured["generate"]["ai_model"] == "gpt51"
    assert captured["generate"]["content_title"] == "Forced title"
    assert captured["generate"]["document_name"] == "Forced title"
    assert captured["build"]["teamId"] == 39539
    assert captured["build"]["folderId"] == 2000
    assert captured["build"]["publish"] is True
    assert captured["build"]["user_id"] is None
    assert captured["build"]["team_id"] == 39539
    assert captured["build"]["user"] == "Importer"
    assert captured["build"]["password"] == "importer-team-token"


def test_importer_html_to_guide_requires_auth_without_session(monkeypatch):
    monkeypatch.setattr(main, "generate_html_import_yaml_with_ai", lambda **kwargs: "guide: {}")

    with TestClient(main.app) as raw_client:
        r = raw_client.post(
            "/api/importer/html-to-guide",
            json={
                "teamId": 39539,
                "folderId": 2000,
                "html": "<html><body>Hello</body></html>",
            },
        )

    assert r.status_code == 401
    assert r.json()["detail"] == "Missing or expired session"


def test_importer_html_to_guide_requires_team_token_for_admin_auth(monkeypatch):
    monkeypatch.setattr(main, "generate_html_import_yaml_with_ai", lambda **kwargs: "guide: {}")

    with TestClient(main.app) as raw_client:
        r = raw_client.post(
            "/api/importer/html-to-guide",
            headers={"Authorization": "Bearer secret"},
            json={
                "teamId": 39539,
                "folderId": 2000,
                "html": "<html><body>Hello</body></html>",
            },
        )

    assert r.status_code == 400
    assert r.json()["detail"] == "teamToken is required when using importer admin auth"


def test_html_structure_uses_selected_model_and_returns_placeholders(client, monkeypatch):
    captured = {}

    def fake_generate_html_structure_yaml_with_ai(**kwargs):
        captured.update(kwargs)
        return (
            """guide:
  contentTitle: Verification guide
  contentType: GUIDE
  language: en-US
  firstStep:
    title: Choose caller type
    content: "<p>will be replaced</p>"
    choices:
      - label: Continue
        step:
          title: Verify details
          content: "<p>also replaced</p>"
""",
            False,
        )

    monkeypatch.setattr(main, "generate_html_structure_yaml_with_ai", fake_generate_html_structure_yaml_with_ai)

    r = client.post(
        "/api/importer/html-to-guide/structure",
        json={
            "html": "<html><body><h1>Verification</h1><p>Choose a caller type.</p></body></html>",
            "documentName": "Verification",
            "outputMode": "single",
            "aiModel": "gpt51",
            "language": "en-US",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["modelUsed"] == "gpt51"
    assert body["guideCount"] == 1
    assert body["stepCount"] == 2
    assert "<p>[TO_FILL_FROM_HTML]</p>" in body["yaml"]
    assert captured["ai_model"] == "gpt51"
    assert captured["output_mode"] == "single"


def test_markdown_structure_uses_selected_model_and_returns_placeholders(client, monkeypatch):
    captured = {}

    def fake_generate_markdown_structure_yaml_with_ai(**kwargs):
        captured.update(kwargs)
        return (
            """guide:
  contentTitle: Access troubleshooting
  contentType: GUIDE
  language: en-US
  firstStep:
    title: Start here
    content: "<p>will be replaced</p>"
    choices:
      - label: Continue
        step:
          title: Next step
          content: "<p>also replaced</p>"
""",
            False,
        )

    monkeypatch.setattr(main, "generate_markdown_structure_yaml_with_ai", fake_generate_markdown_structure_yaml_with_ai)

    r = client.post(
        "/api/importer/markdown-to-guide/structure",
        json={
            "markdown": "# Hello\n\nThis is a long markdown document.",
            "documentName": "Doc name",
            "outputMode": "single",
            "aiModel": "gpt52",
            "language": "en-US",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["modelUsed"] == "gpt52"
    assert body["guideCount"] == 1
    assert body["stepCount"] == 2
    assert "<p>[TO_FILL_FROM_MARKDOWN]</p>" in body["yaml"]
    assert captured["ai_model"] == "gpt52"
    assert captured["output_mode"] == "single"


def test_html_build_retries_failed_batch_and_builds(client, monkeypatch):
    attempts = {}
    captured = {}

    def fake_generate_html_batch_content_yaml_with_ai(**kwargs):
        batch_index = kwargs["batch_index"]
        attempts[batch_index] = attempts.get(batch_index, 0) + 1
        if batch_index == 1 and attempts[batch_index] == 1:
            raise ValueError("bad yaml")
        rows = {
            "steps": [
                {"stepId": step["stepId"], "content": f"<p>HTML body for {step['stepId']}</p>"}
                for step in kwargs["batch_steps"]
            ]
        }
        return main.yaml.safe_dump(rows, sort_keys=False), False

    def fake_api_build(payload, *, user_id=None, stonly_client=None):
        captured["yaml"] = payload.yaml
        captured["publish"] = payload.publish
        captured["teamId"] = payload.creds.teamId
        captured["folderId"] = payload.folderId
        captured["user_id"] = user_id
        return {"ok": True, "guideId": "html-built"}

    monkeypatch.setattr(main, "generate_html_batch_content_yaml_with_ai", fake_generate_html_batch_content_yaml_with_ai)
    monkeypatch.setattr(main, "api_build_guide", fake_api_build)

    structure_yaml = """guide:
  contentTitle: Caller verification
  contentType: GUIDE
  language: en-US
  firstStep:
    title: Start
    content: "<p>[TO_FILL_FROM_HTML]</p>"
    choices:
      - label: Path A
        step:
          title: Applicant path
          content: "<p>[TO_FILL_FROM_HTML]</p>"
      - label: Path B
        step:
          title: Merchant path
          content: "<p>[TO_FILL_FROM_HTML]</p>"
"""
    r = client.post(
        "/api/importer/html-to-guide/build",
        json={
            "creds": {"user": "tester@example.com", "teamId": 39539, "base": "https://public.stonly.com/api/v3"},
            "folderId": 2000,
            "html": "<html><body><h1>Caller verification</h1><p>Details for each caller type.</p></body></html>",
            "structureYaml": structure_yaml,
            "aiModel": "gpt52",
            "publish": True,
            "batchSize": 2,
            "maxRetriesPerBatch": 3,
            "defaults": {"language": "en-US"},
            "documentName": "Verification.html",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["batchCount"] == 2
    assert body["modelUsed"] == "gpt52"
    assert body["progress"][0]["batch"] == 1
    assert body["progress"][0]["attempts"] == 2
    assert body["progress"][1]["batch"] == 2
    assert body["progress"][1]["attempts"] == 1
    assert "HTML body for g1-s001" in captured["yaml"]
    assert "HTML body for g1-s002" in captured["yaml"]
    assert "HTML body for g1-s003" in captured["yaml"]
    assert captured["publish"] is True


def test_markdown_build_retries_failed_batch_and_builds(client, monkeypatch):
    attempts = {}
    captured = {}

    def fake_generate_markdown_batch_content_yaml_with_ai(**kwargs):
        batch_index = kwargs["batch_index"]
        attempts[batch_index] = attempts.get(batch_index, 0) + 1
        if batch_index == 1 and attempts[batch_index] == 1:
            raise ValueError("bad yaml")
        rows = {
            "steps": [
                {"stepId": step["stepId"], "content": f"<p>Body for {step['stepId']}</p>"}
                for step in kwargs["batch_steps"]
            ]
        }
        return main.yaml.safe_dump(rows, sort_keys=False), False

    def fake_api_build(payload, *, user_id=None, stonly_client=None):
        captured["yaml"] = payload.yaml
        captured["publish"] = payload.publish
        captured["teamId"] = payload.creds.teamId
        captured["folderId"] = payload.folderId
        captured["user_id"] = user_id
        return {"ok": True, "guideId": "g-built"}

    monkeypatch.setattr(main, "generate_markdown_batch_content_yaml_with_ai", fake_generate_markdown_batch_content_yaml_with_ai)
    monkeypatch.setattr(main, "api_build_guide", fake_api_build)

    structure_yaml = """guide:
  contentTitle: Access troubleshooting
  contentType: GUIDE
  language: en-US
  firstStep:
    title: Start
    content: "<p>[TO_FILL_FROM_MARKDOWN]</p>"
    choices:
      - label: Path A
        step:
          title: Verify account
          content: "<p>[TO_FILL_FROM_MARKDOWN]</p>"
      - label: Path B
        step:
          title: Reset credentials
          content: "<p>[TO_FILL_FROM_MARKDOWN]</p>"
"""
    r = client.post(
        "/api/importer/markdown-to-guide/build",
        json={
            "creds": {"user": "tester@example.com", "teamId": 39539, "base": "https://public.stonly.com/api/v3"},
            "folderId": 2000,
            "markdown": "# Intro\n\nDetails for all steps.",
            "structureYaml": structure_yaml,
            "aiModel": "gpt51",
            "publish": True,
            "batchSize": 2,
            "maxRetriesPerBatch": 3,
            "defaults": {"language": "en-US"},
            "documentName": "Source.md",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["batchCount"] == 2
    assert body["modelUsed"] == "gpt51"
    assert body["progress"][0]["batch"] == 1
    assert body["progress"][0]["attempts"] == 2
    assert body["progress"][1]["batch"] == 2
    assert body["progress"][1]["attempts"] == 1
    assert "Body for g1-s001" in captured["yaml"]
    assert "Body for g1-s002" in captured["yaml"]
    assert "Body for g1-s003" in captured["yaml"]
    assert captured["publish"] is True


class RecordingGuideBuilderStonly:
    def __init__(self):
        self.append_calls = []
        self.link_calls = []

    def create_guide(self, **kwargs):
        return {"guideId": "g-1", "firstStepId": "s-1", "raw": kwargs}

    def append_step(self, **kwargs):
        self.append_calls.append(kwargs)
        return {"stepId": f"s-{len(self.append_calls) + 1}", "raw": kwargs}

    def link_steps(self, **kwargs):
        self.link_calls.append(kwargs)
        return {"raw": kwargs}


def test_build_one_guide_omits_append_position_when_choice_targets_end():
    definition = main.GuideDefinition(
        contentTitle="AccurisTech Login Help",
        contentType="GUIDE",
        language="en",
        firstStep=main.GuideStep(
            title="Intro",
            content="<p>Welcome</p>",
            choices=[
                main.GuideStepChoice(
                    label="First path",
                    position=1,
                    step=main.GuideStep(title="A", content="<p>A</p>"),
                ),
                main.GuideStepChoice(
                    label="Second path",
                    position=2,
                    step=main.GuideStep(title="B", content="<p>B</p>"),
                ),
                main.GuideStepChoice(
                    label="Third path",
                    position=2,
                    step=main.GuideStep(title="C", content="<p>C</p>"),
                ),
            ],
        ),
    )
    st = RecordingGuideBuilderStonly()

    result = main._build_one_guide(
        st=st,
        team_id=39539,
        folder_id=2000,
        definition=definition,
        dry_run=False,
        publish=False,
    )

    assert [call["position"] for call in st.append_calls] == [None, None, None]
    assert [step["position"] for step in result["steps"][1:]] == [None, None, None]


def test_build_one_guide_keeps_insert_position_for_deferred_link():
    definition = main.GuideDefinition(
        contentTitle="Deferred link ordering",
        contentType="GUIDE",
        language="en",
        firstStep=main.GuideStep(
            title="Intro",
            content="<p>Welcome</p>",
            choices=[
                main.GuideStepChoice(label="Go to future", position=0, ref="future"),
                main.GuideStepChoice(
                    label="Current branch",
                    position=1,
                    step=main.GuideStep(
                        title="Current branch",
                        content="<p>Current</p>",
                        choices=[
                            main.GuideStepChoice(
                                label="Define future",
                                step=main.GuideStep(
                                    key="future",
                                    title="Future step",
                                    content="<p>Future</p>",
                                ),
                            )
                        ],
                    ),
                ),
            ],
        ),
    )
    st = RecordingGuideBuilderStonly()

    result = main._build_one_guide(
        st=st,
        team_id=39539,
        folder_id=2000,
        definition=definition,
        dry_run=False,
        publish=False,
    )

    assert [call["position"] for call in st.append_calls] == [None, None]
    assert [call["position"] for call in st.link_calls] == [0]
    assert result["links"][0]["position"] == 0


# --- Guide export ---------------------------------------------------------

EDITOR_URL = "https://app.stonly.com/app/guide/U9RM3Ewtgo/editor/101"
EXPORT_FOLDER = 2000
CONVERTED_MARKER = "Converted from"


def _export(client, creds, **overrides):
    body = {"creds": creds, "guide": EDITOR_URL, "folderId": EXPORT_FOLDER}
    body.update(overrides)
    return client.post("/api/guides/export", json=body)


def _first_step(content):
    return yaml.safe_load(content)["guide"]["firstStep"]


def _choice(step, label):
    return next(c for c in step.get("choices") or [] if c.get("label") == label)


def _walk_steps(step, acc=None):
    acc = [] if acc is None else acc
    acc.append(step)
    for choice in step.get("choices") or []:
        if choice.get("step"):
            _walk_steps(choice["step"], acc)
    return acc


# --- YAML: the Guide Builder format, re-importable -------------------------

def test_guide_export_yaml_uses_the_guide_builder_schema(client, creds):
    r = _export(client, creds)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["reimportable"] is True
    assert data["filename"] == "stonly-guide-U9RM3Ewtgo.yaml"

    doc = yaml.safe_load(data["content"])
    assert set(doc) == {"guide"}
    guide = doc["guide"]
    assert guide["contentTitle"] == "Machine installation"
    assert guide["contentType"] == "GUIDE"
    assert guide["language"] == "en"
    first = guide["firstStep"]
    assert first["title"] == "Overview"
    # step content stays HTML, which is what the build API expects
    assert first["content"].startswith("<h3>Intro</h3>")
    assert "<strong>safety notes</strong>" in first["content"]
    assert [c["label"] for c in first["choices"]] == ["Unload", "Report a problem", "Skip"]


def test_guide_export_yaml_is_reimportable(client, creds):
    """The export must parse straight back through the build endpoint's parser."""
    content = _export(client, creds).json()["content"]
    items = main.parse_guides_multi(content, main.GuideDefaults())
    assert len(items) == 1
    definition = items[0]["definition"]
    assert definition.contentTitle == "Machine installation"
    assert definition.contentType == "GUIDE"
    assert definition.firstStep.title == "Overview"
    assert len(definition.firstStep.choices) == 3
    # every step in the tree carries a title and content
    for step in _walk_steps(_first_step(content)):
        assert step["title"].strip()
        assert step["content"].strip()


def test_guide_export_yaml_reimports_through_the_build_endpoint(client, creds):
    content = _export(client, creds).json()["content"]
    r = client.post("/api/guides/build", json={
        "creds": creds,
        "folderId": EXPORT_FOLDER,
        "yaml": content,
        "dryRun": True,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["summary"]["stepCount"] == 5


def test_guide_export_yaml_batch_is_multi_document_and_reimportable(client, creds):
    r = client.post("/api/guides/export", json={
        "creds": creds,
        "guides": [EDITOR_URL, "GRAPHGUIDE"],
        "folderId": EXPORT_FOLDER,
    })
    assert r.status_code == 200, r.text
    content = r.json()["content"]
    assert len(list(yaml.safe_load_all(content))) == 2
    items = main.parse_guides_multi(content, main.GuideDefaults())
    assert [i["definition"].contentTitle for i in items] == ["Machine installation", "Graph guide"]


def test_guide_export_yaml_keeps_a_traceable_header(client, creds):
    content = _export(client, creds).json()["content"]
    header = [line for line in content.split("\n") if line.startswith("#")]
    assert any("U9RM3Ewtgo" in line for line in header)
    assert any("contentType" in line for line in header)
    assert any("tags" in line for line in header)  # the fixture's first step has tags


def test_guide_export_yaml_converts_special_steps_with_a_note(client, creds):
    content = _export(client, creds).json()["content"]
    steps = {s["title"]: s for s in _walk_steps(_first_step(content))}

    ticket = steps["Submit a ticket"]
    assert CONVERTED_MARKER in ticket["content"]
    assert '"Contact form"' in ticket["content"]
    assert "Email address" in ticket["content"]          # form fields are listed
    assert "Thanks!" in ticket["content"]
    assert "<p>Fill in the form.</p>" in ticket["content"]  # original content kept

    embedded = steps["Embedded"]
    assert '"Embedded guide"' in embedded["content"]
    assert "OTHERGUIDE" in embedded["content"]
    assert "900" in embedded["content"]

    # a step with no content at all still gets valid content
    assert steps["Done"]["content"].strip()


def test_guide_export_yaml_notes_modules_on_regular_steps(client, creds):
    content = _export(client, creds).json()["content"]
    steps = {s["title"]: s for s in _walk_steps(_first_step(content))}
    unload = steps["Unload"]
    assert "extra modules" in unload["content"]
    assert "Resolution notes" in unload["content"]
    assert "longText" in unload["content"]
    assert "required" in unload["content"]
    assert "<p>Use a forklift.</p>" in unload["content"]


def test_guide_export_yaml_rebuilds_loops_and_shared_steps_with_refs(client, creds):
    data = _export(client, creds, guide="GRAPHGUIDE").json()
    content = data["content"]
    guide = yaml.safe_load(content)["guide"]
    first = guide["firstStep"]

    # untitled first step falls back to the guide name
    assert guide["contentTitle"] == "Graph guide"
    assert first["title"] == "Graph guide"
    # the first step is linked back to, so it is addressable
    assert first["key"]

    left = _choice(first, "Left")["step"]
    right = _choice(first, "Right")["step"]
    assert left["title"] == "Left branch"
    # the loop back to the first step is a ref, not a copy
    assert _choice(left, "Back to start")["ref"] == first["key"]
    # the shared step is created once and linked from the other branch
    shared = _choice(left, "Shared")["step"]
    assert shared["title"] == "Shared wrap up"
    assert shared["key"]
    assert right["choices"][0]["ref"] == shared["key"]
    # unlabelled transitions get a usable label
    assert right["choices"][0]["label"] == "Next"

    # the unreachable step is kept, flagged, and reported
    orphan = _choice(first, "[Unlinked] Detached note")["step"]
    assert orphan["title"] == "Detached note"
    assert any("not reachable" in w for w in data["warnings"])
    assert any("no label" in w for w in data["warnings"])

    # and it all still parses as builder YAML
    items = main.parse_guides_multi(content, main.GuideDefaults())
    assert items[0]["definition"].firstStep.key == first["key"]


def test_guide_export_yaml_drops_transitions_with_no_target(client, creds):
    data = _export(client, creds).json()
    assert any("pointed to no step" in w for w in data["warnings"])
    unload = {s["title"]: s for s in _walk_steps(_first_step(data["content"]))}["Unload"]
    assert not unload.get("choices")


# --- Markdown / JSON: the documentation view ------------------------------

def test_guide_export_markdown_uses_markdown_step_content(client, creds):
    r = _export(client, creds, format="markdown")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["reimportable"] is False
    assert data["filename"].endswith(".md")
    content = data["content"]
    assert content.startswith("---")
    assert "# Machine installation" in content
    assert "## Flow" in content
    assert "--[Unload]--> `102`" in content
    assert "## Step 1 — Overview" in content
    assert "### Intro" in content                     # HTML converted to Markdown
    assert "**safety notes**" in content
    assert "[pallet](https://x.test/p)" in content
    assert "<h3>" not in content


def test_guide_export_json_uses_markdown_step_content(client, creds):
    r = _export(client, creds, format="json")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["filename"].endswith(".json")
    doc = json.loads(data["content"])
    assert doc["guide"]["id"] == "U9RM3Ewtgo"
    assert doc["guide"]["contentFormat"] == "markdown"
    assert len(doc["steps"]) == 5
    first = doc["steps"][0]
    assert "### Intro" in first["content"]
    assert first["nextSteps"][0] == {"label": "Unload", "stepId": 102, "stepTitle": "Unload"}
    # modules are exposed as data here rather than as notes
    unload = next(s for s in doc["steps"] if s["title"] == "Unload")
    assert unload["modules"][0]["type"] == "INPUT"
    embedded = next(s for s in doc["steps"] if s["title"] == "Embedded")
    assert embedded["embeddedGuide"] == {"guideId": "OTHERGUIDE", "stepId": 900}


# --- Fallbacks, errors, guide picker --------------------------------------

def test_guide_export_accepts_id_and_public_url(client, creds):
    assert _export(client, creds, guide="U9RM3Ewtgo").status_code == 200
    r = _export(client, creds, guide="https://stonly.com/kb/guide/en/machine-install-U9RM3Ewtgo/Steps/101")
    assert r.status_code == 200
    assert r.json()["requestedGuides"] == ["U9RM3Ewtgo"]


def test_guide_export_batch_skips_invalid_reference(client, creds):
    r = client.post("/api/guides/export", json={
        "creds": creds,
        "guides": [EDITOR_URL, "DRAFTGUIDE", "###"],
        "folderId": EXPORT_FOLDER,
    })
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["requestedGuides"] == ["U9RM3Ewtgo", "DRAFTGUIDE"]
    assert data["filename"] == "stonly-guides-2.yaml"
    assert any("###" in w for w in data["warnings"])


def test_guide_export_falls_back_to_saved_version_for_drafts(client, creds):
    r = _export(client, creds, guide="DRAFTGUIDE")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["guides"][0]["version"] == "last_saved_version"
    assert any("last published" in w for w in data["warnings"])


def test_guide_export_falls_back_when_language_missing(client, creds):
    r = _export(client, creds, guide="DRAFTGUIDE", language="de")
    assert r.status_code == 200, r.text
    assert any("'de' is not available" in w for w in r.json()["warnings"])


def test_guide_export_unknown_guide_returns_404(client, creds):
    r = _export(client, creds, guide="NOPE123")
    assert r.status_code == 404, r.text
    assert r.json()["detail"]["failures"][0]["guideId"] == "NOPE123"


def test_guide_export_requires_a_guide_reference(client, creds):
    assert client.post("/api/guides/export", json={"creds": creds}).status_code == 422


def test_guide_export_rejects_unknown_format(client, creds):
    assert _export(client, creds, format="pdf").status_code == 422


def test_guide_export_requires_session(creds):
    from fastapi.testclient import TestClient
    with TestClient(main.app) as anonymous:
        r = anonymous.post("/api/guides/export", json={"creds": creds, "guide": EDITOR_URL})
    assert r.status_code == 401


def test_guides_list_returns_picker_items(client, creds):
    r = client.get(f"/api/guides/list?teamId={creds['teamId']}&folderId={EXPORT_FOLDER}")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["folderId"] == EXPORT_FOLDER
    assert data["count"] == 3
    assert data["truncated"] is False
    item = next(i for i in data["items"] if i["id"] == "U9RM3Ewtgo")
    assert item["name"] == "Machine installation"
    assert item["status"] == "published"
    assert item["folderName"] == "Guides"
    assert item["languages"] == ["en", "fr"]


def test_guides_list_can_filter_status(client, creds):
    r = client.get(f"/api/guides/list?teamId={creds['teamId']}&folderId={EXPORT_FOLDER}&status=draft")
    assert r.status_code == 200
    assert [i["id"] for i in r.json()["items"]] == ["DRAFTGUIDE"]


def test_guides_list_rejects_bad_status(client, creds):
    r = client.get(f"/api/guides/list?teamId={creds['teamId']}&folderId={EXPORT_FOLDER}&status=archived")
    assert r.status_code == 400


def test_guides_list_requires_folder_without_root(client, creds):
    assert client.get(f"/api/guides/list?teamId={creds['teamId']}").status_code == 400


# --- Units ----------------------------------------------------------------

def test_extract_guide_id_variants():
    assert main._extract_guide_id("https://app.stonly.com/app/guide/U9RM3Ewtgo/editor/4999083") == "U9RM3Ewtgo"
    assert main._extract_guide_id("app.stonly.com/app/guide/abc123/editor") == "abc123"
    assert main._extract_guide_id("https://stonly.com/kb/guide/en/some-slug-6h5WT6zwzA/Steps/85968") == "6h5WT6zwzA"
    assert main._extract_guide_id("https://x.test/anything?guideId=Zz99aa") == "Zz99aa"
    assert main._extract_guide_id("  U9RM3Ewtgo  ") == "U9RM3Ewtgo"
    assert main._extract_guide_id("203") == "203"
    assert main._extract_guide_id("not an id!") is None
    assert main._extract_guide_id("") is None


def test_step_html_to_markdown_handles_stonly_content():
    md = main._step_html_to_markdown(
        "<h4>Title</h4><p>Text with <em>emphasis</em>.</p>"
        "<aside class=\"warning\"><p>Careful now</p></aside>"
        "<ol><li>First<ul><li>Nested</li></ul></li><li>Second</li></ol>"
        "<table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>"
        "<pre><code>run me</code></pre>"
        "<p><img src=\"https://x.test/i.png\" alt=\"Shot\"></p>"
    )
    assert "#### Title" in md
    assert "*emphasis*" in md
    assert "> **Warning**\n> Careful now" in md
    assert "1. First" in md
    assert "  - Nested" in md
    assert "| A | B |" in md
    assert "| --- | --- |" in md
    assert "```\nrun me\n```" in md
    assert "![Shot](https://x.test/i.png)" in md
    # inline images encoded as data URIs are not dumped into the export
    assert "<inline-data-omitted>" in main._step_html_to_markdown(
        '<p><img src="data:image/png;base64,AAAABBBB" alt="x"></p>'
    )


def test_step_html_to_markdown_passes_through_plain_text():
    assert main._step_html_to_markdown("https://x.test/a") == "https://x.test/a"
    assert main._step_html_to_markdown("") == ""
    assert main._step_html_to_markdown(None) == ""


def test_data_view_yaml_keeps_multiline_blocks_readable():
    document = main._build_guide_export_document(
        guide_id="ABC",
        team_id=1,
        steps=[{"id": 1, "title": "T", "content": "<p>One</p><p>Two</p>", "type": "regular",
                "isFirstStep": True, "nextSteps": [], "tags": []}],
        guide_modules=[],
        meta={},
        applied={"language": "en", "version": "last_published_version", "purpose": "EXPORT"},
        content_format="markdown",
        include_modules=False,
    )
    text = main._guide_export_yaml([document])
    assert "content: |-" in text
    assert yaml.safe_load(text)["steps"][0]["content"] == "One\n\nTwo"


def test_builder_document_handles_structured_step_content():
    document, warnings, stats = main._build_guide_builder_document(
        guide_id="ABC",
        team_id=1,
        steps=[{"id": 1, "title": "Close", "content": {"type": "CLOSE_WIDGET", "value": {}},
                "type": "widgetAction", "isFirstStep": True, "nextSteps": [], "tags": []}],
        meta={},
        applied={"language": "en", "version": "last_saved", "purpose": "BPA"},
    )
    first = document["guide"]["firstStep"]
    assert "CLOSE_WIDGET" in first["content"]
    assert '"Widget action"' in first["content"]
    assert stats["convertedSteps"] == 1
    # renders and re-parses
    text = main._render_guide_export(
        [{"builderDocument": document, "builderHeader": main._builder_yaml_header(stats)}], "yaml"
    )
    assert main.parse_guides_multi(text, main.GuideDefaults())[0]["definition"].firstStep.title == "Close"


def test_builder_document_requires_steps():
    with pytest.raises(HTTPException):
        main._build_guide_builder_document(
            guide_id="ABC", team_id=1, steps=[], meta={},
            applied={"language": "en", "version": "last_saved", "purpose": "BPA"},
        )
