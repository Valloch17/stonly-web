import json
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
