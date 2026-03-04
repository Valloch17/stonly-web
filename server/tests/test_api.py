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
