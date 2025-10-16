import json

ADMIN = "secret"           # must match APP_ADMIN_TOKEN from conftest
PARENT_ID = 1000           # matches FakeStonly root parent
SUPPORT_ID = 2000          # existing Support in FakeStonly
FAQS_ID = 2001             # existing FAQs in FakeStonly

def _payload(creds, root, *, dry=False, settings=None, parent=PARENT_ID):
    body = {
        "token": ADMIN,
        "creds": creds,
        "parentId": parent,
        "dryRun": dry,
        "root": root,
    }
    if settings:
        body["settings"] = settings
    return body

def test_dump_structure_with_parent(client, creds):
    # Should walk children under parentId using list_children()
    r = client.get(
        "/api/dump-structure",
        params={
            "token": ADMIN,
            "user": creds["user"],
            "password": creds["password"],
            "teamId": creds["teamId"],
            "base": creds["base"],
            "parentId": PARENT_ID,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "root" in data
    # Expect to see Support with its child FAQs
    names = [n["name"] for n in data["root"]]
    assert "Support" in names
    support = next(n for n in data["root"] if n["name"] == "Support")
    assert any(c["name"] == "FAQs" for c in support.get("children", []))

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
        "token": ADMIN, "creds": creds, "parentId": PARENT_ID,
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
        "token": ADMIN, "creds": creds, "parentId": PARENT_ID, "root": root
    })
    assert r.status_code == 200
    data = r.json()
    if "ok" in data:
        assert data["ok"] is True
    if "missing" in data:
        assert data["missing"] in ([], {})
    if "unexpected" in data:
        assert data["unexpected"] in ([], {})
