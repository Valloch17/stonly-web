import os
import sys
import pathlib
import types
import pytest
import uuid
from fastapi import HTTPException

# --- 1) Set required env BEFORE importing main.py ---
os.environ.setdefault("APP_ADMIN_TOKEN", "secret")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("TEAM_TOKEN_ENCRYPTION_KEY", "5hG9nZrX2R3wVd0R1S6eKXrFz0K8Q1m2YtZp4x9JZ9k=")
os.environ.setdefault("SESSION_COOKIE_SECURE", "0")

# --- 2) Make import work whether pytest is run at repo root or in server/ ---
ROOT = pathlib.Path(__file__).resolve().parents[1]     # .../server
REPO = ROOT.parent                                     # repo root
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))
if str(REPO) not in sys.path:
    sys.path.append(str(REPO))

# Try both import styles
try:
    import server.main as main  # when running from repo root
except ModuleNotFoundError:
    import main as main         # when running from server/

# server/tests/conftest.py (remplace la classe FakeStonly par cette version)

_SHARED = {
    "nodes_by_parent": {
        1000: [{"id": 2000, "name": "Support", "parentId": 1000}],
        2000: [{"id": 2001, "name": "FAQs",    "parentId": 2000}],
    },
    "created": [],
}


# --- Guide export fixtures -------------------------------------------------
# Three guides: a published one with branching/special steps, a draft that only exists as a
# saved version, and a graph one (loop, shared step, orphan, unlabelled transition).
_EXPORT_GUIDES = {
    "U9RM3Ewtgo": {
        "name": "Machine installation",
        "status": "published",
        "languages": ["en", "fr"],
        "published": [
            {
                "id": 101,
                "title": "Overview",
                "content": "<h3>Intro</h3><p>Read the <strong>safety notes</strong> before starting.</p>"
                           "<ul><li>Wear gloves</li><li>Check the <a href=\"https://x.test/p\">pallet</a></li></ul>",
                "type": "regular",
                "isFirstStep": True,
                "nextSteps": [
                    {"choiceLabel": "Unload", "id": 102},
                    {"choiceLabel": "Report a problem", "id": 104},
                    {"choiceLabel": "Skip", "id": 103},
                ],
                "tags": ["Install", "Safety"],
            },
            {
                "id": 102,
                "title": "Unload",
                "content": "<p>Use a forklift.</p>",
                "type": "regular",
                "isFirstStep": False,
                "nextSteps": [{"choiceLabel": "", "id": None}],
                "tags": [],
                "modules": [{
                    "type": "INPUT",
                    "properties": {"key": "notes", "subtype": "longText", "isRequired": True},
                    "content": {"label": "Resolution notes"},
                }],
            },
            {
                "id": 103,
                "title": "Embedded",
                "content": "OTHERGUIDE",
                "type": "embeddedContent",
                "isFirstStep": False,
                "nextSteps": [],
                "tags": [],
                "meta": {"embeddedGuideId": "OTHERGUIDE", "embeddedStepId": 900},
            },
            {
                "id": 104,
                "title": "Submit a ticket",
                "content": "<p>Fill in the form.</p>",
                "type": "contactForm",
                "isFirstStep": False,
                "nextSteps": [{"choiceLabel": "", "id": 105}],
                "tags": [],
                "modules": [
                    {"type": "FORM", "properties": {}, "content": {"successMessage": "Thanks!"}},
                    {"type": "INPUT", "properties": {"key": "email", "subtype": "email", "isRequired": True},
                     "content": {"label": "Email address"}},
                ],
            },
            {
                "id": 105,
                "title": "Done",
                "content": "",
                "type": "endGuide",
                "isFirstStep": False,
                "nextSteps": [],
                "tags": [],
            },
        ],
    },
    "DRAFTGUIDE": {
        "name": "Draft only",
        "status": "draft",
        "languages": ["en"],
        "saved": [
            {
                "id": 201,
                "title": "Draft step",
                "content": "<p>Work in progress</p>",
                "type": "regular",
                "isFirstStep": True,
                "nextSteps": [],
                "tags": [],
            }
        ],
    },
    "GRAPHGUIDE": {
        "name": "Graph guide",
        "status": "published",
        "languages": ["en"],
        "published": [
            {
                "id": 301,
                "title": "",  # untitled first step: falls back to the guide name
                "content": "<p>Start</p>",
                "type": "regular",
                "isFirstStep": True,
                "nextSteps": [
                    {"choiceLabel": "Left", "id": 302},
                    {"choiceLabel": "Right", "id": 303},
                ],
                "tags": [],
            },
            {
                "id": 302,
                "title": "Left branch",
                "content": "<p>Left</p>",
                "type": "regular",
                "isFirstStep": False,
                # shared step (also reached from 303) + a loop back to the first step
                "nextSteps": [
                    {"choiceLabel": "Shared", "id": 304},
                    {"choiceLabel": "Back to start", "id": 301},
                ],
                "tags": [],
            },
            {
                "id": 303,
                "title": "Right branch",
                "content": "<p>Right</p>",
                "type": "regular",
                "isFirstStep": False,
                "nextSteps": [{"choiceLabel": "", "id": 304}],
                "tags": [],
            },
            {
                "id": 304,
                "title": "Shared wrap up",
                "content": "<p>Shared</p>",
                "type": "regular",
                "isFirstStep": False,
                "nextSteps": [],
                "tags": [],
            },
            {
                "id": 305,
                "title": "Detached note",  # unreachable from the first step
                "content": "<p>Orphan</p>",
                "type": "regular",
                "isFirstStep": False,
                "nextSteps": [],
                "tags": [],
            },
        ],
    },
}


class FakeStonly:
    def __init__(self, base, user, password, team_id):
        self.base = base
        self.user = user
        self.password = password
        self.team_id = team_id
        self._store = _SHARED  # <-- shared state

    def get_structure_flat(self, parent_id):
        # Renvoie les éléments sous parent_id si fourni, sinon tout (à plat)
        if parent_id is not None:
            return list(self._store["nodes_by_parent"].get(int(parent_id), []))
        items = []
        for lst in self._store["nodes_by_parent"].values():
            items.extend(lst)
        return items

    def list_children(self, parent_id):
        if parent_id == -1:
            return []
        if parent_id is None:
            # ton backend prod peut exiger folderId; renvoie vide
            return []
        return list(self._store["nodes_by_parent"].get(int(parent_id), []))

    def create_folder(self, name, parent_id, *, public_access=None, language=None, description=None):
        new_id = 9000 + len(self._store["created"])
        self._store["created"].append({
            "name": name,
            "parent_id": parent_id,
            "public_access": public_access,
            "language": language,
            "description": description,
            "id": new_id,
        })
        self._store["nodes_by_parent"].setdefault(int(parent_id), []).append(
            {"id": new_id, "name": name, "parentId": int(parent_id)}
        )
        return new_id

    def list_guides_in_folder(self, folder_id, *, recursive=False, guide_status=None, limit=100, max_items=None):
        items = []
        for guide_id, guide in _EXPORT_GUIDES.items():
            if guide_status and guide["status"] != guide_status:
                continue
            items.append({
                "entityId": guide_id,
                "entityName": guide["name"],
                "entityStatus": guide["status"],
                "entityLanguages": list(guide["languages"]),
                "entityFolder": {"id": int(folder_id), "name": "Guides"},
            })
        if max_items is not None:
            items = items[:max_items]
        return items

    def export_guide(self, content_id, *, language=None, version=None, purpose=None):
        guide = _EXPORT_GUIDES.get(str(content_id))
        if not guide:
            raise HTTPException(404, detail={"upstream": {"message": "Not Found"}})
        if language and language not in guide["languages"]:
            raise HTTPException(404, detail={"upstream": {"message": "Language not found"}})
        if version in (None, "last_published_version"):
            steps = guide.get("published")
            if not steps:
                raise HTTPException(404, detail={"upstream": {"message": "No published version found"}})
        else:
            steps = guide.get("saved") or guide.get("published") or []
        modules_kept = purpose == "BPA"
        cleaned = []
        for step in steps:
            copy = dict(step)
            if not modules_kept:
                copy.pop("modules", None)
            cleaned.append(copy)
        return {"steps": cleaned, "guideModules": []}

    def validate_credentials(self):
        if self.password in {"invalid-token", "bad-token"}:
            raise HTTPException(401, detail="Unauthorized")
        return True

# --- 4) Patch main.Stonly with FakeStonly for all tests ---
@pytest.fixture(autouse=True)
def patch_stonly(monkeypatch):
    monkeypatch.setattr(main, "Stonly", FakeStonly)
    yield

# --- 5) TestClient + common fixtures ---
from fastapi.testclient import TestClient

@pytest.fixture()
def client():
    with TestClient(main.app) as client:
        email = f"tester-{uuid.uuid4().hex}@example.com"
        resp = client.post("/api/signup", json={
            "email": email,
            "password": "password123",
            "adminToken": "secret",
        })
        assert resp.status_code == 200
        resp = client.post("/api/teams", json={
            "teamId": 39539,
            "teamToken": "test-token",
            "name": "Test Team",
        })
        assert resp.status_code == 200
        yield client

@pytest.fixture()
def creds():
    return {
        "user": "tester@example.com",
        "teamId": 39539,
        "base": "https://public.stonly.com/api/v3",
    }
