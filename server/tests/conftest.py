import os
import sys
import pathlib
import types
import pytest
import uuid

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
