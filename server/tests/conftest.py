import os
import types
import pytest
from fastapi.testclient import TestClient
import server.main as main

@pytest.fixture(autouse=True)
def set_admin_env(monkeypatch):
    # Make sure admin token is predictable for tests
    monkeypatch.setenv("APP_ADMIN_TOKEN", "secret")
    yield
    os.environ.pop("APP_ADMIN_TOKEN", None)

class FakeStonly:
    """
    A fake Stonly client capturing calls and returning predictable data.
    It emulates both /folder (children) and /folder/structure behaviors.
    """
    def __init__(self, base, user, password, team_id):
        self.base = base
        self.user = user
        self.password = password
        self.team_id = team_id
        self.created = []  # list of dict(name, parent_id, public_access, language, description)
        # Build a small in-memory tree to emulate existing folders
        # Using ids for nodes: parent 1000 -> Support (2000) -> FAQs (2001)
        self.nodes_by_parent = {
            1000: [  # children of parentId=1000
                {"id": 2000, "name": "Support", "parentId": 1000},
            ],
            2000: [
                {"id": 2001, "name": "FAQs", "parentId": 2000},
            ],
        }

    # ---- API surface expected by main.py ----
    def get_structure_flat(self, parent_id):
        # For these tests we mostly rely on list_children recursion,
        # but return a flattened structure when parent_id is None if called.
        items = []
        for lst in self.nodes_by_parent.values():
            items.extend(lst)
        return items

    def list_children(self, parent_id):
        # Support sentinel -1 (dry-run) => no remote calls
        if parent_id == -1:
            return []
        # None should return [] in our backend (tenant requires folderId)
        if parent_id is None:
            return []
        return self.nodes_by_parent.get(int(parent_id), [])

    def create_folder(self, name, parent_id, *, public_access=None, language=None, description=None):
        # emulate ID allocation and keep track of what we were asked to create
        new_id = 9000 + len(self.created)
        self.created.append({
            "name": name,
            "parent_id": parent_id,
            "public_access": public_access,
            "language": language,
            "description": description,
            "id": new_id,
        })
        # also store into tree so subsequent list_children sees it
        self.nodes_by_parent.setdefault(int(parent_id), []).append(
            {"id": new_id, "name": name, "parentId": int(parent_id)}
        )
        return new_id

@pytest.fixture(autouse=True)
def patch_stonly(monkeypatch):
    # Replace the real Stonly client with our fake for all tests
    monkeypatch.setattr(main, "Stonly", FakeStonly)
    yield

@pytest.fixture()
def client():
    return TestClient(main.app)

@pytest.fixture()
def creds():
    # Minimal valid credentials (the FakeStonly ignores auth anyway)
    return {
        "user": "tester@example.com",
        "password": "x",
        "teamId": 39539,
        "base": "https://public.stonly.com/api/v3",
    }
