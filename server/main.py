from __future__ import annotations
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
import os, time

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests

# ---- Config ----
STONLY_BASE = os.getenv("STONLY_BASE", "https://public.stonly.com/api/v3").rstrip("/")
STONLY_USER = os.getenv("STONLY_USER")
STONLY_PASS = os.getenv("STONLY_PASS")
TEAM_ID     = os.getenv("TEAM_ID")
ADMIN_TOKEN = os.getenv("APP_ADMIN_TOKEN")

if not all([STONLY_USER, STONLY_PASS, TEAM_ID, ADMIN_TOKEN]):
    raise RuntimeError("Missing env: STONLY_USER, STONLY_PASS, TEAM_ID, APP_ADMIN_TOKEN")

app = FastAPI(title="Stonly Web Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ---- Auth guard ----
def ensure_admin(auth_header: Optional[str]):
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(401, detail="Missing bearer token")
    token = auth_header.split(" ", 1)[1]
    if token != ADMIN_TOKEN:
        raise HTTPException(403, detail="Invalid token")

# ---- Client API Stonly ----
class Stonly:
    def __init__(self):
        self.s = requests.Session()
        self.s.auth = (STONLY_USER, STONLY_PASS)
        self.s.headers.update({"Content-Type": "application/json"})

    def _req(self, method: str, path: str, *, params=None, json=None):
        url = f"{STONLY_BASE}{path}"
        p = {**(params or {}), "teamId": TEAM_ID}
        backoff = 1.0
        for _ in range(5):
            r = self.s.request(method, url, params=p, json=json, timeout=30)
            if r.status_code in (429,500,502,503,504):
                time.sleep(backoff)
                backoff = min(backoff * 2, 10)
                continue
            if not r.ok:
                try:
                    msg = r.json()
                except Exception:
                    msg = r.text
                raise HTTPException(r.status_code, detail={"error": msg})
            return r.json() if r.headers.get("content-type","" ).startswith("application/json") else r.text

    def list_children(self, parent_id: Optional[int]):
        # endpoint paginé /folder avec entityName/entityId selon ton instance
        if parent_id is None:
            # fallback structure à la racine → liste plate, on filtrera côté appelant si besoin
            data = self._req("GET", "/folder/structure")
            items = data.get("items") if isinstance(data, dict) else []
            return items or []
        page, limit, acc = 1, 100, []
        while True:
            data = self._req("GET", "/folder", params={"folderId": parent_id, "page": page, "limit": limit})
            items = []
            if isinstance(data, dict):
                items = data.get("items") or []
            elif isinstance(data, list):
                items = data
            acc.extend(items)
            if len(items) < limit:
                break
            page += 1
        return acc

    def create_folder(self, name: str, parent_id: Optional[int]):
        body = {"name": name}
        if parent_id is not None:
            body["parentFolderId"] = int(parent_id)
        data = self._req("POST", "/folder", json=body)
        return int(data.get("folderId"))

    def get_structure_flat(self, parent_id: Optional[int]):
        data = self._req("GET", "/folder/structure", params={"folderId": parent_id} if parent_id else None)
        items = data.get("items") if isinstance(data, dict) else []
        return items or []

# ---- modèles ----
class UINode(BaseModel):
    name: str
    children: list["UINode"] = []

UINode.model_rebuild()

class ApplyPayload(BaseModel):
    token: str
    parentId: Optional[int] = None
    dryRun: bool = False
    root: list[UINode]

class VerifyPayload(BaseModel):
    token: str
    parentId: Optional[int] = None
    root: list[UINode]

# ---- util ----
def extract_name_id(obj: dict) -> tuple[Optional[str], Optional[int]]:
    if not isinstance(obj, dict):
        return None, None
    name = None
    for k in ("name","folderName","title","label","displayName","entityName"):
        if obj.get(k):
            name = obj[k]; break
    _id = None
    for k in ("folderId","id","folder_id","entityId"):
        if obj.get(k) is not None:
            try: _id = int(obj[k]); break
            except Exception: pass
    return name, _id

def build_path(parent: str, name: str) -> str:
    return f"{parent}/{name}" if parent else f"/{name}"

# ---- endpoints ----
@app.post("/api/apply")
def api_apply(payload: ApplyPayload, authorization: Optional[str] = Header(None)):
    ensure_admin(f"Bearer {payload.token}")  # token passé côté client
    st = Stonly()
    mapping: Dict[str, int] = {}

    def list_index(pid: Optional[int]) -> Dict[str, dict]:
        items = st.list_children(pid)
        idx: Dict[str, dict] = {}
        for it in items:
            nm, _id = extract_name_id(it)
            if nm:
                idx[nm] = {"raw": it, "id": _id}
        return idx

    def dfs(nodes: List[UINode], pid: Optional[int], ppath: str):
        idx = list_index(pid)
        for n in nodes:
            fp = build_path(ppath, n.name)
            if n.name in idx:
                fid = idx[n.name]["id"]
            else:
                if payload.dryRun:
                    fid = -1
                else:
                    fid = st.create_folder(n.name, pid)
            if fid != -1:
                mapping[fp] = int(fid)
            if n.children:
                dfs(n.children, None if fid == -1 else fid, fp)

    dfs(payload.root, payload.parentId, "")
    return {"ok": True, "mapping": mapping}

@app.post("/api/verify")
def api_verify(payload: VerifyPayload):
    ensure_admin(f"Bearer {payload.token}")
    st = Stonly()

    expected = []
    def collect_expected(nodes: List[UINode], p: str):
        for n in nodes:
            fp = build_path(p, n.name)
            expected.append(fp)
            if n.children:
                collect_expected(n.children, fp)
    collect_expected(payload.root, "")

    real = []
    def walk(pid: Optional[int], p: str):
        items = st.list_children(pid)
        for it in items:
            nm, _id = extract_name_id(it)
            if not nm: continue
            fp = build_path(p, nm)
            real.append(fp)
            if _id is not None:
                walk(_id, fp)
    walk(payload.parentId, "")

    missing = sorted(set(expected) - set(real))
    extra   = sorted(set(real) - set(expected))
    return {"ok": True, "missing": missing, "extra": extra}

@app.get("/api/dump-structure")
def api_dump(parentId: Optional[int] = None, token: Optional[str] = None):
    ensure_admin(f"Bearer {token}")
    st = Stonly()
    items = st.get_structure_flat(parentId)

    # Reconstituer l'arbre [ {name, children} ]
    by_id: Dict[int, Dict[str, Any]] = {}
    children_map: Dict[int, list] = {}
    for it in items:
        _id = it.get("id") or it.get("entityId")
        _nm = it.get("name") or it.get("entityName")
        _pid = it.get("parentId")
        if _id is None: continue
        _id = int(_id)
        by_id[_id] = {"name": _nm, "children": []}
        if _pid is not None:
            children_map.setdefault(int(_pid), []).append(_id)

    for pid, kids in children_map.items():
        parent_node = by_id.get(pid)
        if not parent_node: continue
        for kid in kids:
            if kid in by_id:
                parent_node["children"].append(by_id[kid])

    roots = []
    if parentId is not None and int(parentId) in by_id:
        roots = by_id[int(parentId)].get("children", [])
    else:
        parent_ids = {int(it["parentId"]) for it in items if it.get("parentId") is not None}
        roots = [by_id[i] for i in by_id.keys() if i not in parent_ids]

    return {"root": roots}