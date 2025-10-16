from __future__ import annotations
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
import os, time

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests

# ---- Config ----

ADMIN_TOKEN = os.getenv("APP_ADMIN_TOKEN")
if not ADMIN_TOKEN:
    raise RuntimeError("Missing env: APP_ADMIN_TOKEN")

# IMPORTANT : ne pas exiger STONLY_USER/PASS/TEAM_ID ici.
# Ils arrivent depuis le frontend dans chaque requête (payload ou query).


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
    def __init__(self, *, base: str, user: str, password: str, team_id: int):
        self.base = base.rstrip("/")
        self.team_id = int(team_id)
        self.s = requests.Session()
        self.s.auth = (user, password)
        self.s.headers.update({"Content-Type": "application/json"})

    def _req(self, method: str, path: str, *, params=None, json=None):
        url = f"{self.base}{path}"
        p = {**(params or {}), "teamId": self.team_id}
        backoff = 1.0
        for _ in range(5):
            r = self.s.request(method, url, params=p, json=json, timeout=30)
            if r.status_code in (429,500,502,503,504):
                time.sleep(backoff); backoff = min(backoff*2, 10); continue
            if not r.ok:
                try: msg = r.json()
                except Exception: msg = r.text
                raise HTTPException(r.status_code, detail={"error": msg})
            return r.json() if r.headers.get("content-type","").startswith("application/json") else r.text

# ---- modèles ----
class UINode(BaseModel):
    name: str
    children: list["UINode"] = []

UINode.model_rebuild()

class Creds(BaseModel):
    user: str
    password: str
    teamId: int
    base: Optional[str] = "https://public.stonly.com/api/v3"  # optionnel

class UINode(BaseModel):
    name: str
    children: list["UINode"] = []
UINode.model_rebuild()

class ApplyPayload(BaseModel):
    token: str
    creds: Creds
    parentId: Optional[int] = None
    dryRun: bool = False
    root: list[UINode]

class VerifyPayload(BaseModel):
    token: str
    creds: Creds
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
    ensure_admin(f"Bearer {payload.token}")  # ton APP_ADMIN_TOKEN côté serveur
    st = Stonly(base=payload.creds.base, user=payload.creds.user,
                password=payload.creds.password, team_id=payload.creds.teamId)
    # ... reste inchangé (list_children/create_folder/DFS)

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
    st = Stonly(base=payload.creds.base, user=payload.creds.user,
                password=payload.creds.password, team_id=payload.creds.teamId)
    # ... reste inchangé (collect expected vs real)


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
def api_dump(parentId: Optional[int] = None, token: Optional[str] = None,
             user: Optional[str] = None, password: Optional[str] = None,
             teamId: Optional[int] = None, base: Optional[str] = "https://public.stonly.com/api/v3"):
    ensure_admin(f"Bearer {token}")
    if not all([user, password, teamId]):
        raise HTTPException(400, "user, password, teamId are required")
    st = Stonly(base=base, user=user, password=password, team_id=int(teamId))
    items = st.get_structure_flat(parentId)
    # ... reconstruction de l’arbre comme avant, puis return {"root": roots}


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