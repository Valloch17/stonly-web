from __future__ import annotations
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
import os, time

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
import requests
import yaml
import uuid


import logging, logging.handlers

LOG_FILE = os.getenv("LOG_FILE", "logs/guide_builder.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logger = logging.getLogger("stonly")
logger.setLevel(logging.DEBUG)

fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s :: %(message)s")
fh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
fh.setFormatter(fmt)
sh = logging.StreamHandler()
sh.setFormatter(fmt)

# Avoid duplicate handlers when hot-reloading
if not logger.handlers:
    logger.addHandler(fh)
    logger.addHandler(sh)

# Turn up HTTP client logging when HTTP_DEBUG=1
logging.getLogger("urllib3").setLevel(logging.DEBUG if os.getenv("HTTP_DEBUG") == "1" else logging.INFO)



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

from fastapi import Query
from fastapi.responses import PlainTextResponse
import os, itertools, collections

LOG_FILE = os.getenv("LOG_FILE", "logs/guide_builder.log")

@app.get("/api/debug/logs", response_class=PlainTextResponse)
def tail_logs(lines: int = Query(300, ge=1, le=5000)):
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            buf = collections.deque(f, maxlen=lines)
        return "".join(buf)
    except FileNotFoundError:
        return "No log file yet."


from fastapi.responses import JSONResponse
import traceback

def mask_secret(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:3]}***{value[-2:]}"

@app.exception_handler(Exception)
async def unhandled_exc(_, exc: Exception):
    # Evite les 500 silencieux : log + payload JSON simple
    logger.exception("Unhandled error")
    return JSONResponse(
        status_code=500,
        content={"ok": False, "error": str(exc), "type": exc.__class__.__name__},
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
        self.s.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def get_structure_flat(self, parent_id: Optional[int]):
        """
        Appelle GET /folder/structure (payload 'flat' observé : { items: [{id,name,parentId}, ...] }).
        Retourne toujours une list (ou []).
        """
        params = {"folderId": parent_id} if parent_id is not None else None
        data = self._req("GET", "/folder/structure", params=params)
        # format attendu: dict { items: [...] }
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return data["items"]
        # certains tenants peuvent renvoyer directement une liste
        if isinstance(data, list):
            return data
        # fallback: rien d'exploitable
        return []

    def list_children(self, parent_id: Optional[int]) -> list[dict]:
        """
        Liste les enfants d'un dossier.
        - parent_id == -1  : sentinel dry-run -> aucun appel réseau, retourne []
        - parent_id is None: (tenant qui exige folderId) -> retourne [] pour éviter 400
        - sinon            : /folder paginé avec ?folderId=...
        """
        # ✅ dry-run sentinel : pas d'appel API
        if parent_id == -1:
            return []

        # ⚠️ ton tenant exige folderId -> pas d'appel /folder/structure ici
        if parent_id is None:
            return []

        # enfants du parent via /folder
        page, limit, acc = 1, 100, []
        while True:
            data = self._req("GET", "/folder", params={"folderId": int(parent_id), "page": page, "limit": limit})
            if isinstance(data, dict):
                items = data.get("items") or []
            elif isinstance(data, list):
                items = data
            else:
                items = []
            acc.extend(items)
            if len(items) < limit:
                break
            page += 1
        return acc



    def _req(self, method: str, path: str, *, params=None, json=None):
        url = f"{self.base}{path}"
        p = {**(params or {}), "teamId": self.team_id}
        backoff = 1.0
        for _ in range(5):
            r = self.s.request(method, url, params=p, json=json, timeout=30)
            # log minimal
            # Just before returning/raising inside _req(...)
            logger.info("REQ %s %s params=%s status=%s json=%s",
                        method, r.url, p, r.status_code,
                        json if method in ("POST","PUT","PATCH") else None)

            if not r.ok:
                try:
                    detail = r.json()
                except Exception:
                    detail = {"text": r.text[:2000]}
                logger.error("UPSTREAM ERROR %s %s -> %s", method, r.url, detail)
                raise HTTPException(r.status_code, detail={"upstream": detail, "url": str(r.url)})

            # Also guard the 200-with-error-body edge case:
            if r.headers.get("content-type", "").startswith("application/json"):
                data = r.json()
                if isinstance(data, dict) and (
                    str(data.get("status", "")).lower().startswith("bad request")
                    or data.get("error") is True
                    or str(data.get("message", "")).lower().startswith("bad request")
                ):
                    logger.error("UPSTREAM LOGICAL ERROR %s %s -> %s", method, r.url, data)
                    raise HTTPException(400, detail={"upstream": data, "url": str(r.url)})
                logger.debug("RESP %s %s -> %s", method, r.url, data)
                return data

            logger.debug("RESP %s %s (non-json) -> %s", method, r.url, r.text[:500])
            return r.text


        raise HTTPException(502, detail={"error": "Too many retries", "url": url})

    def create_guide(
        self,
        *,
        folder_id: int,
        content_type: str,
        content_title: str,
        first_step_title: str,
        content: str,
        language: str,
        media: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "folderId": int(folder_id),
            "contentType": content_type,
            "contentTitle": content_title,
            "firstStepTitle": first_step_title,
            "content": content,
            "language": language,
        }
        if media is not None:
            body["media"] = media
        logger.info("GUIDE create payload=%s", body)
        data = self._req("POST", "/guide", json=body)
        if not isinstance(data, dict):
            raise HTTPException(502, detail={"error": "Unexpected response creating guide", "payload": data})
        guide_id = data.get("guideId") or data.get("id") or data.get("entityId") or data.get("guid")
        first_step_id = data.get("firstStepId") or data.get("stepId")
        if first_step_id is None and isinstance(data.get("firstStep"), (int, str)):
            first_step_id = data.get("firstStep")
        if guide_id is None or first_step_id is None:
            raise HTTPException(502, detail={
                "error": "Missing identifiers from create guide response",
                "payload": data
            })
        return {"guideId": guide_id, "firstStepId": first_step_id, "raw": data}

    def append_step(
        self,
        *,
        guide_id: str,
        parent_step_id: Any,
        title: str,
        content: str,
        language: str,
        choice_label: Optional[str] = None,
        position: Optional[int] = None,
        media: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "guideId": guide_id,
            "parentStepId": parent_step_id,
            "title": title,
            "content": content,
            "language": language,
        }
        if choice_label is not None:
            body["choiceLabel"] = choice_label
        if position is not None:
            body["position"] = position
        if media is not None:
            body["media"] = media
        logger.info("GUIDE append payload=%s", body)
        data = self._req("POST", "/guide/step", json=body)
        if not isinstance(data, dict):
            raise HTTPException(502, detail={"error": "Unexpected response appending step", "payload": data})
        step_id = data.get("stepId") or data.get("id") or data.get("entityId")
        if step_id is None:
            raise HTTPException(502, detail={"error": "Missing stepId from append step response", "payload": data})
        return {"stepId": step_id, "raw": data}

    def create_folder(
        self,
        name: str,
        parent_id: Optional[int],
        *,
        public_access: Optional[int] = None,
        language: Optional[str] = None,
        description: Optional[str] = None,
    ) -> int:
        """
        Crée un dossier. Supporte parentFolderId, publicAccess, language, description.
        Essaie d'abord le payload 'canonique', puis fallback si besoin.
        """
        def _make_body(var_name_for_parent: str):
            body = {"name": name}
            if parent_id is not None:
                body[var_name_for_parent] = int(parent_id)  # "parentFolderId" ou "parentId"
            if public_access in (0, 1):
                body["publicAccess"] = int(public_access)
            if language:
                body["language"] = str(language)
            if description:
                body["description"] = str(description)
            return body

        # Variante 1: parentFolderId (spec canonique)
        try:
            data = self._req("POST", "/folder", json=_make_body("parentFolderId"))
            fid = data.get("folderId") or data.get("id") or data.get("entityId")
            return int(fid)
        except HTTPException as e1:
            # Variante 2: parentId
            try:
                data = self._req("POST", "/folder", json=_make_body("parentId"))
                fid = data.get("folderId") or data.get("id") or data.get("entityId")
                return int(fid)
            except HTTPException as e2:
                # Variante 3: parentId en query
                params3 = {"parentId": int(parent_id)} if parent_id is not None else None
                body3 = _make_body("parentFolderId")
                body3.pop("parentFolderId", None)
                try:
                    data = self._req("POST", "/folder", params=params3, json=body3)
                    fid = data.get("folderId") or data.get("id") or data.get("entityId")
                    return int(fid)
                except HTTPException as e3:
                    raise HTTPException(e3.status_code, detail={
                        "error": "create_folder failed",
                        "attempts": [
                            {"variant": "parentFolderId", "detail": getattr(e1, "detail", str(e1))},
                            {"variant": "parentId", "detail": getattr(e2, "detail", str(e2))},
                            {"variant": "parentId(query)", "detail": getattr(e3, "detail", str(e3))}
                        ]
                    })


# ---- modèles ----

class Creds(BaseModel):
    user: str
    password: str
    teamId: int
    base: Optional[str] = "https://public.stonly.com/api/v3"

class UINode(BaseModel):
    name: str
    description: Optional[str] = None
    children: List["UINode"] = Field(default_factory=list)

# Rebuild recursive refs
UINode.model_rebuild()

class Settings(BaseModel):
    publicAccess: int = 1   # 1 = public (visible), 0 = private
    language: str = "en"    # e.g., "en", "fr", ...

class GuideDefaults(BaseModel):
    contentTitle: Optional[str] = None
    contentType: str = "GUIDE"
    language: str = "en-US"

class GuideStepChoice(BaseModel):
    label: Optional[str] = None
    position: Optional[int] = None
    step: "GuideStep"

class GuideStep(BaseModel):
    title: str
    content: str
    language: Optional[str] = None
    media: List[str] = Field(default_factory=list)
    position: Optional[int] = None
    choices: List["GuideStepChoice"] = Field(default_factory=list)

    @field_validator("media")
    @classmethod
    def media_limit(cls, v: List[str]):
        if len(v) > 3:
            raise ValueError("media accepts up to 3 URLs")
        return v

class GuideDefinition(BaseModel):
    contentTitle: str
    contentType: str = "GUIDE"
    language: str = "en-US"
    firstStep: GuideStep

GuideStepChoice.model_rebuild()
GuideStep.model_rebuild()
GuideDefinition.model_rebuild()

class ApplyPayload(BaseModel):
    token: str
    creds: Creds
    parentId: Optional[int] = None
    dryRun: bool = False
    root: List[UINode]
    settings: Optional[Settings] = None

class VerifyPayload(BaseModel):
    token: str
    creds: Creds
    parentId: Optional[int] = None
    root: List[UINode]

class GuideBuildPayload(BaseModel):
    token: str
    creds: Creds
    folderId: int
    yaml: str
    dryRun: bool = False
    defaults: GuideDefaults = GuideDefaults()



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

def parse_guide_yaml(source: str, defaults: GuideDefaults) -> GuideDefinition:
    text = (source or "").strip()
    if not text:
        raise HTTPException(400, detail={"error": "YAML payload is required"})
    try:
        data = yaml.safe_load(text)
    except Exception as e:
        raise HTTPException(400, detail={"error": "Invalid YAML", "message": str(e)})
    if not isinstance(data, dict):
        raise HTTPException(400, detail={"error": "YAML root must be a mapping"})
    guide_data = data.get("guide") if isinstance(data.get("guide"), dict) else data
    if not isinstance(guide_data, dict):
        raise HTTPException(400, detail={"error": "Missing guide object"})
    first_step_raw = guide_data.get("firstStep")
    if not isinstance(first_step_raw, dict):
        raise HTTPException(400, detail={"error": "guide.firstStep must be an object"})
    first_step = GuideStep.model_validate(first_step_raw)
    content_title = guide_data.get("contentTitle") or defaults.contentTitle or first_step.title
    if not content_title:
        raise HTTPException(400, detail={"error": "Missing contentTitle for guide"})
    content_type = guide_data.get("contentType") or defaults.contentType or "GUIDE"
    language = guide_data.get("language") or defaults.language or first_step.language or "en-US"
    return GuideDefinition(
        contentTitle=content_title,
        contentType=content_type,
        language=language,
        firstStep=first_step,
    )

# ---- endpoints ----
@app.post("/api/apply")
def api_apply(payload: ApplyPayload, authorization: Optional[str] = Header(None)):
    ensure_admin(f"Bearer {payload.token}")
    st = Stonly(base=payload.creds.base, user=payload.creds.user,
                password=payload.creds.password, team_id=payload.creds.teamId)
    mapping: Dict[str, int] = {}

    # valeurs globales
    s = getattr(payload, "settings", None) or Settings()


    def path_join(p, n): return f"{p}/{n}" if p else f"/{n}"

    def list_index(pid: Optional[int]) -> Dict[str, dict]:
        items = st.list_children(pid)
        idx: Dict[str, dict] = {}
        for it in items:
            nm = it.get("name") or it.get("entityName")
            _id = it.get("folderId") or it.get("id") or it.get("entityId")
            if nm:
                try: _id = int(_id) if _id is not None else None
                except: _id = None
                idx[nm] = {"id": _id, "raw": it}
        return idx

    def dfs(nodes: List[UINode], pid: Optional[int], ppath: str):
        idx = list_index(pid)
        for n in nodes:
            if not n.name or not str(n.name).strip():
                raise HTTPException(400, detail={"error": "Empty folder name in payload", "path": ppath})

            fp = f"{ppath}/{n.name}" if ppath else f"/{n.name}"

            if n.name in idx:
                fid = idx[n.name]["id"]
            else:
                if payload.dryRun:
                    fid = -1
                else:
                    try:
                        desc = getattr(n, "description", None)
                        fid = st.create_folder(
                            n.name, pid,
                            public_access=s.publicAccess,
                            language=s.language,
                            description=desc,   # <-- utilise la description si fournie
                        )
                    except HTTPException as e:
                        # bubble up with extra context
                        raise HTTPException(e.status_code, detail={
                            "error": "create_folder failed",
                            "path": fp,
                            "name": n.name,
                            "upstream": getattr(e, "detail", str(e)),
                        })

            # ✅ Renseigner le mapping même en dry-run
            if fid == -1:
                mapping[fp] = "(dry-run)"   # ou None si tu préfères
            elif fid is not None:
                mapping[fp] = int(fid)

            next_pid = -1 if fid == -1 else fid
            if n.children:
                dfs(n.children, next_pid, fp)


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


@app.post("/api/guides/build")
def api_build_guide(payload: GuideBuildPayload):
    request_id = str(uuid.uuid4())
    logger.info("REQUEST %s :: /api/guides/build", request_id)
    def _log(prefix, msg):
        logger.info("%s %s :: %s", prefix, request_id, msg)


    ensure_admin(f"Bearer {payload.token}")
    definition = parse_guide_yaml(payload.yaml, payload.defaults)

    logger.info(
        "GUIDE build start dryRun=%s team=%s folder=%s contentTitle=%s firstStep=%s",
        payload.dryRun,
        payload.creds.teamId,
        payload.folderId,
        definition.contentTitle,
        definition.firstStep.title,
    )
    logger.debug(
        "GUIDE creds user=%s base=%s",
        mask_secret(payload.creds.user),
        payload.creds.base,
    )

    st = Stonly(
        base=payload.creds.base,
        user=payload.creds.user,
        password=payload.creds.password,
        team_id=payload.creds.teamId
    )

    dry_run = bool(payload.dryRun)
    folder_id = int(payload.folderId)

    steps_created: List[Dict[str, Any]] = []
    if dry_run:
        guide_id: Any = "dry-run-guide"
        first_step_id: Any = "dry-step-1"
        steps_created.append({
            "title": definition.firstStep.title,
            "stepId": first_step_id,
            "parent": None,
            "choiceLabel": None,
        })
    else:
        try:
            created = st.create_guide(
                folder_id=folder_id,
                content_type=definition.contentType,
                content_title=definition.contentTitle,
                first_step_title=definition.firstStep.title,
                content=definition.firstStep.content,
                language=definition.firstStep.language or definition.language,
                media=definition.firstStep.media,
            )
        except Exception:
            logger.exception(
                "GUIDE create failed folder=%s title=%s",
                folder_id,
                definition.contentTitle,
            )
            raise
        guide_id = created["guideId"]
        first_step_id = created["firstStepId"]
        steps_created.append({
            "title": definition.firstStep.title,
            "stepId": first_step_id,
            "parent": None,
            "choiceLabel": None,
        })
        logger.info(
            "GUIDE created guideId=%s firstStepId=%s",
            guide_id,
            first_step_id,
        )

    counter = len(steps_created)
    queue: List[Tuple[GuideStepChoice, str, str, Any, int]] = []
    for idx, choice in enumerate(definition.firstStep.choices):
        queue.append((choice, f"firstStep.choices[{idx}]", definition.firstStep.title, first_step_id, idx))

    while queue:
        choice, path, parent_title, parent_step_id, choice_index = queue.pop(0)
        step = choice.step
        language = step.language or definition.language
        position_value = choice.position if choice.position is not None else (
            step.position if step.position is not None else choice_index
        )

        if dry_run:
            counter += 1
            step_id = f"dry-step-{counter}"
        else:
            try:
                appended = st.append_step(
                    guide_id=guide_id,
                    parent_step_id=parent_step_id,
                    title=step.title,
                    content=step.content,
                    language=language,
                    choice_label=choice.label,
                    position=position_value,
                    media=step.media,
                )
            except Exception:
                logger.exception(
                    "GUIDE append failed guideId=%s parentStepId=%s title=%s",
                    guide_id,
                    parent_step_id,
                    step.title,
                )
                raise
            step_id = appended["stepId"]

        steps_created.append({
            "title": step.title,
            "stepId": step_id,
            "parent": parent_title,
            "parentPath": path,
            "choiceLabel": choice.label,
            "position": position_value,
        })
        logger.info(
            "GUIDE step appended guideId=%s parent=%s step=%s stepId=%s dryRun=%s position=%s",
            guide_id,
            parent_title,
            step.title,
            step_id,
            dry_run,
            position_value,
        )

        for idx, child in enumerate(step.choices):
            queue.append((child, f"{path}.step.choices[{idx}]", step.title, step_id, idx))

    logger.info(
        "GUIDE build complete guideId=%s dryRun=%s steps=%s",
        guide_id,
        dry_run,
        len(steps_created),
    )

    return {
        "ok": True,
        "dryRun": dry_run,
        "guideId": guide_id,
        "firstStepId": first_step_id,
        "steps": steps_created,
        "summary": {
            "stepCount": len(steps_created),
            "branchCount": max(len(steps_created) - 1, 0),
        }
    }

@app.get("/api/dump-structure")
def api_dump(
    token: str,
    user: str,
    password: str,
    teamId: int,
    parentId: Optional[int] = None,
    base: str = "https://public.stonly.com/api/v3",
):
    ensure_admin(f"Bearer {token}")
    st = Stonly(base=base, user=user, password=password, team_id=int(teamId))

    try:
        items = st.get_structure_flat(parentId)
        if not isinstance(items, list):
            # Fallback: essaye /folder si structure est atypique
            items = st.list_children(parentId)
            if not isinstance(items, list):
                raise HTTPException(502, detail={"error": "Unexpected payload from Stonly", "payload_type": type(items).__name__})
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("dump-structure upstream/parse error")
        raise HTTPException(502, detail={"error": "Upstream/parse error", "msg": str(e)})

    # Reconstituer l'arbre
    by_id, children_map = {}, {}
    for it in items:
        if not isinstance(it, dict):
            continue
        _id = it.get("id") or it.get("entityId")
        _nm = it.get("name") or it.get("entityName")
        _pid = it.get("parentId")
        if _id is None:
            continue
        try:
            _id = int(_id)
        except Exception:
            continue
        by_id[_id] = {"name": _nm, "children": []}
        if _pid is not None:
            try:
                children_map.setdefault(int(_pid), []).append(_id)
            except Exception:
                pass

    for pid, kids in children_map.items():
        parent_node = by_id.get(pid)
        if not parent_node: 
            continue
        for kid in kids:
            if kid in by_id:
                parent_node["children"].append(by_id[kid])

    if parentId is not None and int(parentId) in by_id:
        roots = by_id[int(parentId)].get("children", [])
    else:
        parent_ids = {int(it["parentId"]) for it in items if isinstance(it, dict) and it.get("parentId") is not None}
        roots = [by_id[i] for i in by_id.keys() if i not in parent_ids]

    return {"root": roots}


@app.get("/api/ping")
def ping():
    return {"ok": True}




if __name__ == "__main__":
    import argparse, json
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Build a Stonly guide from YAML (local runner).")
    parser.add_argument("yaml_file", help="Path to guide YAML")
    parser.add_argument("--dry-run", action="store_true", help="Do not call Stonly, just parse/show payloads")
    args = parser.parse_args()

    # Pull creds/config from env
    admin_token = os.getenv("APP_ADMIN_TOKEN")
    user = os.getenv("STONLY_USER")
    password = os.getenv("STONLY_PASSWORD")
    team_id = int(os.getenv("TEAM_ID", "0") or "0")
    folder_id = int(os.getenv("FOLDER_ID", "0") or "0")

    if not all([admin_token, user, password, team_id, folder_id]):
        raise SystemExit("Missing one of: APP_ADMIN_TOKEN, STONLY_USER, STONLY_PASSWORD, TEAM_ID, FOLDER_ID")

    yaml_text = Path(args.yaml_file).read_text(encoding="utf-8")

    payload = GuideBuildPayload(
        token=admin_token,
        creds=Creds(user=user, password=password, teamId=team_id),
        folderId=folder_id,
        yaml=yaml_text,
        dryRun=bool(args.dry_run),
        defaults=GuideDefaults(),
    )

    # Call the same function the API uses so behavior matches /api/guides/build
    out = api_build_guide(payload)
    print(json.dumps(out, indent=2))
