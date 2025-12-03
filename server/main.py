from __future__ import annotations
from typing import List, Optional, Dict, Any, Tuple
import re
from dataclasses import dataclass, field
import os, time, html, ipaddress

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
try:
    # pydantic v2
    from pydantic import model_validator  # type: ignore
except Exception:  # pragma: no cover - fallback (older pydantic)
    def model_validator(*args, **kwargs):  # type: ignore
        def deco(f):
            return f
        return deco
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

# Session / cookie configuration (admin login)
SESSION_COOKIE_NAME = "st_session"
SESSION_TTL_SECONDS = int(os.getenv("SESSION_COOKIE_TTL", "259200"))  # 72h default
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "1") != "0"
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "none")

# Stockage en mémoire des sessions : session_id -> timestamp d'expiration
SESSIONS: Dict[str, float] = {}

# IMPORTANT : ne pas exiger STONLY_USER/PASS/TEAM_ID ici.
# Ils arrivent depuis le frontend dans chaque requête (payload ou query).


tags_metadata = [
    {"name": "Health", "description": "Health and readiness probes"},
    {"name": "Debug", "description": "Diagnostics and server logs"},
    {"name": "Structure", "description": "Folder and tree operations"},
    {"name": "Builder", "description": "Build/verify/apply guide trees"},
]

app = FastAPI(
    title="Stonly Web Backend",
    openapi_tags=tags_metadata,
    swagger_ui_parameters={"docExpansion": "list", "defaultModelsExpandDepth": -1},
)

ALLOW_LOCAL_TESTING_MODE = os.getenv("AI_ALLOW_TESTING_MODE", "1") != "0"

# CORS : autoriser seulement les frontends connus (+ localhost optionnel)
FRONTEND_ORIGINS = [
    "https://api-stonly-internal.onrender.com",
    "https://ai-builder.stonly.com",
]
if os.getenv("CORS_ALLOW_LOCALHOST") == "1":
    FRONTEND_ORIGINS.extend(
        [
            "http://localhost",
            "http://localhost:3000",
            "http://localhost:5173",
            "http://localhost:4173",
            "http://127.0.0.1:8000",
        ]
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi import Query
from fastapi.responses import PlainTextResponse
import os, itertools, collections

LOG_FILE = os.getenv("LOG_FILE", "logs/guide_builder.log")

@app.get("/api/debug/logs", response_class=PlainTextResponse, tags=["Debug"], summary="Tail server logs")
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


def shorten_for_log(text: Any, limit: int = 50) -> Any:
    """
    Truncate long step/content strings for logs so we don't dump full HTML.
    Non-string values are returned unchanged.
    """
    if not isinstance(text, str):
        return text
    s = text.replace("\n", " ").strip()
    if len(s) <= limit:
        return s
    return s[:limit] + "…"


def shorten_payload_for_log(obj: Any) -> Any:
    """
    Best-effort truncation of large HTML/text fields in request/response
    payloads. Only shortens keys whose name contains 'content'.
    """
    if not isinstance(obj, dict):
        return obj
    out: Dict[str, Any] = {}
    for k, v in obj.items():
        if isinstance(v, str) and "content" in str(k).lower():
            out[k] = shorten_for_log(v)
        else:
            out[k] = v
    return out

@app.exception_handler(Exception)
async def unhandled_exc(_, exc: Exception):
    # Evite les 500 silencieux : log + payload JSON simple
    logger.exception("Unhandled error")
    return JSONResponse(
        status_code=500,
        content={"ok": False, "error": str(exc), "type": exc.__class__.__name__},
    )


def _create_session() -> str:
    sid = uuid.uuid4().hex
    SESSIONS[sid] = time.time() + SESSION_TTL_SECONDS
    return sid


def _clear_session(session_id: str) -> None:
    SESSIONS.pop(session_id, None)


def _has_valid_session(request: Optional[Request]) -> bool:
    if request is None:
        return False
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if not sid:
        return False
    expires_at = SESSIONS.get(sid)
    now = time.time()
    if not expires_at or expires_at < now:
        SESSIONS.pop(sid, None)
        return False
    return True


# ---- Auth guard ----
def ensure_admin(
    auth_header: Optional[str] = None,
    *,
    request: Optional[Request] = None,
    token: Optional[str] = None,
) -> None:
    # Allow bearer token via incoming request headers when not explicitly provided
    if auth_header is None and request is not None:
        auth_header = request.headers.get("Authorization")

    # 1) Session via cookie
    if _has_valid_session(request):
        return

    # 2) Fallback : jeton brut (header ou payload)
    candidate: Optional[str] = None
    if token:
        candidate = token
    elif auth_header:
        if not auth_header.startswith("Bearer "):
            raise HTTPException(401, detail="Missing bearer token")
        candidate = auth_header.split(" ", 1)[1]

    if not candidate:
        raise HTTPException(401, detail="Missing admin token or session")
    if candidate != ADMIN_TOKEN:
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

    def publish_guides(self, guide_ids: list[str]):
            payload = {"guideList": [{"guideId": gid} for gid in guide_ids]}
            return self._req(
                "POST",
                "/guide/publish",
                params={"teamId": self.team_id},
                json=payload,
            )

    def list_guides_in_folder(
        self,
        folder_id: int,
        *,
        recursive: bool = False,
        guide_status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List guides inside a folder (optionally recursive) using GET /folder/guide.
        Paginates until the server stops returning more items.
        """
        page = 1
        acc: List[Dict[str, Any]] = []
        limit = max(1, min(int(limit or 100), 100))
        while True:
            params = {
                "folderId": int(folder_id),
                "page": page,
                "limit": limit,
                "recursive": "true" if recursive else "false",
            }
            if guide_status:
                params["guideStatus"] = guide_status

            data = self._req("GET", "/folder/guide", params=params)
            items = []
            has_next = False
            if isinstance(data, dict):
                items = data.get("items") or []
                has_next = bool(data.get("existsNext"))
            elif isinstance(data, list):
                items = data
                has_next = len(items) >= limit

            acc.extend(items)
            if not has_next or len(items) < limit:
                break
            page += 1
        return acc

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
            log_json = shorten_payload_for_log(json) if method in ("POST", "PUT", "PATCH") else None
            logger.info(
                "REQ %s %s params=%s status=%s json=%s",
                method,
                r.url,
                p,
                r.status_code,
                log_json,
            )

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
                logger.debug("RESP %s %s -> %s", method, r.url, shorten_payload_for_log(data))
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
        if media:
            body["media"] = media

        body_log = dict(body)
        body_log["content"] = shorten_for_log(body_log.get("content"))
        logger.info("GUIDE create payload=%s", body_log)
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
        if media:
            body["media"] = media

        body_log = dict(body)
        body_log["content"] = shorten_for_log(body_log.get("content"))
        logger.info("GUIDE append payload=%s", body_log)
        data = self._req("POST", "/guide/step", json=body)
        if not isinstance(data, dict):
            raise HTTPException(502, detail={"error": "Unexpected response appending step", "payload": data})
        step_id = data.get("stepId") or data.get("id") or data.get("entityId")
        if step_id is None:
            raise HTTPException(502, detail={"error": "Missing stepId from append step response", "payload": data})
        return {"stepId": step_id, "raw": data}

    def link_steps(
        self,
        *,
        guide_id: str,
        source_step_id: Any,
        target_step_id: Any,
        choice_label: Optional[str] = None,
        position: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create a navigation link from an existing source step to an existing
        target step. Mirrors POST /guide/step/link.
        """
        body = {
            "guideId": guide_id,
            "sourceStepId": source_step_id,
            "targetStepId": target_step_id,
        }
        if choice_label is not None:
            body["choiceLabel"] = choice_label
        if position is not None:
            body["position"] = position

        logger.info("GUIDE link payload=%s", body)
        data = self._req("POST", "/guide/step/link", json=body)
        # Stonly may not return identifiers here; forward raw payload
        if not isinstance(data, (dict, list, str)):
            data = {"raw": data}
        return {"raw": data}

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
    user: str = "Undefined"
    password: str
    teamId: int
    base: Optional[str] = "https://public.stonly.com/api/v3"

    @field_validator("user", mode="before")
    @classmethod
    def default_user(cls, v):
        s = str(v).strip() if v is not None else ""
        return s or "Undefined"

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
    # Either create a new step or link to an existing one by key
    step: Optional["GuideStep"] = None
    ref: Optional[str] = None

    @model_validator(mode="after")
    def validate_step_or_ref(self):
        has_step = self.step is not None
        has_ref = isinstance(self.ref, str) and bool(self.ref.strip())
        if has_step == has_ref:  # both or none
            raise ValueError("Each choice must define either 'step' or 'ref' (but not both)")
        # normalize ref
        if has_ref:
            self.ref = self.ref.strip()
        return self

class GuideStep(BaseModel):
    title: str
    content: str
    language: Optional[str] = None
    media: List[str] = Field(default_factory=list)
    position: Optional[int] = None
    # Optional key to make this step addressable for reuse (linking)
    key: Optional[str] = None
    choices: List["GuideStepChoice"] = Field(default_factory=list)

    @field_validator("content", mode="before")
    @classmethod
    def content_normalize(cls, v):
        # Normalize HTML content early so payloads and logs have clean markup
        try:
            return normalize_html_content(v)
        except Exception:
            return v if isinstance(v, str) else str(v or "")

    @field_validator("media", mode="before")
    @classmethod
    def media_coerce_and_clip(cls, v):
        # Accept str or list; normalize to list[str]
        if v is None or v == "":
            return []
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, list):
            return []
        # drop non-string entries, strip spaces
        v = [str(x).strip() for x in v if isinstance(x, (str, bytes))]
        # Be permissive: keep any non-empty URL-like strings.
        # Some CDN/image hosts may not expose a clean file extension.
        v = [u for u in v if u]
        # clip to 3 per Stonly API
        return v[:3]

    @field_validator("media")
    @classmethod
    def media_limit(cls, v: List[str]):
        if len(v) > 3:
            raise ValueError("media accepts up to 3 URLs")
        return v

    @field_validator("key", mode="before")
    @classmethod
    def key_clean(cls, v):
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        # Keep simple slug-like keys; allow dashes/underscores
        return s

class GuideDefinition(BaseModel):
    contentTitle: str
    contentType: str = "GUIDE"
    language: str = "en-US"
    firstStep: GuideStep

GuideStepChoice.model_rebuild()
GuideStep.model_rebuild()
GuideDefinition.model_rebuild()

class PublishDraftsPayload(BaseModel):
    token: Optional[str] = None
    creds: Creds
    folderId: int
    includeSubfolders: bool = True
    limit: int = Field(default=100, ge=1, le=100)

class ApplyPayload(BaseModel):
    token: Optional[str] = None
    creds: Creds
    parentId: Optional[int] = None
    dryRun: bool = False
    root: List[UINode]
    settings: Optional[Settings] = None

class VerifyPayload(BaseModel):
    token: Optional[str] = None
    creds: Creds
    parentId: Optional[int] = None
    root: List[UINode]

class GuideBuildPayload(BaseModel):
    token: Optional[str] = None
    creds: Creds
    folderId: int
    yaml: str
    dryRun: bool = False
    defaults: GuideDefaults = GuideDefaults()
    publish: bool = False


class AIGuidePayload(BaseModel):
    token: Optional[str] = None
    prompt: str = ""
    teamId: int
    folderId: int
    teamToken: str
    publish: bool = False
    dryRun: bool = False
    base: Optional[str] = "https://public.stonly.com/api/v3"
    previewOnly: bool = False
    baseYaml: Optional[str] = None
    refinePrompt: Optional[str] = None
    yamlOverride: Optional[str] = None
    testingMode: bool = False

    @field_validator("prompt")
    @classmethod
    def prompt_required(cls, v: str):
        text = (v or "").strip()
        if len(text) > 8000:
            raise ValueError("prompt is too long (max 8000 characters)")
        return text

    @field_validator("teamToken")
    @classmethod
    def team_token_required(cls, v: str):
        text = (v or "").strip()
        if not text:
            raise ValueError("teamToken is required")
        return text

    @field_validator("base")
    @classmethod
    def base_default(cls, v: Optional[str]):
        s = (v or "").strip()
        return s or "https://public.stonly.com/api/v3"

    @field_validator("baseYaml", "yamlOverride", mode="before")
    @classmethod
    def trim_yaml(cls, v):
        if v is None:
            return None
        s = str(v)
        return s.strip()


class LoginPayload(BaseModel):
    token: str



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

def normalize_html_content(html: Optional[str]) -> str:
    """Normalize HTML minimally to remove YAML-induced newlines without
    altering intended spaces around inline tags.

    Rules:
    - Normalize CR/CRLF to LF.
    - Trim leading/trailing whitespace and EOL spaces.
    - If there is no <pre>/<code>/<textarea>, replace newline runs with a single space.
    - Do NOT remove spaces around tags (avoid changing text like `</strong> Do <strong>`).
    """
    if html is None:
        return ""
    s = str(html)

    # Normalize line endings
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # Replace NBSP with regular space
    s = s.replace("\u00A0", " ")
    # Trim end-of-line spaces introduced by YAML formatting
    s = re.sub(r"[ \t]+\n", "\n", s)
    # Collapse multiple blank lines to a single newline
    s = re.sub(r"\n{2,}", "\n", s)

    # If no block-preserving tags, convert newline runs to a single space
    # Note: inline <code> should NOT prevent newline collapsing
    if not re.search(r"<\s*(pre|textarea)\b", s, re.I):
        s = re.sub(r"\s*\n\s*", " ", s)

    # Collapse whitespace strictly BETWEEN tags (does not affect text near tags)
    s = re.sub(r">\s+<", "><", s)

    # Trim outer whitespace only
    s = s.strip()
    return s


def strip_code_fences(text: str) -> str:
    """Remove common Markdown fences/backticks the model may emit."""
    if not text:
        return ""
    s = text.strip()
    # Remove ```yaml ... ``` or ``` ... ``` fences
    s = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    return s.strip()


def sanitize_titles_and_labels(defn: "GuideDefinition") -> "GuideDefinition":
    """Replace ':' in titles/labels with '-' to avoid YAML/parse issues."""
    defn.contentTitle = (defn.contentTitle or "").replace(":", "-")

    def walk_step(step: "GuideStep"):
        step.title = (step.title or "").replace(":", "-")
        for ch in step.choices or []:
            if ch.label:
                ch.label = ch.label.replace(":", "-")
            if ch.step:
                walk_step(ch.step)

    walk_step(defn.firstStep)
    return defn


def clamp_positions(defn: "GuideDefinition") -> "GuideDefinition":
    """Ensure choice positions are within valid bounds per parent."""
    def walk(step: "GuideStep"):
        if step.choices:
            max_idx = max(0, len(step.choices) - 1)
            for ch in step.choices:
                if ch.position is not None:
                    ch.position = min(max(ch.position, 0), max_idx)
                if ch.step:
                    walk(ch.step)
    walk(defn.firstStep)
    return defn


def resolve_missing_refs(defn: "GuideDefinition") -> "GuideDefinition":
    """
    If a choice uses ref to a key that is never defined, convert that choice to an inline
    step with a placeholder so the build does not fail. This preserves the branching
    intent while avoiding 400s for unknown keys.
    """
    existing_keys: set[str] = set()

    def collect(step: "GuideStep"):
        if step.key:
            existing_keys.add(step.key)
        for ch in step.choices or []:
            if ch.step:
                collect(ch.step)
    collect(defn.firstStep)

    def patch(step: "GuideStep"):
        for ch in step.choices or []:
            if ch.ref and ch.ref not in existing_keys:
                # Swap ref for an inline placeholder step; register key
                missing_key = ch.ref
                ch.ref = None
                ch.step = GuideStep(
                    title=f"Placeholder for {missing_key}",
                    content="<p>Replace this placeholder with the intended step.</p>",
                    key=missing_key,
                    choices=[],
                    media=[],
                )
                existing_keys.add(missing_key)
            if ch.step:
                patch(ch.step)
    patch(defn.firstStep)
    return defn


def wrap_root_if_needed(text: str) -> str:
    """If YAML appears to be a bare guide object (contentTitle + firstStep) without a top-level 'guide:', wrap it."""
    try:
        data = yaml.safe_load(text)
    except Exception:
        return text
    if isinstance(data, dict) and "guide" not in data:
        keys = set(k.lower() for k in data.keys())
        if {"contenttitle", "firststep"} & keys:
            wrapped = {"guide": data}
            return yaml.safe_dump(wrapped, sort_keys=False)
    return text


def normalize_ai_yaml(text: str) -> str:
    """Best-effort cleanup for AI-generated YAML to reduce failures."""
    if text is None:
        return ""
    s = strip_code_fences(text)
    # Replace tabs with spaces to avoid YAML indentation errors
    s = s.replace("\t", "  ")
    # Wrap if missing top-level guide
    s = wrap_root_if_needed(s)
    return s


def serialize_items_to_yaml(items: list[dict]) -> str:
    """Serialize parsed guide items back to YAML (used for cleaned output)."""
    docs = []
    for it in items:
        definition: GuideDefinition = it["definition"]
        overrides = it.get("overrides") or {}
        doc: dict = {}
        # allowed top-level overrides
        for k in ("folderId", "folder_id", "publish", "contentType", "language"):
            if overrides.get(k) is not None:
                doc[k] = overrides[k]
        doc["guide"] = definition.model_dump(exclude_none=True)
        docs.append(doc)
    return yaml.safe_dump_all(docs, sort_keys=False)


def _load_gemini_client():
    """Import the Google GenAI client lazily to avoid hard dependency at import."""
    try:
        from google import genai  # type: ignore
        from google.genai import types  # type: ignore
    except Exception:
        raise HTTPException(
            500,
            detail={
                "error": "Missing dependency for Gemini",
                "hint": "Install google-genai>=0.3.0 on the server",
            },
        )

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise HTTPException(500, detail={"error": "Missing env: GEMINI_API_KEY"})

    client = genai.Client(api_key=api_key)
    return client, types


SYSTEM_PROMPT = """You are a GUIDE GENERATOR for Stonly. OUTPUT ONLY VALID STONLY GUIDE YAML based on the user request — NO prose, NO Markdown fences, NO code blocks.

ROLE & STYLE:
- Impersonate a KNOWLEDGE MANAGER who builds step-by-step guides and articles for a knowledge base.
- Create DECISION TREES with branching steps; branches can REJOIN via key/ref.
- Produce BEAUTIFUL, LOGICAL content with rich HTML: <p>, <ul>/<ol>, tables (no <thead>/<tbody>), emojis, <aside class="tip|warning">, inline <code>. Prefer <h4>/<h5> over <h3>.

OUTPUT RULES (MUST FOLLOW):
- CONTENT TYPES: default GUIDE unless ARTICLE is clearly requested or it's a single step output; GUIDED_TOUR ONLY if explicitly asked. Articles MUST NOT use media property (inline <img> is fine).
- REQUIRED: contentTitle, contentType, language, firstStep. Steps live only under guide.firstStep/choices.
- STEP: title + HTML content; optional key (for reuse), media (<=3 URLs; ignored for ARTICLE), choices[].
- CHOICE: label?, position?, EXACTLY ONE OF step OR ref. Use key/ref for branching/rejoining; avoid one-step “Back” links.
- KEYS/REFS: Every ref MUST match a defined key. Define keyed steps inline first time; reuse via ref thereafter. NO YAML anchors (*, &). AVOID ":" in titles/labels to keep YAML safe.
- PROHIBITED TAGS: never emit <hr>, <hr/>, or <hr /> anywhere in the HTML.
- MULTI-GUIDE: allow --- separators or guides: [] list.
- FORMAT: keep HTML concise but rich; multi-line HTML in block scalar |. NO Markdown fences.

Mini examples (structure only):
---
guide:
  contentTitle: Company Security Policy (Quick Read)
  contentType: ARTICLE
  language: en
  firstStep:
    title: Security Policy Overview
    content: |
      <h4>Welcome</h4>
      <ul>
        <li>MFA required</li>
        <li>Use a password manager</li>
      </ul>

---
guide:
  contentTitle: Laptop Setup Wizard
  contentType: GUIDE
  language: en
  firstStep:
    key: choose_os
    title: Choose Your OS
    content: "<p>Select your OS.</p>"
    media:
      - https://example.com/os.png
    choices:
      - label: macOS
        step:
          title: macOS Setup
          content: "<p>Enable FileVault.</p>"
          choices:
            - label: Done
              ref: finish
      - label: Windows
        step:
          title: Windows Setup
          content: "<p>Run Windows Update.</p>"
          choices:
            - label: Done
              ref: finish
      - label: Need help
        step:
          key: finish
          title: You're all set
          content: |
            <p>Setup complete.</p>
            <aside class="tip"><p>Reach out if you need help.</p></aside>
"""


def _testing_snippet(text: Optional[str], limit: int = 140) -> str:
    cleaned = re.sub(r"\s+", " ", (text or ""))
    cleaned = cleaned.strip()
    if not cleaned:
        return ""
    if len(cleaned) > limit:
        return cleaned[:limit].rstrip() + "…"
    return cleaned


def _is_local_host(host: str) -> bool:
    if not host:
        return False
    host = host.strip().lower()
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_loopback or ip_obj.is_private:
            return True
    except ValueError:
        if host in {"localhost"} or host.endswith(".local"):
            return True
    return False


def should_use_testing_mode(request: Request, requested: bool) -> bool:
    if not requested or not ALLOW_LOCAL_TESTING_MODE:
        return False
    client = getattr(request, "client", None)
    host = getattr(client, "host", "") if client else ""
    return _is_local_host(host)


def generate_testing_mode_yaml(prompt: str, refine_prompt: Optional[str], base_yaml: Optional[str]) -> str:
    prompt_snippet = html.escape(_testing_snippet(prompt) or "No prompt provided")
    refine_snippet = html.escape(_testing_snippet(refine_prompt) or "")
    body_sections = [
        "<p>Testing mode is active. Gemini calls stay offline so you can iterate on layout safely.</p>",
        f'<aside class="tip"><p><strong>Prompt sample:</strong> {prompt_snippet}</p></aside>',
    ]
    if refine_snippet:
        body_sections.append(f'<aside class="warning"><p><strong>Refine request:</strong> {refine_snippet}</p></aside>')
    if base_yaml:
        base_lines = len([ln for ln in base_yaml.splitlines() if ln.strip()]) or len(base_yaml.splitlines()) or 1
        body_sections.append(
            f'<aside class="tip"><p>Existing YAML detected ({base_lines} lines). It stays untouched in testing mode.</p></aside>'
        )

    confirmation_step = {
        "key": "testing_confirmation",
        "title": "Mock run complete",
        "content": "<p>Switch off testing mode to call Gemini for real content.</p>",
    }

    guides = [
        {
            "guide": {
                "contentTitle": "🧪 Testing Mode Preview · Primary Flow",
                "contentType": "GUIDE",
                "language": "en",
                "firstStep": {
                    "key": "testing_intro",
                    "title": "Preview mocked Gemini output",
                    "content": "\n".join(body_sections),
                    "choices": [
                        {
                            "label": "📋 Branching sample",
                            "step": {
                                "key": "testing_branch",
                                "title": "Branching sample",
                                "content": "<p>Use this branch to check nested spacing, connectors, and typography.</p>",
                                "choices": [
                                    {"label": "↩ Return to confirmation", "ref": "testing_confirmation"},
                                    {
                                        "label": "➕ Deep dive",
                                        "step": {
                                            "title": "Deep nested branch",
                                            "content": "<p>Verify secondary levels, muted labels, and looping back.</p>",
                                            "choices": [
                                                {"label": "Done", "ref": "testing_confirmation"}
                                            ],
                                        },
                                    },
                                ],
                            },
                        },
                        {
                            "label": "🧭 Inline content",
                            "step": {
                                "title": "Inline helper content",
                                "content": (
                                    "<p>Testing mode lets you preview refine UI without waiting on a model.</p>"
                                    "<ul><li>Prompts are echoed back for context.</li>"
                                    "<li>Refine text, if any, shows as a warning block.</li></ul>"
                                ),
                                "choices": [{"label": "Looks good", "ref": "testing_confirmation"}],
                            },
                        },
                        {"label": "✅ Approve mock", "step": confirmation_step},
                    ],
                },
            }
        },
        {
            "guide": {
                "contentTitle": "📰 Testing Mode Notes",
                "contentType": "ARTICLE",
                "language": "en",
                "firstStep": {
                    "title": "Testing notes",
                    "content": (
                        "<h4>Why you're seeing mock data</h4>"
                        f"<p>The local toggle is on, so we're returning canned YAML.</p>"
                        f"<p><strong>Prompt recap:</strong> {prompt_snippet}</p>"
                        + (f"<p><strong>Refine recap:</strong> {refine_snippet}</p>" if refine_snippet else "")
                    ),
                },
            }
        },
    ]

    return yaml.safe_dump_all(guides, sort_keys=False, allow_unicode=True).strip()


FEW_SHOT_EXAMPLE = """Examples (structure only, for style/reference — do not copy literally):
---
guide:
  contentTitle: Laptop Setup Wizard
  contentType: GUIDE
  language: en
  firstStep:
    key: choose_os
    title: Choose Your OS
    content: "<p>Pick your operating system.</p>"
    media:
      - https://upload.wikimedia.org/wikipedia/commons/f/fa/Apple_logo_black.svg
    choices:
      - label: macOS
        step:
          title: macOS Setup
          content: |
            <ol>
              <li>Open <strong>System Settings</strong> → <em>Privacy & Security</em></li>
              <li>Enable FileVault</li>
            </ol>
          choices:
            - label: Done
              ref: finish
      - label: Windows
        step:
          title: Windows Setup
          content: "<p>Run Windows Update, then enable BitLocker.</p>"
          choices:
            - label: Done
              ref: finish
      - label: Need help
        step:
          key: finish
          title: You're all set
          content: "<p>Setup complete.</p>"

---
guide:
  contentTitle: Company Security Policy (Quick Read)
  contentType: ARTICLE
  language: en
  firstStep:
    title: Security Policy Overview
    content: |
      <h4>Welcome</h4>
      <ul>
        <li>MFA required for all accounts</li>
        <li>Use a password manager</li>
        <li>Report phishing via the <code>Phish Alert</code> button</li>
      </ul>

---
guide:
  contentTitle: Product Onboarding Tour
  contentType: GUIDED_TOUR
  language: en
  firstStep:
    key: tour_start
    title: Welcome
    content: "<p>This tour highlights key areas.</p>"
    choices:
      - label: Next
        step:
          title: Create Your First Project
          content: "<p>Click <strong>New Project</strong> in the top right.</p>"
          choices:
            - label: Next
              step:
                title: Invite Your Team
                content: "<p>Open <em>Settings → Members</em> and invite colleagues.</p>"
                choices:
                  - label: Back to start
                    ref: tour_start

---
guide:
  contentTitle: Account Portal | Access Reset (Example)
  contentType: GUIDE
  language: en
  firstStep:
    key: overview
    title: "🧭 Overview"
    content: |
      <p>This workflow is for <strong>Tier 2 Support</strong> handling escalated <strong>account access reset</strong> requests.</p>
      <aside class="tip"><p>📌 <strong>Before you begin:</strong> Confirm the user is <strong>Active</strong> in the admin tool.</p></aside>
    media:
      - https://upload.wikimedia.org/wikipedia/commons/7/71/Portal.svg
    choices:
      - label: "🪪 Step 1 — Verify Identity"
        step:
          key: verify_identity
          title: "🪪 Verify Identity"
          content: |
            <h4>🧩 Phone or Video</h4>
            <ul><li>Verify full name and email.</li></ul>
            <h4>🧩 Email Request</h4>
            <ul><li>Send a confirmation template and await reply.</li></ul>
            <aside class="warning"><p>⚠️ Never request OTP codes.</p></aside>
          media:
            - https://upload.wikimedia.org/wikipedia/commons/6/6e/Ionicons_id-card.svg
          choices:
            - label: "🔍 Confirm Channel"
              step:
                title: "🔍 Confirm Channel"
                content: "<p>Ensure the reply comes from the registered address.</p>"
                choices:
                  - label: Back
                    ref: verify_identity
      - label: "🔁 Step 2 — Perform Reset"
        step:
          title: "🔁 Perform Reset"
          content: |
            <ol>
              <li>Open the Admin Console.</li>
              <li>Select Reset login or Initiate password reset.</li>
              <li>Confirm prerequisites are complete.</li>
            </ol>
            <aside class="tip"><p>✅ Tell the user a temporary password or reset link is coming.</p></aside>
      - label: "✅ Step 3 — Confirm & Close"
        step:
          key: confirm_close
          title: "✅ Confirm & Close"
          content: |
            <ul>
              <li>Confirm successful sign-in.</li>
              <li>Apply the correct closing macro.</li>
            </ul>
            <aside class="tip"><p><strong>🎯 End of Workflow</strong></p></aside>

---
guide:
  contentTitle: "✈️ Flight Attendant Backfill | Hotline"
  contentType: GUIDE
  language: en
  firstStep:
    key: fa_overview
    title: "🧭 Overview"
    content: |
      <p>Helps scheduling agents find qualified replacements fast.</p>
      <aside class="tip"><p>📌 Verify the absence in Crew Portal before proceeding.</p></aside>
    media:
      - https://upload.wikimedia.org/wikipedia/commons/3/3a/Airplane_silhouette.svg
    choices:
      - label: "🗺️ Step 1 — Capture Flight Info"
        step:
          title: "🗺️ Capture Flight Info"
          content: |
            <ul>
              <li>Departure + Destination airport codes</li>
              <li>Scheduled departure time (local)</li>
            </ul>
          choices:
            - label: "👥 Step 2 — Check Local Crew"
              step:
                title: "👥 Check Local Crew"
                content: "<p>Are standby flight attendants available at departure?</p>"
                media:
                  - https://upload.wikimedia.org/wikipedia/commons/f/f7/Team_font_awesome.svg
                choices:
                  - label: "✅ Crew Available"
                    step:
                      title: "🔄 Check Return Flights"
                      content: |
                        <p>Find return flights within 24h; validate duty hours & rest.</p>
                      choices:
                        - label: "🟢 Return Flight Available"
                          step:
                            key: fa_success
                            title: "🟢 Success"
                            content: "<p>Book crew and confirm return.</p>"
                        - label: "🔴 No Return Flight"
                          step:
                            key: evaluate_risk
                            title: "🌦️ Evaluate Disruption Risk"
                            content: "<p>Check weather alerts. If delays expected, search nearby bases.</p>"
                            choices:
                              - label: "🏙️ Search Nearby Bases"
                                step:
                                  key: nearby_bases
                                  title: "🏙️ Search Nearby Bases"
                                  content: "<p>Identify closest bases with available crew.</p>"
                                  choices:
                                    - label: "🟢 Backfill Realistic"
                                      ref: fa_success
                                    - label: "🔴 Not Realistic"
                                      step:
                                        key: final_triage
                                        title: "🚨 Final Triage"
                                        content: "<p>Escalate to supervisor; prepare for possible cancellation.</p>"
"""

def generate_yaml_with_gemini(
    prompt: str,
    *,
    base_yaml: Optional[str] = None,
    refine_prompt: Optional[str] = None,
) -> str:
    client, types = _load_gemini_client()
    user_prompt = (prompt or "").strip()
    sections: list[str] = []
    if user_prompt:
        sections.append(f"User prompt:\n{user_prompt}")
    if base_yaml:
        sections.append("Existing YAML to refine:\n" + base_yaml.strip())
    if refine_prompt:
        sections.append("Refinement instructions:\n" + refine_prompt.strip())
    if not sections:
        sections.append("User prompt:\nGenerate an improved Stonly guide.")
    sections.append(f"Format examples:\n{FEW_SHOT_EXAMPLE.strip()}")
    contents = ["\n\n".join(sections)]
    cfg = types.GenerateContentConfig(
        temperature=0.6,          # slightly higher to encourage fuller generations
        top_p=0.9,
        max_output_tokens=12288,
        system_instruction=[types.Part.from_text(text=SYSTEM_PROMPT)],
    )
    try:
        parts: list[str] = []
        for chunk in client.models.generate_content_stream(
            model="gemini-2.5-pro",
            contents=contents,
            config=cfg,
        ):
            if getattr(chunk, "text", None):
                parts.append(str(chunk.text))
        text = "".join(parts).strip()
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Gemini call failed")
        raise HTTPException(502, detail={"error": "Gemini call failed", "message": str(e)})

    cleaned = strip_code_fences(text)
    if not cleaned:
        raise HTTPException(502, detail={"error": "Gemini returned empty content"})
    return cleaned


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

def parse_guides_multi(source: str, defaults: GuideDefaults) -> list[dict]:
    """
    Parse a YAML that may contain multiple guides.
    Accepts:
      - Multi-document YAML (--- separators)
      - Single document with a top-level 'guides' list
      - Single guide (backward compatible)

    Returns a list of items: { 'definition': GuideDefinition, 'overrides': {folderId?, publish?} }
    Top-level contentType/language inside an item override values inside the nested guide, if present.
    """
    text = (source or "").strip()
    if not text:
        raise HTTPException(400, detail={"error": "YAML payload is required"})

    try:
        docs = list(yaml.safe_load_all(text))
    except Exception as e:
        raise HTTPException(400, detail={"error": "Invalid YAML", "message": str(e)})

    # If a single doc with a 'guides' list, expand it
    if len(docs) == 1 and isinstance(docs[0], dict) and isinstance(docs[0].get("guides"), list):
        docs = docs[0]["guides"]

    # If still empty, error
    if not docs:
        raise HTTPException(400, detail={"error": "No guides found in YAML"})

    items: list[dict] = []
    for idx, raw in enumerate(docs):
        if not isinstance(raw, dict):
            raise HTTPException(400, detail={"error": f"YAML document {idx} must be a mapping"})

        guide_data = raw.get("guide") if isinstance(raw.get("guide"), dict) else raw

        # Allow item-level overrides
        top_ct = raw.get("contentType")
        top_lang = raw.get("language")
        folder_id = raw.get("folderId") or raw.get("folder_id")
        publish = raw.get("publish")

        first_step_raw = guide_data.get("firstStep") if isinstance(guide_data, dict) else None
        if not isinstance(first_step_raw, dict):
            raise HTTPException(400, detail={"error": f"guide.firstStep must be an object in document {idx}"})
        first_step = GuideStep.model_validate(first_step_raw)

        # Compute merged fields with precedence: guide > top-level > defaults
        content_title = guide_data.get("contentTitle") or defaults.contentTitle or first_step.title
        if not content_title:
            raise HTTPException(400, detail={"error": f"Missing contentTitle for guide in document {idx}"})
        content_type = guide_data.get("contentType") or top_ct or defaults.contentType or "GUIDE"
        language = guide_data.get("language") or top_lang or defaults.language or first_step.language or "en-US"

        definition = GuideDefinition(
            contentTitle=content_title,
            contentType=content_type,
            language=language,
            firstStep=first_step,
        )
        items.append({
            "definition": definition,
            "overrides": {"folderId": folder_id, "publish": publish},
        })

    return items

def _build_one_guide(
    *,
    st: Stonly,
    team_id: int,
    folder_id: int,
    definition: GuideDefinition,
    dry_run: bool,
    publish: bool,
):
    """
    Build a single guide with steps. Optionally publish.
    Returns a dict similar to the legacy response (without 'ok').
    """
    steps_created: List[Dict[str, Any]] = []
    links_created: List[Dict[str, Any]] = []
    # key -> stepId mapping for reuse
    by_key: Dict[str, Any] = {}
    if dry_run:
        guide_id: Any = "dry-run-guide"
        first_step_id: Any = "dry-step-1"
        steps_created.append({
            "title": definition.firstStep.title,
            "stepId": first_step_id,
            "parent": None,
            "choiceLabel": None,
        })
        # Register first step key once (enables refs like 'intro')
        k = getattr(definition.firstStep, "key", None)
        if k:
            if k in by_key:
                raise HTTPException(400, detail={"error": f"Duplicate step key: {k}"})
            by_key[k] = first_step_id
    else:
        allow_media = (str(definition.contentType).upper() != "ARTICLE")
        created = st.create_guide(
            folder_id=folder_id,
            content_type=definition.contentType,
            content_title=definition.contentTitle,
            first_step_title=definition.firstStep.title,
            content=definition.firstStep.content,
            language=definition.firstStep.language or definition.language,
            media=(definition.firstStep.media if allow_media else None),
        )
        guide_id = created["guideId"]
        first_step_id = created["firstStepId"]
        # Register first step key if provided (non-dry-run path)
        if getattr(definition.firstStep, "key", None):
            k = definition.firstStep.key
            if k in by_key:
                raise HTTPException(400, detail={"error": f"Duplicate step key: {k}"})
            by_key[k] = first_step_id
        steps_created.append({
            "title": definition.firstStep.title,
            "stepId": first_step_id,
            "parent": None,
            "choiceLabel": None,
        })

    counter = len(steps_created)
    queue: List[Tuple[GuideStepChoice, str, str, Any, int]] = []
    for idx, choice in enumerate(definition.firstStep.choices):
        queue.append((choice, f"firstStep.choices[{idx}]", definition.firstStep.title, first_step_id, idx))

    # Deferred links if target key is not yet created
    pending_links: List[Tuple[str, Any, Optional[str], Optional[int], str, str]] = []
    # tuple: (target_key, source_step_id, choice_label, position, parent_title, path)

    while queue:
        choice, path, parent_title, parent_step_id, choice_index = queue.pop(0)

        if choice.ref:  # create a link to an existing step
            position_value = choice.position if choice.position is not None else choice_index
            target_id = by_key.get(choice.ref)
            if dry_run:
                links_created.append({
                    "action": "link",
                    "sourceStepId": parent_step_id,
                    "targetKey": choice.ref,
                    "targetStepId": (target_id if target_id is not None else "<pending>"),
                    "choiceLabel": choice.label,
                    "position": position_value,
                    "parent": parent_title,
                    "parentPath": path,
                })
            else:
                if target_id is not None:
                    st.link_steps(
                        guide_id=guide_id,
                        source_step_id=parent_step_id,
                        target_step_id=target_id,
                        choice_label=choice.label,
                        position=position_value,
                    )
                    links_created.append({
                        "action": "link",
                        "sourceStepId": parent_step_id,
                        "targetKey": choice.ref,
                        "targetStepId": target_id,
                        "choiceLabel": choice.label,
                        "position": position_value,
                        "parent": parent_title,
                        "parentPath": path,
                    })
                else:
                    pending_links.append((choice.ref, parent_step_id, choice.label, position_value, parent_title, path))
            # Do not traverse into referenced step (already part of the tree)
            continue

        # else: create a brand new step
        step = choice.step  # type: ignore
        language = step.language or definition.language
        position_value = choice.position if choice.position is not None else (
            step.position if step.position is not None else choice_index
        )

        if dry_run:
            counter += 1
            step_id = f"dry-step-{counter}"
        else:
            appended = st.append_step(
                guide_id=guide_id,
                parent_step_id=parent_step_id,
                title=step.title,
                content=step.content,
                language=language,
                choice_label=choice.label,
                position=position_value,
                media=(step.media if allow_media else None),
            )
            step_id = appended["stepId"]

        steps_created.append({
            "title": step.title,
            "stepId": step_id,
            "parent": parent_title,
            "parentPath": path,
            "choiceLabel": choice.label,
            "position": position_value,
        })

        # Register step key for reuse
        if step.key:
            if step.key in by_key:
                raise HTTPException(400, detail={"error": f"Duplicate step key: {step.key}"})
            by_key[step.key] = step_id

        for idx, child in enumerate(step.choices):
            queue.append((child, f"{path}.step.choices[{idx}]", step.title, step_id, idx))

    # Resolve deferred links now that all steps have been created
    if not dry_run and pending_links:
        unresolved: List[str] = []
        for target_key, source_id, label, pos, parent_title, path in pending_links:
            tgt = by_key.get(target_key)
            if tgt is None:
                unresolved.append(target_key)
                continue
            st.link_steps(
                guide_id=guide_id,
                source_step_id=source_id,
                target_step_id=tgt,
                choice_label=label,
                position=pos,
            )
            links_created.append({
                "action": "link",
                "sourceStepId": source_id,
                "targetKey": target_key,
                "targetStepId": tgt,
                "choiceLabel": label,
                "position": pos,
                "parent": parent_title,
                "parentPath": path,
            })
        if unresolved:
            raise HTTPException(400, detail={"error": "Unknown step key(s) referenced", "keys": sorted(set(unresolved))})

    # Publish? (skipped in dry-run)
    published = False
    if not dry_run and publish:
        # Caller may also perform a bulk publish later; in that case they should pass publish=False here.
        st._req(
            "POST",
            "/guide/publish",
            params={"teamId": team_id},
            json={"guideList": [{"guideId": guide_id}]},
        )
        published = True

    return {
        "guideId": guide_id,
        "firstStepId": first_step_id,
        "steps": steps_created,
        "links": links_created,
        "summary": {
            "stepCount": len(steps_created),
            "branchCount": max(len(steps_created) - 1, 0),
        },
        "published": published,
    }

# ---- endpoints ----
@app.post("/api/login", tags=["Auth"], summary="Obtain admin session")
def api_login(payload: LoginPayload):
    if payload.token != ADMIN_TOKEN:
        raise HTTPException(401, detail="Invalid token")
    sid = _create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=sid,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite=SESSION_COOKIE_SAMESITE,
        path="/",
    )
    return resp


@app.post("/api/logout", tags=["Auth"], summary="Clear admin session")
def api_logout(request: Request):
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if sid:
        _clear_session(sid)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return resp


@app.get("/api/auth/status", tags=["Auth"], summary="Check admin session")
def api_auth_status(request: Request):
    ensure_admin(request=request)
    return {"ok": True}


@app.post("/api/apply", tags=["Builder"], summary="Apply folder structure")
def api_apply(payload: ApplyPayload, request: Request, authorization: Optional[str] = Header(None)):
    ensure_admin(auth_header=authorization, request=request, token=payload.token)
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

@app.post("/api/verify", tags=["Builder"], summary="Verify folder structure")
def api_verify(payload: VerifyPayload, request: Request):
    ensure_admin(request=request, token=payload.token)
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


def api_build_guide(payload: GuideBuildPayload):
    request_id = str(uuid.uuid4())
    logger.info("REQUEST %s :: /api/guides/build", request_id)
    def _log(prefix, msg):
        logger.info("%s %s :: %s", prefix, request_id, msg)
    # Parse YAML; may contain one or multiple guides
    items = parse_guides_multi(payload.yaml, payload.defaults)

    # Log a concise header; avoid referencing per-guide fields before selecting items
    try:
        titles = []
        for it in items[:3]:
            d = it.get("definition")
            if d:
                titles.append(str(getattr(d, "contentTitle", "")) or "<no-title>")
        extra = "" if len(items) <= 3 else f" (+{len(items)-3} more)"
        sample = ", ".join(titles) + extra
    except Exception:
        sample = "(unavailable)"
    logger.info(
        "GUIDE build start dryRun=%s team=%s folder=%s items=%s titles=%s",
        payload.dryRun,
        payload.creds.teamId,
        payload.folderId,
        len(items),
        sample,
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

    # Single guide (back-compat): keep response shape
    if len(items) == 1:
        definition = items[0]["definition"]
        ov = items[0]["overrides"] or {}
        folder_id = int(ov.get("folderId") or payload.folderId)
        publish = bool(ov.get("publish") if ov.get("publish") is not None else getattr(payload, "publish", False))

        try:
            result_one = _build_one_guide(
                st=st,
                team_id=payload.creds.teamId,
                folder_id=folder_id,
                definition=definition,
                dry_run=dry_run,
                publish=publish,
            )
        except HTTPException:
            raise
        except Exception:
            logger.exception("GUIDE build failed (single)")
            raise HTTPException(502, detail={"error": "Build failed"})

        return {
            "ok": True,
            "dryRun": dry_run,
            **result_one,
        }

    # Multiple guides: continue-on-error, batch publish at end
    results: list[dict] = []
    publish_ids: list[str] = []

    for idx, item in enumerate(items):
        definition = item["definition"]
        ov = item.get("overrides") or {}
        folder_id = int(ov.get("folderId") or payload.folderId)
        item_publish = bool(ov.get("publish") if ov.get("publish") is not None else getattr(payload, "publish", False))
        try:
            result = _build_one_guide(
                st=st,
                team_id=payload.creds.teamId,
                folder_id=folder_id,
                definition=definition,
                dry_run=dry_run,
                publish=False,  # defer to bulk publish later
            )
            # Track for bulk publish if requested and not dry run
            if item_publish and not dry_run:
                publish_ids.append(result["guideId"])
            results.append({"ok": True, "index": idx, "contentTitle": definition.contentTitle, **result})
        except HTTPException as e:
            results.append({
                "ok": False,
                "index": idx,
                "contentTitle": getattr(definition, "contentTitle", None),
                "error": getattr(e, "detail", str(e)),
                "type": e.__class__.__name__,
            })
        except Exception as e:
            results.append({
                "ok": False,
                "index": idx,
                "contentTitle": getattr(definition, "contentTitle", None),
                "error": str(e),
                "type": e.__class__.__name__,
            })

    published_all = False
    bulk_publish_error = None
    published_ids: list[str] = []
    if publish_ids and not dry_run:
        try:
            st.publish_guides(publish_ids)
            published_all = True
            # mark each corresponding result as published
            for r in results:
                if r.get("ok") and r.get("guideId") in publish_ids:
                    r["published"] = True
            published_ids = list(publish_ids)
        except Exception as e:
            bulk_publish_error = str(e)

    total_steps = sum((r.get("summary", {}).get("stepCount", 0) for r in results if r.get("ok")), 0)
    succeeded = sum(1 for r in results if r.get("ok"))
    failed = len(results) - succeeded
    created_ids = [r["guideId"] for r in results if r.get("ok") and r.get("guideId")]
    resp = {
        "ok": True,
        "dryRun": dry_run,
        "results": results,
        "summary": {
            "count": len(results),
            "succeeded": succeeded,
            "failed": failed,
            "totalSteps": total_steps,
        },
        "publishedAll": published_all,
        "createdIds": created_ids,
        "attemptedPublishIds": publish_ids,
        "publishedIds": published_ids,
    }
    if bulk_publish_error:
        resp["bulkPublishError"] = bulk_publish_error
    return resp


@app.post("/api/guides/publish-drafts", tags=["Builder"], summary="Publish draft guides already present in a folder")
def api_publish_drafts(payload: PublishDraftsPayload, request: Request):
    ensure_admin(request=request, token=payload.token)
    st = Stonly(
        base=payload.creds.base or "https://public.stonly.com/api/v3",
        user=payload.creds.user,
        password=payload.creds.password,
        team_id=payload.creds.teamId,
    )

    try:
        items = st.list_guides_in_folder(
            folder_id=payload.folderId,
            recursive=payload.includeSubfolders,
            guide_status="draft",
            limit=payload.limit,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("list draft guides failed")
        raise HTTPException(502, detail={"error": "Failed to list draft guides", "msg": str(e)})

    drafts: List[Dict[str, Any]] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        status = str(it.get("entityStatus") or it.get("status") or "").lower()
        if status != "draft":
            continue
        gid = it.get("entityId") or it.get("id")
        if not gid:
            continue
        drafts.append({
            "id": gid,
            "name": it.get("entityName") or it.get("name"),
            "folder": it.get("entityFolder"),
            "languages": it.get("entityLanguages") or it.get("languages") or [],
            "status": status,
        })

    published_ids: list[str] = []
    if drafts:
        ids = [str(d["id"]) for d in drafts if d.get("id")]
        try:
            # Stonly publish endpoint accepts max 100 per request; chunk accordingly
            def chunks(seq, size=100):
                for i in range(0, len(seq), size):
                    yield seq[i:i + size]
            for batch in chunks(ids, 100):
                st.publish_guides(batch)
                published_ids.extend(batch)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("publish draft guides failed")
            raise HTTPException(
                502,
                detail={
                    "error": "Failed to publish guides",
                    "msg": str(e),
                    "guideIds": ids,
                    "publishedSoFar": published_ids,
                },
            )

    return {
        "ok": True,
        "recursive": payload.includeSubfolders,
        "draftCount": len(drafts),
        "publishedCount": len(published_ids),
        "publishedIds": published_ids,
        "drafts": drafts,
    }


@app.post("/api/guides/build", tags=["Builder"], summary="Build guides from YAML")
def api_build_guide_http(payload: GuideBuildPayload, request: Request):
    ensure_admin(request=request, token=payload.token)
    return api_build_guide(payload)


@app.post(
    "/api/ai-guides/build",
    tags=["Builder"],
    summary="Generate guide YAML via Gemini, then build/publish it",
)
def api_ai_guides_build(payload: AIGuidePayload, request: Request):
    ensure_admin(request=request, token=payload.token)
    request_id = str(uuid.uuid4())
    testing_mode_active = should_use_testing_mode(request, payload.testingMode)
    logger.info(
        "REQUEST %s :: /api/ai-guides/build team=%s folder=%s publish=%s previewOnly=%s testingMode=%s",
        request_id,
        payload.teamId,
        payload.folderId,
        payload.publish,
        payload.previewOnly,
        testing_mode_active,
    )

    # 1) Determine YAML source (manual override vs Gemini)
    provided_yaml = (payload.yamlOverride or "").strip() or None
    if provided_yaml:
        raw_yaml = provided_yaml
    elif testing_mode_active:
        raw_yaml = generate_testing_mode_yaml(
            payload.prompt or "",
            refine_prompt=payload.refinePrompt,
            base_yaml=payload.baseYaml,
        )
    else:
        raw_yaml = generate_yaml_with_gemini(
            payload.prompt or "",
            base_yaml=payload.baseYaml,
            refine_prompt=payload.refinePrompt,
        )
    yaml_text = normalize_ai_yaml(raw_yaml)

    # 2) Parse YAML with leniency; apply auto-fixes for common issues
    try:
        items = parse_guides_multi(yaml_text, GuideDefaults())
    except HTTPException:
        # Try one more time after wrapping/dedenting if possible
        try:
            yaml_text = normalize_ai_yaml(yaml_text)
            items = parse_guides_multi(yaml_text, GuideDefaults())
        except HTTPException as e2:
            detail = getattr(e2, "detail", str(e2))
            if isinstance(detail, dict):
                detail = {**detail, "modelText": raw_yaml}
            else:
                detail = {"error": detail, "modelText": raw_yaml}
            raise HTTPException(getattr(e2, "status_code", 400), detail=detail)

    # 3) Auto-sanitize titles/labels, clamp choice positions, and resolve missing refs to reduce failures
    for item in items:
        definition: GuideDefinition = item["definition"]
        definition = sanitize_titles_and_labels(definition)
        definition = clamp_positions(definition)
        definition = resolve_missing_refs(definition)
        item["definition"] = definition

    # 4) Re-serialize cleaned YAML for display/traceability
    yaml_text = serialize_items_to_yaml(items)

    if payload.previewOnly:
        return {"ok": True, "yaml": yaml_text, "previewOnly": True, "testingMode": testing_mode_active}

    # 3) Build using existing pipeline (reuse team token as password)
    dry_run_flag = bool(payload.dryRun or testing_mode_active)
    build_payload = GuideBuildPayload(
        token=payload.token,
        creds=Creds(
            user="Undefined",
            password=payload.teamToken,
            teamId=payload.teamId,
            base=payload.base or "https://public.stonly.com/api/v3",
        ),
        folderId=payload.folderId,
        yaml=yaml_text,
        dryRun=dry_run_flag,
        defaults=GuideDefaults(),
        publish=False if testing_mode_active else payload.publish,
    )

    try:
        build_result = api_build_guide(build_payload)
    except HTTPException as e:
        detail = getattr(e, "detail", str(e))
        if isinstance(detail, dict):
            detail = {**detail, "modelText": yaml_text}
        else:
            detail = {"error": detail, "modelText": yaml_text}
        raise HTTPException(getattr(e, "status_code", 500), detail=detail)
    except Exception as e:
        logger.exception("AI build failed (request %s)", request_id)
        raise HTTPException(502, detail={"error": "Guide build failed", "modelText": yaml_text, "message": str(e)})

    resp = {"ok": True, "yaml": yaml_text, "build": build_result}
    if testing_mode_active:
        resp["testingMode"] = True
    return resp

@app.get("/api/dump-structure", tags=["Structure"], summary="Dump folder tree")
def api_dump(
    request: Request,
    token: Optional[str] = None,
    user: str = ...,
    password: str = ...,
    teamId: int = ...,
    parentId: Optional[int] = None,
    base: str = "https://public.stonly.com/api/v3",
):
    ensure_admin(request=request, token=token)
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


@app.get("/api/ping", tags=["Health"], summary="Health check")
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

    # Call the same core logic the API uses so behavior matches /api/guides/build
    out = api_build_guide(payload)
    print(json.dumps(out, indent=2))
