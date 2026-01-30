from __future__ import annotations
from typing import List, Optional, Dict, Any, Tuple
import re
import json
import base64
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
import os, time, html, ipaddress, base64, hashlib, hmac, secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urljoin

from fastapi import FastAPI, HTTPException, Request
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
import json
import yaml
import uuid


import logging, logging.handlers
from dotenv import load_dotenv
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Text,
    UniqueConstraint,
    inspect,
    text,
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
from cryptography.fernet import Fernet, InvalidToken

load_dotenv()

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

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
GOOGLE_ALLOWED_DOMAIN = os.getenv("GOOGLE_ALLOWED_DOMAIN")
GOOGLE_STATE_TTL = int(os.getenv("GOOGLE_STATE_TTL", "600"))

# Allow local testing shortcuts (e.g., ephemeral keys, sqlite fallback)
ALLOW_LOCAL_TESTING_MODE = os.getenv("AI_ALLOW_TESTING_MODE", "1") != "0"

# Session / cookie configuration (account login)
SESSION_COOKIE_NAME = "st_session"
SESSION_TTL_SECONDS = int(os.getenv("SESSION_COOKIE_TTL", "604800"))  # 7d default
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "1") != "0"
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "none")

# ---- DB / Auth config ----
DEFAULT_STONLY_BASE = "https://public.stonly.com/api/v3"
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    if ALLOW_LOCAL_TESTING_MODE:
        DATABASE_URL = "sqlite:///./stonly.db"
        logger.warning("DATABASE_URL missing; using local sqlite for testing.")
    else:
        raise RuntimeError("Missing env: DATABASE_URL")

# SQLAlchemy requires "postgresql://" scheme
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

TEAM_TOKEN_ENCRYPTION_KEY = os.getenv("TEAM_TOKEN_ENCRYPTION_KEY")
if not TEAM_TOKEN_ENCRYPTION_KEY:
    if ALLOW_LOCAL_TESTING_MODE:
        TEAM_TOKEN_ENCRYPTION_KEY = Fernet.generate_key().decode("utf-8")
        logger.warning("Generated ephemeral TEAM_TOKEN_ENCRYPTION_KEY for testing.")
    else:
        raise RuntimeError("Missing env: TEAM_TOKEN_ENCRYPTION_KEY")

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
try:
    fernet = Fernet(TEAM_TOKEN_ENCRYPTION_KEY.encode("utf-8"))
except Exception as exc:
    raise RuntimeError("Invalid TEAM_TOKEN_ENCRYPTION_KEY") from exc

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ---- Time helpers ----
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# ---- DB models ----
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    api_base = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=_utcnow, nullable=False)


class Team(Base):
    __tablename__ = "teams"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    team_id = Column(Integer, nullable=False)
    token_encrypted = Column(Text, nullable=False)
    name = Column(String(255), nullable=True)
    root_folder = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=_utcnow, nullable=False)
    updated_at = Column(DateTime, default=_utcnow, nullable=False)
    __table_args__ = (
        UniqueConstraint("user_id", "team_id", name="uq_user_team_id"),
    )


class UserSession(Base):
    __tablename__ = "sessions"
    id = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=_utcnow, nullable=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_user_schema()


def _ensure_user_schema() -> None:
    try:
        inspector = inspect(engine)
        if "users" not in inspector.get_table_names():
            return
        columns = {col["name"] for col in inspector.get_columns("users")}
        if "api_base" not in columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN api_base TEXT"))
    except Exception:
        logger.exception("Failed to ensure users schema")


# IMPORTANT : ne pas exiger STONLY_USER/PASS/TEAM_ID ici.
# Ils arrivent depuis le frontend dans chaque requête (payload ou query).


tags_metadata = [
    {"name": "Auth", "description": "Account authentication and sessions"},
    {"name": "Settings", "description": "Account-level settings"},
    {"name": "Teams", "description": "Team registry for stored Stonly tokens"},
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

@app.on_event("startup")
def _startup_init_db() -> None:
    init_db()

# CORS : autoriser seulement les frontends connus (+ localhost optionnel)
FRONTEND_ORIGINS = [
    "https://api-stonly-internal.onrender.com",
    "https://ai-builder.stonly.com",
]
PRIMARY_FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://ai-builder.stonly.com")
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
from fastapi.responses import PlainTextResponse, StreamingResponse, RedirectResponse, Response
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


def _google_enabled() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI)


def _sanitize_next(next_value: Optional[str]) -> str:
    if not next_value:
        return "/ai-content-creator.html"
    if next_value.startswith("/") and not next_value.startswith("//"):
        return next_value
    return "/ai-content-creator.html"


def _state_sign(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    data = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    sig = hmac.new(TEAM_TOKEN_ENCRYPTION_KEY.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{data}.{sig}"


def _state_verify(state: str) -> dict:
    if not state or "." not in state:
        raise ValueError("Invalid state")
    data, sig = state.rsplit(".", 1)
    expected = hmac.new(TEAM_TOKEN_ENCRYPTION_KEY.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid state signature")
    padded = data + "=" * (-len(data) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8"))
    ts = int(payload.get("ts", 0))
    if ts <= 0 or (time.time() - ts) > GOOGLE_STATE_TTL:
        raise ValueError("State expired")
    return payload


def _frontend_origin() -> str:
    return PRIMARY_FRONTEND_ORIGIN.rstrip("/")


def _redirect_to_login(next_path: str, *, error: Optional[str] = None) -> RedirectResponse:
    params = {"next": next_path}
    if error:
        params["error"] = error
    target = _frontend_origin() + "/login.html?" + urlencode(params)
    return RedirectResponse(target)


def _google_authorize_url(next_path: str) -> str:
    payload = {
        "ts": int(time.time()),
        "next": next_path,
        "nonce": secrets.token_urlsafe(12),
    }
    state = _state_sign(payload)
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    if GOOGLE_ALLOWED_DOMAIN:
        params["hd"] = GOOGLE_ALLOWED_DOMAIN
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)

@app.exception_handler(Exception)
async def unhandled_exc(_, exc: Exception):
    # Evite les 500 silencieux : log + payload JSON simple
    logger.exception("Unhandled error")
    return JSONResponse(
        status_code=500,
        content={"ok": False, "error": str(exc), "type": exc.__class__.__name__},
    )


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


def _encrypt_team_token(token: str) -> str:
    return fernet.encrypt(token.encode("utf-8")).decode("utf-8")


def _decrypt_team_token(token_enc: str) -> str:
    try:
        return fernet.decrypt(token_enc.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise HTTPException(500, detail="Failed to decrypt team token")


def _create_session(db, user_id: int) -> str:
    sid = uuid.uuid4().hex
    expires_at = _utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)
    db.add(UserSession(id=sid, user_id=user_id, expires_at=expires_at))
    db.commit()
    return sid


def _clear_session(db, session_id: Optional[str]) -> None:
    if not session_id:
        return
    db.query(UserSession).filter(UserSession.id == session_id).delete()
    db.commit()


def _get_session_user_id(db, session_id: Optional[str]) -> Optional[int]:
    if not session_id:
        return None
    session = db.query(UserSession).filter(UserSession.id == session_id).first()
    if not session:
        return None
    if _as_utc(session.expires_at) <= _utcnow():
        db.query(UserSession).filter(UserSession.id == session_id).delete()
        db.commit()
        return None
    return session.user_id


def get_user_from_request(db, request: Request) -> User:
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    user_id = _get_session_user_id(db, sid)
    if not user_id:
        raise HTTPException(401, detail="Missing or expired session")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(401, detail="Unknown session user")
    return user


def get_team_for_user(db, user_id: int, team_id: int) -> Team:
    team = db.query(Team).filter(Team.user_id == user_id, Team.team_id == team_id).first()
    if not team:
        raise HTTPException(404, detail="Team not found")
    return team


def get_stonly_client_for_team(
    db,
    *,
    user_id: int,
    team_id: int,
    base: Optional[str],
    user_label: Optional[str],
) -> Tuple["Stonly", Team]:
    team = get_team_for_user(db, user_id, team_id)
    token = _decrypt_team_token(team.token_encrypted)
    base_value = (base or "").strip()
    if not base_value:
        user = db.query(User).filter(User.id == user_id).first()
        base_value = (user.api_base or "").strip() if user else ""
    if not base_value:
        base_value = DEFAULT_STONLY_BASE
    st = Stonly(
        base=base_value,
        user=(user_label or "Undefined"),
        password=token,
        team_id=team.team_id,
    )
    return st, team

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
    teamId: int
    base: Optional[str] = None
    password: Optional[str] = None  # deprecated: only used in local/testing

    @field_validator("user", mode="before")
    @classmethod
    def default_user(cls, v):
        s = str(v).strip() if v is not None else ""
        return s or "Undefined"

    @field_validator("teamId")
    @classmethod
    def team_id_required(cls, v):
        if v is None:
            raise ValueError("teamId is required")
        return int(v)

    @field_validator("base", mode="before")
    @classmethod
    def base_optional(cls, v):
        if v is None:
            return None
        text = str(v).strip()
        return text or None

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
    creds: Creds
    folderId: int
    includeSubfolders: bool = True
    limit: int = Field(default=100, ge=1, le=100)

class ApplyPayload(BaseModel):
    creds: Creds
    parentId: Optional[int] = None
    dryRun: bool = False
    root: List[UINode]
    settings: Optional[Settings] = None

class VerifyPayload(BaseModel):
    creds: Creds
    parentId: Optional[int] = None
    root: List[UINode]

class GuideBuildPayload(BaseModel):
    creds: Creds
    folderId: int
    yaml: str
    dryRun: bool = False
    defaults: GuideDefaults = GuideDefaults()
    publish: bool = False


class AIGuidePayload(BaseModel):
    prompt: str = ""
    teamId: int
    folderId: int
    publish: bool = False
    dryRun: bool = False
    base: Optional[str] = None
    previewOnly: bool = False
    baseYaml: Optional[str] = None
    refinePrompt: Optional[str] = None
    yamlOverride: Optional[str] = None
    testingMode: bool = False

    @field_validator("prompt")
    @classmethod
    def prompt_required(cls, v: str):
        text = (v or "").strip()
        if len(text) > 40000:
            raise ValueError("prompt is too long (max 40000 characters)")
        return text

    @field_validator("base")
    @classmethod
    def base_default(cls, v: Optional[str]):
        s = (v or "").strip()
        return s or None

    @field_validator("baseYaml", "yamlOverride", mode="before")
    @classmethod
    def trim_yaml(cls, v):
        if v is None:
            return None
        s = str(v)
        return s.strip()


class AIPromptPayload(BaseModel):
    prompt: str = ""

    @field_validator("prompt")
    @classmethod
    def prompt_required(cls, v: str):
        text = (v or "").strip()
        if len(text) > 40000:
            raise ValueError("prompt is too long (max 40000 characters)")
        return text


class BrandWebsitePayload(BaseModel):
    brandName: str = ""

    @field_validator("brandName")
    @classmethod
    def brand_name_required(cls, v: str):
        text = (v or "").strip()
        if not text:
            raise ValueError("brandName is required")
        if len(text) > 200:
            raise ValueError("brandName is too long (max 200 characters)")
        return text


class BrandColorsPayload(BaseModel):
    brandName: str = ""
    url: Optional[str] = None

    @field_validator("brandName")
    @classmethod
    def brand_name_required(cls, v: str):
        text = (v or "").strip()
        if not text:
            raise ValueError("brandName is required")
        if len(text) > 200:
            raise ValueError("brandName is too long (max 200 characters)")
        return text

    @field_validator("url")
    @classmethod
    def url_normalize(cls, v: Optional[str]):
        if v is None:
            return None
        text = str(v).strip()
        return text or None


class BrandAssetsPayload(BaseModel):
    url: str = ""

    @field_validator("url")
    @classmethod
    def url_required(cls, v: str):
        text = (v or "").strip()
        if not text:
            raise ValueError("url is required")
        if len(text) > 2000:
            raise ValueError("url is too long (max 2000 characters)")
        return text


class LoginPayload(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def email_required(cls, v: str):
        text = _normalize_email(v)
        if "@" not in text:
            raise ValueError("email is required")
        return text

    @field_validator("password")
    @classmethod
    def password_required(cls, v: str):
        text = (v or "").strip()
        if not text:
            raise ValueError("password is required")
        return text


class SignupPayload(BaseModel):
    email: str
    password: str
    adminToken: str

    @field_validator("email")
    @classmethod
    def email_required(cls, v: str):
        text = _normalize_email(v)
        if "@" not in text:
            raise ValueError("email is required")
        return text

    @field_validator("password")
    @classmethod
    def password_required(cls, v: str):
        text = (v or "").strip()
        if len(text) < 8:
            raise ValueError("password must be at least 8 characters")
        return text

    @field_validator("adminToken")
    @classmethod
    def admin_token_required(cls, v: str):
        text = (v or "").strip()
        if not text:
            raise ValueError("adminToken is required")
        return text


class ResetPasswordPayload(BaseModel):
    email: str
    newPassword: str
    adminToken: str

    @field_validator("email")
    @classmethod
    def email_required(cls, v: str):
        text = _normalize_email(v)
        if "@" not in text:
            raise ValueError("email is required")
        return text

    @field_validator("newPassword")
    @classmethod
    def password_required(cls, v: str):
        text = (v or "").strip()
        if len(text) < 8:
            raise ValueError("password must be at least 8 characters")
        return text

    @field_validator("adminToken")
    @classmethod
    def admin_token_required(cls, v: str):
        text = (v or "").strip()
        if not text:
            raise ValueError("adminToken is required")
        return text


class UserSettingsPayload(BaseModel):
    apiBase: Optional[str] = None

    @field_validator("apiBase", mode="before")
    @classmethod
    def api_base_optional(cls, v):
        if v is None:
            return None
        text = str(v).strip()
        return text or None


class TeamCreatePayload(BaseModel):
    teamId: int
    teamToken: str
    name: str
    rootFolder: Optional[int] = None

    @field_validator("teamId")
    @classmethod
    def team_id_required(cls, v):
        if v is None:
            raise ValueError("teamId is required")
        return int(v)

    @field_validator("teamToken")
    @classmethod
    def team_token_required(cls, v: str):
        text = (v or "").strip()
        if not text:
            raise ValueError("teamToken is required")
        return text

    @field_validator("name")
    @classmethod
    def name_required(cls, v):
        text = (v or "").strip()
        if not text:
            raise ValueError("name is required")
        return text

    @field_validator("rootFolder", mode="before")
    @classmethod
    def root_folder_optional(cls, v):
        if v is None or v == "":
            return None
        return int(v)


class TeamUpdatePayload(BaseModel):
    teamId: Optional[int] = None
    teamToken: Optional[str] = None
    name: Optional[str] = None
    rootFolder: Optional[int] = None

    @field_validator("teamId")
    @classmethod
    def team_id_optional(cls, v):
        if v is None:
            return None
        return int(v)

    @field_validator("teamToken")
    @classmethod
    def team_token_optional(cls, v: Optional[str]):
        if v is None:
            return None
        text = str(v).strip()
        return text or None

    @field_validator("name", mode="before")
    @classmethod
    def name_optional(cls, v):
        if v is None:
            return None
        text = str(v).strip()
        return text or None

    @field_validator("rootFolder", mode="before")
    @classmethod
    def root_folder_optional(cls, v):
        if v is None or v == "":
            return None
        return int(v)



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
                if ch.step and ch.step.position is not None:
                    ch.step.position = min(max(ch.step.position, 0), max_idx)
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


def _indent_len(line: str) -> int:
    count = 0
    for ch in line:
        if ch == " ":
            count += 1
        elif ch == "\t":
            count += 2
        else:
            break
    return count


def fix_pre_block_indentation(text: str) -> str:
    """Fix YAML block scalar indentation issues caused by unindented <pre> lines."""
    if not text:
        return ""
    lines = text.splitlines()
    if not lines:
        return text

    block_re = re.compile(r"^(?P<indent>[ \t]*)(?:-[ \t]+)?[^#\n]*:\s*[|>][0-9+-]*\s*$")
    out: list[str] = []
    in_block = False
    in_pre = False
    base_indent = 0
    content_indent: Optional[int] = None

    i = 0
    while i < len(lines):
        line = lines[i]
        if not in_block:
            out.append(line)
            match = block_re.match(line)
            if match:
                in_block = True
                in_pre = False
                base_indent = _indent_len(match.group("indent"))
                content_indent = None
            i += 1
            continue

        if content_indent is None and line.strip():
            indent_len = _indent_len(line)
            content_indent = indent_len if indent_len > base_indent else base_indent + 2

        line_has_pre = bool(re.search(r"<\s*pre\b", line, re.I))
        line_has_pre_end = bool(re.search(r"</\s*pre\s*>", line, re.I))
        is_pre_related = in_pre or line_has_pre or line_has_pre_end

        indent_len = _indent_len(line)
        if line.strip() and indent_len <= base_indent and not is_pre_related:
            in_block = False
            in_pre = False
            content_indent = None
            continue

        if is_pre_related and line.strip():
            if content_indent is None:
                content_indent = base_indent + 2
            if indent_len < content_indent:
                line = (" " * content_indent) + line.lstrip()

        out.append(line)

        pre_starts = len(re.findall(r"<\s*pre\b", line, re.I))
        pre_ends = len(re.findall(r"</\s*pre\s*>", line, re.I))
        if pre_starts > pre_ends:
            in_pre = True
        elif pre_ends > pre_starts:
            in_pre = False

        i += 1

    return "\n".join(out)


def fix_unquoted_colons_in_scalars(text: str) -> str:
    """Quote label/title/contentTitle values that include ':' to keep YAML valid."""
    if not text:
        return ""
    lines = text.splitlines()
    if not lines:
        return text

    block_re = re.compile(r"^(?P<indent>[ \t]*)(?:-[ \t]+)?[^#\n]*:\s*[|>][0-9+-]*\s*$")
    key_re = re.compile(
        r"^(?P<indent>[ \t]*)(?P<dash>-\s+)?(?P<key>label|title|contentTitle|name|description)\s*:\s*(?P<val>.+)\s*$"
    )
    out: list[str] = []
    in_block = False
    base_indent = 0

    i = 0
    while i < len(lines):
        line = lines[i]
        if not in_block:
            match = key_re.match(line)
            if match:
                val = match.group("val")
                stripped = val.strip()
                if stripped and not stripped.startswith(("'", '"', "|", ">")):
                    if re.search(r":\s", stripped):
                        escaped = stripped.replace("\\", "\\\\").replace('"', '\\"')
                        line = f"{match.group('indent')}{match.group('dash') or ''}{match.group('key')}: \"{escaped}\""
            out.append(line)

            bmatch = block_re.match(line)
            if bmatch:
                in_block = True
                base_indent = _indent_len(bmatch.group("indent"))
            i += 1
            continue

        indent_len = _indent_len(line)
        if line.strip() and indent_len <= base_indent:
            in_block = False
            continue

        out.append(line)
        i += 1

    return "\n".join(out)


def normalize_ai_yaml(text: str) -> str:
    """Best-effort cleanup for AI-generated YAML to reduce failures."""
    if text is None:
        return ""
    s = strip_code_fences(text)
    # Replace tabs with spaces to avoid YAML indentation errors
    s = s.replace("\t", "  ")
    # Fix block scalar indentation for <pre> tags
    s = fix_pre_block_indentation(s)
    # Quote values with ':' in labels/titles to avoid YAML parse errors
    s = fix_unquoted_colons_in_scalars(s)
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
- NAVIGATION: Avoid using ref to simulate a single-step “Back” to the immediate parent; the UI already provides a back button. If a back choice is needed, it should jump multiple levels (e.g., “Back to start”, “Back to verification”).
- KEYS/REFS: Every ref MUST match a defined key. Define keyed steps inline first time; reuse via ref thereafter. NO YAML anchors (*, &). AVOID ":" in titles/labels; if you must use ":", wrap the value in quotes.
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

KB_SYSTEM_PROMPT = """You are a knowledge manager who builds clear, logical knowledge base structures.
OUTPUT ONLY VALID YAML. Do not include Markdown fences, code blocks, or extra commentary.

TASK:
- Propose a KB folder structure based on the user's notes.
- Return a single YAML document with a top-level `root:` list.
- Each node must include: name, optional description, and children (always present; use [] if empty).
- Prefer 1 top-level folder that represents the brand (for example: "<Brand> Knowledge Base"), then nest categories beneath it.
- Focus only on folder categories; do NOT create folders for individual guides/articles or specific how-to topics.
- Assume guides/articles will be created later and should live inside the broader folders you define.
- Avoid using ":" in names/descriptions; if you must use ":", wrap the value in double quotes.
- Use consistent 2-space indentation.

YAML EXAMPLE (structure only):
root:
  - name: Support
    description: "Public info & help center"
    children:
      - name: FAQs
        description: "Common questions"
        children: []
      - name: Tutorials
        children:
          - name: Web
            children: []
          - name: Mobile
            description: "iOS & Android guides"
            children: []
"""

ORGANISER_SYSTEM_PROMPT = """You are a knowledge manager who organizes guides into a knowledge base.
OUTPUT ONLY YAML. Do not include Markdown fences, code blocks, or extra commentary.

INPUTS:
1) The KB structure with folder IDs (JSON or YAML mapping of paths to IDs).
2) A list of guides in YAML.

TASK:
- Assign each guide to the best folder ID from the KB mapping.
- Preserve the guide titles and types exactly as given.
- Output ONLY multi-document YAML where each document includes folderId and guide with contentTitle and contentType.
- Remove all other fields (no steps, no content).
- Every guide must have a folderId from the provided mapping. If unsure, choose the most likely folder.

OUTPUT EXAMPLE (structure only):
---
folderId: 499727
guide:
  contentTitle: POS Printer Not Working
  contentType: GUIDE
---
folderId: 499716
guide:
  contentTitle: ID Requirements for Transfers (USA)
  contentType: ARTICLE
"""

WEBSITE_SYSTEM_PROMPT = """You are an assistant that resolves official brand websites.
OUTPUT ONLY THE URL and nothing else. No punctuation, no extra text.
If unsure, provide the most likely official homepage URL.
"""

COLORS_SYSTEM_PROMPT = """You are a brand designer for help centers.
Return ONLY YAML (no Markdown fences, no commentary).
Use exactly these keys with HEX color values (#RRGGBB):
- headerBackground
- iconColor
- highlightColor
Do not omit any key. Values must be 6-character hex colors prefixed with #.

Example 1:
headerBackground: "#0F172A"
iconColor: "#2563EB"
highlightColor: "#22C55E"

Example 2:
headerBackground: "#111827"
iconColor: "#F97316"
highlightColor: "#38BDF8"

Example 3:
headerBackground: "#1F2937"
iconColor: "#A855F7"
highlightColor: "#F59E0B"
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

def generate_gemini_text(
    contents: list[str],
    *,
    system_prompt: str,
    temperature: float = 0.7,
    top_p: float = 0.9,
    max_output_tokens: int = 15000,
    response_mime_type: Optional[str] = None,
) -> str:
    client, types = _load_gemini_client()
    def _extract_text_from_response(resp: Any) -> str:
        if resp is None:
            return ""
        try:
            txt = getattr(resp, "text", None)
            if txt:
                return str(txt)
        except Exception:
            pass
        try:
            candidates = getattr(resp, "candidates", None) or []
            for cand in candidates:
                content = getattr(cand, "content", None)
                parts = getattr(content, "parts", None) or []
                buf: list[str] = []
                for part in parts:
                    part_text = getattr(part, "text", None)
                    if part_text:
                        buf.append(str(part_text))
                if buf:
                    return "".join(buf)
        except Exception:
            pass
        return ""
    cfg_kwargs: dict[str, Any] = {
        "temperature": temperature,
        "top_p": top_p,
        "max_output_tokens": max_output_tokens,
        "system_instruction": [types.Part.from_text(text=system_prompt)],
    }
    if response_mime_type:
        cfg_kwargs["response_mime_type"] = response_mime_type
    try:
        cfg = types.GenerateContentConfig(**cfg_kwargs)
    except TypeError:
        cfg_kwargs.pop("response_mime_type", None)
        cfg = types.GenerateContentConfig(**cfg_kwargs)
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
        if not text:
            try:
                resp = client.models.generate_content(
                    model="gemini-2.5-pro",
                    contents=contents,
                    config=cfg,
                )
                text = _extract_text_from_response(resp).strip()
                if text:
                    logger.info("Gemini stream returned empty; used non-stream fallback.")
            except Exception:
                logger.exception("Gemini fallback call failed")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Gemini call failed")
        raise HTTPException(502, detail={"error": "Gemini call failed", "message": str(e)})

    cleaned = strip_code_fences(text)
    if not cleaned:
        logger.error("Gemini returned empty content (response_mime_type=%s)", response_mime_type)
        raise HTTPException(502, detail={"error": "Gemini returned empty content"})
    return cleaned


def generate_yaml_with_gemini(
    prompt: str,
    *,
    base_yaml: Optional[str] = None,
    refine_prompt: Optional[str] = None,
) -> str:
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
    return generate_gemini_text(
        contents,
        system_prompt=SYSTEM_PROMPT,
        temperature=0.7,
        top_p=0.9,
        max_output_tokens=15000,
    )


def generate_kb_yaml_with_gemini(prompt: str) -> str:
    user_prompt = (prompt or "").strip()
    if not user_prompt:
        user_prompt = "Create a knowledge base structure."
    return generate_gemini_text(
        [user_prompt],
        system_prompt=KB_SYSTEM_PROMPT,
        temperature=0.4,
        top_p=0.9,
        max_output_tokens=8000,
    )


def generate_organiser_yaml_with_gemini(prompt: str) -> str:
    user_prompt = (prompt or "").strip()
    if not user_prompt:
        user_prompt = "Categorize the guides into the KB folders."
    return generate_gemini_text(
        [user_prompt],
        system_prompt=ORGANISER_SYSTEM_PROMPT,
        temperature=0.2,
        top_p=0.9,
        max_output_tokens=12000,
    )


def _extract_first_url(text: str) -> Optional[str]:
    if not text:
        return None
    match = re.search(r"https?://[^\s\"'<>]+", text.strip())
    if match:
        return match.group(0).rstrip(".,);")
    match = re.search(r"www\.[^\s\"'<>]+", text.strip())
    if match:
        return "https://" + match.group(0).rstrip(".,);")
    return None


def _normalize_url(raw: str) -> Optional[str]:
    if not raw:
        return None
    text = raw.strip()
    text = text.strip().strip('"').strip("'")
    if text.startswith("www."):
        text = "https://" + text
    if not re.match(r"^https?://", text, re.I):
        text = "https://" + text
    try:
        parsed = urlparse(text)
    except Exception:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return text


def _brand_request_headers(url: Optional[str] = None, accept: Optional[str] = None) -> dict[str, str]:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": accept
        or "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade-Insecure-Requests": "1",
    }
    if url:
        try:
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                headers["Referer"] = f"{parsed.scheme}://{parsed.netloc}/"
                headers["Origin"] = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass
    return headers


def _sanitize_inline_svg(svg_text: str) -> str:
    if not svg_text:
        return svg_text
    # Vue scoped attributes like data-v-xxxx are boolean in HTML; SVG XML requires values.
    svg_text = re.sub(r'(\s)(data-[A-Za-z0-9_-]+)(?=[\s>])', r'\1\2=""', svg_text)
    # Replace CSS-driven fills with a concrete color so standalone SVGs render.
    svg_text = re.sub(r'fill="currentColor"', 'fill="#000000"', svg_text, flags=re.I)
    svg_text = re.sub(r'stroke="currentColor"', 'stroke="#000000"', svg_text, flags=re.I)
    svg_text = _ensure_svg_dimensions(svg_text)
    return svg_text


def _parse_numeric_size(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)", value)
    if not match:
        return None
    try:
        return float(match.group(1))
    except Exception:
        return None


def _parse_sizes_attr(value: Optional[str]) -> Optional[Tuple[float, float]]:
    if not value:
        return None
    match = re.search(r"([0-9]+)\s*x\s*([0-9]+)", value)
    if not match:
        return None
    try:
        return float(match.group(1)), float(match.group(2))
    except Exception:
        return None


def _parse_widths_attr(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    numbers = [int(n) for n in re.findall(r"\d+", value)]
    if not numbers:
        return None
    return max(numbers)


def _resolve_cmp_src(src: str, attrs: dict[str, str]) -> str:
    if not src:
        return src
    if "{width}" in src:
        widths = attrs.get("data-cmp-widths") or attrs.get("data-widths")
        max_width = _parse_widths_attr(widths)
        if max_width:
            return src.replace("{width}", str(max_width))
    return src


def _pick_best_src_from_srcset(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    best_url = None
    best_score = -1
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        bits = item.split()
        url = bits[0]
        score = 0
        if len(bits) > 1:
            desc = bits[1].strip().lower()
            if desc.endswith("w"):
                try:
                    score = int(float(desc[:-1]))
                except Exception:
                    score = 0
            elif desc.endswith("x"):
                try:
                    score = int(float(desc[:-1]) * 1000)
                except Exception:
                    score = 0
        if score >= best_score:
            best_score = score
            best_url = url
    return best_url


def _pick_lazy_image_source(attrs: dict[str, str]) -> tuple[Optional[str], Optional[str]]:
    srcset = attrs.get("srcset") or attrs.get("data-srcset") or ""
    best_from_srcset = _pick_best_src_from_srcset(srcset) if srcset else None
    src = (
        attrs.get("src")
        or attrs.get("data-src")
        or attrs.get("data-lazy-src")
        or attrs.get("data-original")
        or best_from_srcset
    )
    if src and "{width}" in src:
        src = _resolve_cmp_src(src, attrs)
    if best_from_srcset and "{width}" in best_from_srcset:
        best_from_srcset = _resolve_cmp_src(best_from_srcset, attrs)
    return src, best_from_srcset


def _parse_viewbox_size(value: Optional[str]) -> Optional[Tuple[float, float]]:
    if not value:
        return None
    match = re.findall(r"-?\d+(?:\.\d+)?", value)
    if len(match) < 4:
        return None
    try:
        return float(match[2]), float(match[3])
    except Exception:
        return None


def _format_svg_dimension(value: float) -> str:
    if value is None:
        return ""
    if abs(value - round(value)) < 0.01:
        return str(int(round(value)))
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _ensure_svg_dimensions(svg_text: str) -> str:
    if not svg_text:
        return svg_text
    match = re.search(r"<svg\b[^>]*>", svg_text, flags=re.I)
    if not match:
        return svg_text
    tag = match.group(0)

    def _attr_value(name: str) -> Optional[str]:
        m = re.search(rf"\b{name}\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", tag, flags=re.I)
        if not m:
            return None
        value = m.group(1)
        if value and value[0] in {"\"", "'"}:
            return value[1:-1]
        return value

    width_val = _parse_numeric_size(_attr_value("width"))
    height_val = _parse_numeric_size(_attr_value("height"))
    if width_val is not None and height_val is not None:
        return svg_text

    ratio = None
    vb = _parse_viewbox_size(_attr_value("viewbox"))
    if vb:
        vb_w, vb_h = vb
        if vb_w and vb_h:
            ratio = vb_w / vb_h
    if ratio is None or ratio <= 0:
        ratio = 264 / 36

    target_w = 264.0
    target_h = 36.0
    target_ratio = target_w / target_h
    if ratio >= target_ratio:
        new_w = target_w
        new_h = target_w / ratio
    else:
        new_h = target_h
        new_w = target_h * ratio

    width_str = _format_svg_dimension(new_w)
    height_str = _format_svg_dimension(new_h)

    def _strip_attr(text: str, name: str) -> str:
        return re.sub(rf"\s{name}\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", text, flags=re.I)

    new_tag = _strip_attr(tag, "width")
    new_tag = _strip_attr(new_tag, "height")
    new_tag = re.sub(
        r"<svg\b",
        f'<svg width="{width_str}" height="{height_str}"',
        new_tag,
        count=1,
        flags=re.I,
    )
    return svg_text[:match.start()] + new_tag + svg_text[match.end():]


class _LogoHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.candidates: list[dict[str, Any]] = []
        self.base_href: Optional[str] = None
        self._stack: list[tuple[str, dict[str, str]]] = []
        self._in_svg = False
        self._svg_depth = 0
        self._svg_chunks: list[str] = []
        self._svg_attrs: dict[str, str] = {}
        self._svg_context: list[tuple[str, dict[str, str]]] = []
        self.stylesheets: list[str] = []
        self.inline_styles: list[str] = []
        self.style_blocks: list[str] = []
        self._in_style = False
        self._style_chunks: list[str] = []

    def _stack_hint(self) -> str:
        parts: list[str] = []
        for _, attrs in self._stack:
            for key in ("class", "id", "aria-label", "title"):
                val = attrs.get(key)
                if val:
                    parts.append(val)
        return " ".join(parts).lower()

    def handle_starttag(self, tag, attrs):
        attrs_map = {k.lower(): (v or "") for k, v in attrs}
        self._stack.append((tag, attrs_map))
        context_hint = self._stack_hint()
        inline_style = attrs_map.get("style")
        if inline_style:
            self.inline_styles.append(inline_style)
        if tag == "base" and "href" in attrs_map:
            self.base_href = attrs_map.get("href") or self.base_href
            return
        if tag == "style":
            self._in_style = True
            self._style_chunks = []
            return
        cmp_src = attrs_map.get("data-cmp-src")
        if cmp_src:
            resolved = _resolve_cmp_src(cmp_src, attrs_map)
            hint = " ".join([context_hint, resolved]).lower()
            score = 0
            if "logo" in hint:
                score = 92
            elif "brand" in hint:
                score = 82
            if score:
                width = _parse_numeric_size(attrs_map.get("width"))
                height = _parse_numeric_size(attrs_map.get("height"))
                self.candidates.append({
                    "url": resolved,
                    "score": score,
                    "reason": "data-cmp-src",
                    "width": width,
                    "height": height,
                })
        if self._in_svg:
            text = self.get_starttag_text() or ""
            if text:
                self._svg_chunks.append(text)
        if tag == "svg":
            if not self._in_svg:
                self._svg_chunks = []
                self._svg_attrs = attrs_map
                self._svg_context = list(self._stack[:-1])
            self._in_svg = True
            self._svg_depth += 1
            text = self.get_starttag_text() or ""
            if text:
                self._svg_chunks.append(text)
            return
        if tag == "meta":
            prop = (attrs_map.get("property") or attrs_map.get("name") or attrs_map.get("itemprop") or "").lower()
            if prop in {"og:image", "twitter:image", "image"}:
                content = attrs_map.get("content")
                if content:
                    self.candidates.append({"url": content, "score": 90, "reason": prop})
            return
        if tag == "link":
            rel = (attrs_map.get("rel") or "").lower()
            href = attrs_map.get("href")
            if not href:
                return
            if "stylesheet" in rel:
                self.stylesheets.append(href)
            score = 0
            if "apple-touch-icon" in rel:
                score = 80
            elif "icon" in rel:
                score = 60
            elif "mask-icon" in rel:
                score = 50
            if score:
                sizes = (attrs_map.get("sizes") or "").lower()
                if sizes:
                    score += 5
                size_tuple = _parse_sizes_attr(sizes)
                width, height = (size_tuple if size_tuple else (None, None))
                self.candidates.append({
                    "url": href,
                    "score": score,
                    "reason": rel,
                    "width": width,
                    "height": height,
                })
            return
        if tag == "img":
            src, best_srcset = _pick_lazy_image_source(attrs_map)
            if not src:
                return
            hint = " ".join([
                attrs_map.get("alt", ""),
                attrs_map.get("class", ""),
                attrs_map.get("id", ""),
                attrs_map.get("aria-label", ""),
                attrs_map.get("title", ""),
                src,
                best_srcset or "",
            ]).lower()
            score = 0
            if "logo" in hint:
                score = 90
            elif "brand" in hint:
                score = 80
            elif "logo" in context_hint:
                score = 75
            elif "brand" in context_hint:
                score = 65
            if score:
                width = _parse_numeric_size(attrs_map.get("width"))
                height = _parse_numeric_size(attrs_map.get("height"))
                self.candidates.append({
                    "url": best_srcset or src,
                    "score": score,
                    "reason": "img",
                    "width": width,
                    "height": height,
                })

    def handle_data(self, data):
        if self._in_style and data:
            self._style_chunks.append(data)
        if self._in_svg and data:
            self._svg_chunks.append(data)

    def handle_endtag(self, tag):
        if self._in_style and tag == "style":
            block = "".join(self._style_chunks).strip()
            if block:
                self.style_blocks.append(block)
            self._style_chunks = []
            self._in_style = False
        if self._in_svg:
            self._svg_chunks.append(f"</{tag}>")
            if tag == "svg":
                self._svg_depth -= 1
                if self._svg_depth <= 0:
                    svg_text = "".join(self._svg_chunks).strip()
                    hint = " ".join([
                        self._stack_hint(),
                        " ".join([
                            self._svg_attrs.get("class", ""),
                            self._svg_attrs.get("id", ""),
                            self._svg_attrs.get("aria-label", ""),
                            self._svg_attrs.get("title", ""),
                        ]).lower(),
                    ])
                    score = 55
                    if "logo" in hint:
                        score = 95
                    elif "brand" in hint:
                        score = 85
                    if svg_text and len(svg_text) < 200000:
                        try:
                            svg_clean = _sanitize_inline_svg(svg_text)
                            svg_bytes = svg_clean.encode("utf-8")
                            data_url = "data:image/svg+xml;base64," + base64.b64encode(svg_bytes).decode("ascii")
                            width = _parse_numeric_size(self._svg_attrs.get("width"))
                            height = _parse_numeric_size(self._svg_attrs.get("height"))
                            if width is None or height is None:
                                vb = _parse_viewbox_size(self._svg_attrs.get("viewbox"))
                                if vb:
                                    width, height = vb
                            self.candidates.append({
                                "url": data_url,
                                "score": score,
                                "reason": "inline-svg",
                                "width": width,
                                "height": height,
                            })
                        except Exception:
                            pass
                    self._in_svg = False
                    self._svg_chunks = []
                    self._svg_attrs = {}
                    self._svg_context = []
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)


def _pick_top_logos(candidates: list[dict[str, Any]], base_url: str) -> list[str]:
    seen = set()
    scored: list[tuple[int, str]] = []
    for item in candidates:
        raw_url = str(item.get("url") or "").strip()
        if not raw_url:
            continue
        width = item.get("width")
        height = item.get("height")
        if isinstance(width, (int, float)) and isinstance(height, (int, float)):
            if max(width, height) <= 32:
                continue
        abs_url = raw_url if raw_url.startswith("data:") else urljoin(base_url, raw_url)
        if abs_url in seen:
            continue
        seen.add(abs_url)
        score = int(item.get("score") or 0)
        scored.append((score, abs_url))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [u for _, u in scored[:3]]


def _normalize_hex_color(value: str) -> Optional[str]:
    if not value:
        return None
    color = value.strip().lower()
    if not color.startswith("#"):
        return None
    if len(color) == 4:
        color = "#" + "".join([c * 2 for c in color[1:]])
    if len(color) != 7:
        return None
    if not re.match(r"^#[0-9a-f]{6}$", color):
        return None
    return color.upper()


def _rgb_to_hex(r: float, g: float, b: float) -> str:
    return "#{:02X}{:02X}{:02X}".format(
        max(0, min(255, round(r))),
        max(0, min(255, round(g))),
        max(0, min(255, round(b))),
    )


def _parse_rgb_values(match_text: str) -> Optional[str]:
    parts = [p.strip() for p in match_text.split(",")]
    if len(parts) < 3:
        return None
    vals = []
    for part in parts[:3]:
        if part.endswith("%"):
            try:
                pct = float(part.rstrip("%"))
                vals.append(pct / 100 * 255)
            except Exception:
                return None
        else:
            try:
                vals.append(float(part))
            except Exception:
                return None
    if len(parts) >= 4:
        try:
            alpha = float(parts[3])
            if alpha <= 0.05:
                return None
        except Exception:
            pass
    return _rgb_to_hex(vals[0], vals[1], vals[2])


def _extract_colors_from_css(text: str) -> list[str]:
    colors: list[str] = []
    if not text:
        return colors
    for match in re.findall(r"#[0-9a-fA-F]{3,6}", text):
        normalized = _normalize_hex_color(match)
        if normalized:
            colors.append(normalized)
    for match in re.findall(r"rgba?\(([^)]+)\)", text, re.I):
        hex_color = _parse_rgb_values(match)
        if hex_color:
            colors.append(hex_color)
    return colors


def _hex_to_rgb(color: str) -> Tuple[int, int, int]:
    h = color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _color_distance(a: str, b: str) -> float:
    r1, g1, b1 = _hex_to_rgb(a)
    r2, g2, b2 = _hex_to_rgb(b)
    return ((r1 - r2) ** 2 + (g1 - g2) ** 2 + (b1 - b2) ** 2) ** 0.5


def _is_near_white(color: str) -> bool:
    r, g, b = _hex_to_rgb(color)
    return r >= 245 and g >= 245 and b >= 245


def _is_near_black(color: str) -> bool:
    r, g, b = _hex_to_rgb(color)
    return r <= 12 and g <= 12 and b <= 12


def _pick_distinct_colors(counts: "collections.Counter[str]", limit: int = 3) -> list[str]:
    if not counts:
        return []
    ordered = [c for c, _ in counts.most_common()]
    selected: list[str] = []
    for color in ordered:
        if _is_near_white(color) or _is_near_black(color):
            continue
        if all(_color_distance(color, s) >= 80 for s in selected):
            selected.append(color)
        if len(selected) >= limit:
            return selected
    for color in ordered:
        if color in selected:
            continue
        if all(_color_distance(color, s) >= 40 for s in selected):
            selected.append(color)
        if len(selected) >= limit:
            break
    return selected[:limit]


def generate_brand_website_with_gemini(brand_name: str) -> str:
    prompt = f"Can you give me the main website for {brand_name}? Only output the URL and nothing else."
    return generate_gemini_text(
        [prompt],
        system_prompt=WEBSITE_SYSTEM_PROMPT,
        temperature=0.1,
        top_p=0.9,
        max_output_tokens=400,
    )


def _extract_colors_from_text(raw: str) -> dict:
    text = (raw or "").strip()
    if not text:
        raise ValueError("Empty color response")
    patterns = {
        "headerBackground": r"(header[^#\n]*|header\s*background[^#\n]*)(#[0-9a-fA-F]{6})",
        "iconColor": r"(icon[^#\n]*)(#[0-9a-fA-F]{6})",
        "highlightColor": r"(highlight[^#\n]*)(#[0-9a-fA-F]{6})",
    }
    found: dict[str, str] = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.I)
        if match:
            found[key] = match.group(2).upper()
    if len(found) == 3:
        return found

    candidates = re.findall(r"#[0-9a-fA-F]{6}", text)
    uniq = []
    for code in candidates:
        up = code.upper()
        if up not in uniq:
            uniq.append(up)
    if len(uniq) >= 3:
        return {
            "headerBackground": found.get("headerBackground", uniq[0]),
            "iconColor": found.get("iconColor", uniq[1]),
            "highlightColor": found.get("highlightColor", uniq[2]),
        }
    raise ValueError("Invalid color JSON")


def _parse_colors_payload(text: str) -> dict:
    raw = (text or "").strip()
    if not raw:
        raise ValueError("Empty color response")
    data = None
    try:
        data = yaml.safe_load(raw)
    except Exception:
        data = None
    if isinstance(data, dict):
        normalized = {str(k).strip(): v for k, v in data.items()}
        required = ["headerBackground", "iconColor", "highlightColor"]
        out: dict[str, str] = {}
        for key in required:
            if key not in normalized:
                break
            value = str(normalized[key]).strip()
            if not re.match(r"^#[0-9a-fA-F]{6}$", value):
                break
            out[key] = value.upper()
        if len(out) == 3:
            return out

    return _extract_colors_from_text(raw)


def generate_brand_colors_with_gemini(brand_name: str, url: Optional[str] = None) -> dict:
    base_prompt = (
        "Provide me with 3 colors that would work well for a "
        f"{brand_name} help center, knowing these are the 3 colors I am looking for:\n"
        "- header background color, which will be the background color of the upper part of the page on the KB, including around the search bar\n"
        "- default icons color, which will be the color of the icons for the folders and categories of the KB\n"
        "- highlight color, which will be the color border of a category when we highlight it, color of the guides inside the folders, and color of the search button."
    )
    if url:
        base_prompt = base_prompt + f"\n\nFYI the brand website is: {url}"
    raw = generate_gemini_text(
        [base_prompt],
        system_prompt=COLORS_SYSTEM_PROMPT,
        temperature=0.7,
        top_p=0.9,
        max_output_tokens=1200,
    )
    logger.info("Gemini color response (raw): %s", raw)
    try:
        return _parse_colors_payload(raw)
    except Exception as e:
        logger.exception("Color parse failed: %s", raw)
        raise e


def parse_guide_yaml(source: str, defaults: GuideDefaults) -> GuideDefinition:
    text = (source or "").strip()
    if not text:
        raise HTTPException(400, detail={"error": "YAML payload is required"})
    text = fix_pre_block_indentation(text)
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
    text = fix_pre_block_indentation(text)

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
            # Only send explicit positions; Stonly rejects implicit indices when appending.
            position_value = choice.position
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
        # Only send explicit positions; otherwise let Stonly append in creation order.
        position_value = choice.position if choice.position is not None else step.position

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
@app.post("/api/signup", tags=["Auth"], summary="Create account and session")
def api_signup(payload: SignupPayload):
    if payload.adminToken != ADMIN_TOKEN:
        raise HTTPException(401, detail="Invalid admin token")
    email = _normalize_email(payload.email)
    with SessionLocal() as db:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            raise HTTPException(409, detail="Email already registered")
        user = User(email=email, password_hash=_hash_password(payload.password))
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, detail="Email already registered")
        db.refresh(user)
        sid = _create_session(db, user.id)
    resp = JSONResponse({"ok": True, "email": email})
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


@app.post("/api/login", tags=["Auth"], summary="Obtain account session")
def api_login(payload: LoginPayload):
    email = _normalize_email(payload.email)
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        if not user or not _verify_password(payload.password, user.password_hash):
            raise HTTPException(401, detail="Invalid email or password")
        sid = _create_session(db, user.id)
    resp = JSONResponse({"ok": True, "email": email})
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


@app.get("/api/auth/google", tags=["Auth"], summary="Start Google OAuth login")
def api_auth_google(next: Optional[str] = None):
    if not _google_enabled():
        raise HTTPException(500, detail="Google OAuth is not configured")
    next_path = _sanitize_next(next)
    return RedirectResponse(_google_authorize_url(next_path))


@app.get("/api/auth/google/callback", tags=["Auth"], summary="Handle Google OAuth callback")
def api_auth_google_callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
):
    if error:
        return _redirect_to_login("/", error=error)
    if not _google_enabled():
        return _redirect_to_login("/", error="google_not_configured")
    if not code:
        return _redirect_to_login("/", error="missing_code")
    try:
        payload = _state_verify(state or "")
        next_path = _sanitize_next(payload.get("next"))
    except Exception:
        return _redirect_to_login("/", error="invalid_state")

    token_res = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        },
        timeout=10,
    )
    if not token_res.ok:
        logger.warning("Google token exchange failed: %s", token_res.text)
        return _redirect_to_login(next_path, error="token_exchange_failed")
    token_data = token_res.json()
    id_token = token_data.get("id_token")
    if not id_token:
        return _redirect_to_login(next_path, error="missing_id_token")

    info_res = requests.get(
        "https://oauth2.googleapis.com/tokeninfo",
        params={"id_token": id_token},
        timeout=10,
    )
    if not info_res.ok:
        logger.warning("Google tokeninfo failed: %s", info_res.text)
        return _redirect_to_login(next_path, error="tokeninfo_failed")
    info = info_res.json()
    if info.get("aud") != GOOGLE_CLIENT_ID:
        return _redirect_to_login(next_path, error="aud_mismatch")
    if str(info.get("email_verified", "")).lower() != "true":
        return _redirect_to_login(next_path, error="email_not_verified")
    email = (info.get("email") or "").strip().lower()
    if not email:
        return _redirect_to_login(next_path, error="missing_email")
    if GOOGLE_ALLOWED_DOMAIN:
        domain = (info.get("hd") or email.split("@")[-1]).lower()
        if domain != GOOGLE_ALLOWED_DOMAIN.lower():
            return _redirect_to_login(next_path, error="domain_not_allowed")

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(email=email, password_hash=_hash_password(uuid.uuid4().hex))
            db.add(user)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                user = db.query(User).filter(User.email == email).first()
        if not user:
            return _redirect_to_login(next_path, error="user_create_failed")
        sid = _create_session(db, user.id)

    resp = RedirectResponse(_frontend_origin() + next_path)
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


@app.post("/api/password/reset", tags=["Auth"], summary="Reset password with admin token")
def api_reset_password(payload: ResetPasswordPayload):
    if payload.adminToken != ADMIN_TOKEN:
        raise HTTPException(401, detail="Invalid admin token")
    email = _normalize_email(payload.email)
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(404, detail="User not found")
        user.password_hash = _hash_password(payload.newPassword)
        db.query(UserSession).filter(UserSession.user_id == user.id).delete()
        db.commit()
    return {"ok": True}


@app.post("/api/logout", tags=["Auth"], summary="Clear session")
def api_logout(request: Request):
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    with SessionLocal() as db:
        _clear_session(db, sid)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return resp


@app.get("/api/auth/status", tags=["Auth"], summary="Check session")
def api_auth_status(request: Request):
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
    return {"ok": True, "email": user.email}


@app.get("/api/settings", tags=["Settings"], summary="Get account settings")
def api_get_settings(request: Request):
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
    return {"ok": True, "apiBase": user.api_base}


@app.put("/api/settings", tags=["Settings"], summary="Update account settings")
def api_update_settings(payload: UserSettingsPayload, request: Request):
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
        fields_set = getattr(payload, "model_fields_set", set())
        if "apiBase" in fields_set:
            user.api_base = payload.apiBase
        db.commit()
        db.refresh(user)
    return {"ok": True, "apiBase": user.api_base}


@app.get("/api/teams", tags=["Teams"], summary="List teams for current user")
def api_list_teams(request: Request):
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
        teams = db.query(Team).filter(Team.user_id == user.id).order_by(Team.created_at.asc()).all()
        payload = [
            {
                "id": t.id,
                "teamId": t.team_id,
                "name": t.name,
                "rootFolder": t.root_folder,
                "createdAt": t.created_at.isoformat() if t.created_at else None,
            }
            for t in teams
        ]
    return {"ok": True, "teams": payload}


@app.post("/api/teams", tags=["Teams"], summary="Create a team")
def api_create_team(payload: TeamCreatePayload, request: Request):
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
        team = Team(
            user_id=user.id,
            team_id=payload.teamId,
            token_encrypted=_encrypt_team_token(payload.teamToken),
            name=payload.name,
            root_folder=payload.rootFolder,
            created_at=_utcnow(),
            updated_at=_utcnow(),
        )
        db.add(team)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, detail="Team already exists")
        db.refresh(team)
    return {
        "ok": True,
        "team": {
            "id": team.id,
            "teamId": team.team_id,
            "name": team.name,
            "rootFolder": team.root_folder,
        },
    }


@app.put("/api/teams/{team_id}", tags=["Teams"], summary="Update a team")
def api_update_team(team_id: int, payload: TeamUpdatePayload, request: Request):
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
        team = db.query(Team).filter(Team.user_id == user.id, Team.id == team_id).first()
        if not team:
            raise HTTPException(404, detail="Team not found")
        fields_set = getattr(payload, "model_fields_set", set())
        if "teamId" in fields_set:
            team.team_id = payload.teamId
        if "teamToken" in fields_set:
            if not payload.teamToken:
                raise HTTPException(400, detail="teamToken cannot be empty")
            team.token_encrypted = _encrypt_team_token(payload.teamToken)
        if "name" in fields_set:
            team.name = payload.name
        if "rootFolder" in fields_set:
            team.root_folder = payload.rootFolder
        team.updated_at = _utcnow()
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, detail="Team already exists")
    return {"ok": True}


@app.delete("/api/teams/{team_id}", tags=["Teams"], summary="Delete a team")
def api_delete_team(team_id: int, request: Request):
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
        team = db.query(Team).filter(Team.user_id == user.id, Team.id == team_id).first()
        if not team:
            raise HTTPException(404, detail="Team not found")
        db.delete(team)
        db.commit()
    return {"ok": True}


@app.post("/api/apply", tags=["Builder"], summary="Apply folder structure")
def api_apply(payload: ApplyPayload, request: Request):
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
        st, _team = get_stonly_client_for_team(
            db,
            user_id=user.id,
            team_id=payload.creds.teamId,
            base=payload.creds.base,
            user_label=payload.creds.user,
        )
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
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
        st, _team = get_stonly_client_for_team(
            db,
            user_id=user.id,
            team_id=payload.creds.teamId,
            base=payload.creds.base,
            user_label=payload.creds.user,
        )
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


def api_build_guide(payload: GuideBuildPayload, *, user_id: Optional[int] = None):
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

    if user_id is None and payload.creds.password and ALLOW_LOCAL_TESTING_MODE:
        st = Stonly(
            base=payload.creds.base,
            user=payload.creds.user,
            password=payload.creds.password,
            team_id=payload.creds.teamId,
        )
    else:
        if user_id is None:
            raise HTTPException(401, detail="Missing session")
        with SessionLocal() as db:
            st, _team = get_stonly_client_for_team(
                db,
                user_id=user_id,
                team_id=payload.creds.teamId,
                base=payload.creds.base,
                user_label=payload.creds.user,
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
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
        st, _team = get_stonly_client_for_team(
            db,
            user_id=user.id,
            team_id=payload.creds.teamId,
            base=payload.creds.base,
            user_label=payload.creds.user,
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
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
    return api_build_guide(payload, user_id=user.id)


@app.post(
    "/api/ai-guides/build",
    tags=["Builder"],
    summary="Generate guide YAML via Gemini, then build/publish it",
)
def api_ai_guides_build(payload: AIGuidePayload, request: Request):
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
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

    # 3) Build using existing pipeline (use stored team token)
    dry_run_flag = bool(payload.dryRun or testing_mode_active)
    build_payload = GuideBuildPayload(
        creds=Creds(
            user="Undefined",
            teamId=payload.teamId,
            base=payload.base,
        ),
        folderId=payload.folderId,
        yaml=yaml_text,
        dryRun=dry_run_flag,
        defaults=GuideDefaults(),
        publish=False if testing_mode_active else payload.publish,
    )

    try:
        build_result = api_build_guide(build_payload, user_id=user.id)
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


@app.post(
    "/api/ai-kb/generate",
    tags=["Builder"],
    summary="Generate KB YAML via Gemini",
)
def api_ai_kb_generate(payload: AIPromptPayload, request: Request):
    with SessionLocal() as db:
        _user = get_user_from_request(db, request)
    request_id = str(uuid.uuid4())
    logger.info("REQUEST %s :: /api/ai-kb/generate", request_id)
    raw_yaml = generate_kb_yaml_with_gemini(payload.prompt or "")
    yaml_text = normalize_ai_yaml(raw_yaml)
    return {"ok": True, "yaml": yaml_text}


@app.post(
    "/api/ai-organiser/generate",
    tags=["Builder"],
    summary="Generate Guide Organiser YAML via Gemini",
)
def api_ai_organiser_generate(payload: AIPromptPayload, request: Request):
    with SessionLocal() as db:
        _user = get_user_from_request(db, request)
    request_id = str(uuid.uuid4())
    logger.info("REQUEST %s :: /api/ai-organiser/generate", request_id)
    raw_yaml = generate_organiser_yaml_with_gemini(payload.prompt or "")
    yaml_text = normalize_ai_yaml(raw_yaml)
    return {"ok": True, "yaml": yaml_text}


@app.post(
    "/api/ai-brand-website",
    tags=["Builder"],
    summary="Resolve brand website via Gemini",
)
def api_ai_brand_website(payload: BrandWebsitePayload, request: Request):
    with SessionLocal() as db:
        _user = get_user_from_request(db, request)
    request_id = str(uuid.uuid4())
    logger.info("REQUEST %s :: /api/ai-brand-website", request_id)
    raw = generate_brand_website_with_gemini(payload.brandName)
    url = _extract_first_url(raw) or raw
    normalized = _normalize_url(url)
    if not normalized:
        raise HTTPException(502, detail={"error": "Invalid URL from Gemini", "raw": raw})
    return {"ok": True, "url": normalized}


@app.post(
    "/api/ai-brand-colors",
    tags=["Builder"],
    summary="Generate brand colors via Gemini",
)
def api_ai_brand_colors(payload: BrandColorsPayload, request: Request):
    with SessionLocal() as db:
        _user = get_user_from_request(db, request)
    request_id = str(uuid.uuid4())
    logger.info("REQUEST %s :: /api/ai-brand-colors", request_id)
    try:
        colors = generate_brand_colors_with_gemini(payload.brandName, payload.url)
    except Exception as e:
        raise HTTPException(502, detail={"error": "Failed to parse colors", "message": str(e)})
    return {"ok": True, "colors": colors}


@app.post(
    "/api/brand-assets/scrape",
    tags=["Builder"],
    summary="Scrape logo candidates from a brand website",
)
def api_brand_assets_scrape(payload: BrandAssetsPayload, request: Request):
    with SessionLocal() as db:
        _user = get_user_from_request(db, request)
    url = _normalize_url(payload.url)
    if not url:
        raise HTTPException(400, detail="Invalid URL")
    headers = _brand_request_headers(url)
    try:
        resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
    except Exception as e:
        raise HTTPException(502, detail={"error": "Failed to fetch URL", "message": str(e)})
    if resp.status_code == 403:
        try:
            headers_retry = _brand_request_headers(resp.url or url)
            resp_retry = requests.get(url, headers=headers_retry, timeout=10, allow_redirects=True)
            if resp_retry.ok:
                resp = resp_retry
        except Exception:
            pass
    if not resp.ok:
        raise HTTPException(502, detail={"error": "Upstream returned error", "status": resp.status_code})
    content_type = (resp.headers.get("content-type") or "").lower()
    if "text/html" not in content_type:
        raise HTTPException(502, detail={"error": "URL did not return HTML"})

    base_url = resp.url or url
    parser = _LogoHTMLParser()
    try:
        parser.feed(resp.text)
    except Exception:
        pass
    if parser.base_href:
        base_url = urljoin(base_url, parser.base_href)

    logos = _pick_top_logos(parser.candidates, base_url)
    colors: list[str] = []
    css_sources: list[str] = []
    css_sources.extend(parser.style_blocks)
    css_sources.extend(parser.inline_styles)
    for href in parser.stylesheets[:4]:
        css_url = urljoin(base_url, href)
        try:
            css_resp = requests.get(css_url, headers=headers, timeout=8)
            if css_resp.ok:
                css_sources.append(css_resp.text)
        except Exception:
            continue
    for src in css_sources:
        colors.extend(_extract_colors_from_css(src))
    counts = collections.Counter(colors)
    site_colors = _pick_distinct_colors(counts, limit=3)
    if not logos:
        fallback = [
            urljoin(base_url, "/apple-touch-icon.png"),
            urljoin(base_url, "/favicon.ico"),
        ]
        logos = [u for u in fallback if u][:3]

    return {"ok": True, "url": base_url, "logos": logos, "siteColors": site_colors}


@app.get(
    "/api/brand-assets/download",
    tags=["Builder"],
    summary="Proxy logo download",
)
def api_brand_assets_download(url: str, request: Request):
    with SessionLocal() as db:
        _user = get_user_from_request(db, request)
    normalized = _normalize_url(url)
    if not normalized:
        raise HTTPException(400, detail="Invalid URL")
    headers = _brand_request_headers(
        normalized,
        accept="image/avif,image/webp,image/*,*/*;q=0.8",
    )
    try:
        resp = requests.get(normalized, headers=headers, timeout=10, stream=True)
    except Exception as e:
        raise HTTPException(502, detail={"error": "Failed to fetch asset", "message": str(e)})
    if not resp.ok:
        raise HTTPException(502, detail={"error": "Asset fetch failed", "status": resp.status_code})
    content_type = resp.headers.get("content-type") or "application/octet-stream"
    filename = os.path.basename(urlparse(normalized).path) or "logo"
    headers_out = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if "svg" in content_type.lower() or normalized.lower().endswith(".svg"):
        try:
            raw = resp.content
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
            if "<svg" in text.lower():
                svg_text = _sanitize_inline_svg(text)
                return Response(
                    content=svg_text.encode("utf-8"),
                    media_type="image/svg+xml",
                    headers=headers_out,
                )
        except Exception:
            pass
    return StreamingResponse(resp.iter_content(chunk_size=8192), media_type=content_type, headers=headers_out)

@app.get("/api/dump-structure", tags=["Structure"], summary="Dump folder tree")
def api_dump(
    request: Request,
    teamId: int = ...,
    parentId: Optional[int] = None,
    base: Optional[str] = None,
    flat: Optional[bool] = False,
):
    with SessionLocal() as db:
        user = get_user_from_request(db, request)
        st, _team = get_stonly_client_for_team(
            db,
            user_id=user.id,
            team_id=int(teamId),
            base=base,
            user_label="Undefined",
        )

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

    if flat:
        return {"items": items}

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
        by_id[_id] = {"id": _id, "name": _nm, "children": []}
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
    user = os.getenv("STONLY_USER")
    password = os.getenv("STONLY_PASSWORD")
    team_id = int(os.getenv("TEAM_ID", "0") or "0")
    folder_id = int(os.getenv("FOLDER_ID", "0") or "0")

    if not all([user, password, team_id, folder_id]):
        raise SystemExit("Missing one of: STONLY_USER, STONLY_PASSWORD, TEAM_ID, FOLDER_ID")

    yaml_text = Path(args.yaml_file).read_text(encoding="utf-8")

    payload = GuideBuildPayload(
        creds=Creds(user=user, password=password, teamId=team_id),
        folderId=folder_id,
        yaml=yaml_text,
        dryRun=bool(args.dry_run),
        defaults=GuideDefaults(),
    )

    # Call the same core logic the API uses so behavior matches /api/guides/build
    out = api_build_guide(payload)
    print(json.dumps(out, indent=2))
