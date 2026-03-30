from __future__ import annotations

import importlib.util
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from llm_passthough_log.config import Settings
from llm_passthough_log.storage import LogStore, decode_payload, dumps_json, generate_api_key, hash_api_key, hash_password

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}

SENSITIVE_FIELD_NAMES = {
    "authorization",
    "proxy_authorization",
    "x_api_key",
    "api_key",
    "apikey",
    "downstream_apikey",
    "access_token",
    "refresh_token",
    "client_secret",
    "secret",
    "token",
}

BEARER_TOKEN_RE = re.compile(r"(?i)\bbearer\s+([^\s,;]+)")
SK_TOKEN_RE = re.compile(r"\bsk-[A-Za-z0-9._\-]+\b")
URL_HOST_RE = re.compile(r"(https?://)([^/:@\s]+)((?::\d+)?(?:/[^\s\"'<>]*)?)")

URL_FIELD_NAMES = {
    "url",
    "downstream_url",
    "base_url",
    "endpoint",
    "target_url",
}


def normalize_field_name(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def mask_secret(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return stripped
    if stripped.lower().startswith("sk-"):
        return "***" if len(stripped) <= 6 else "***..." + stripped[-4:]
    if len(stripped) <= 4:
        return "*" * len(stripped)
    if len(stripped) <= 8:
        return stripped[:1] + "***" + stripped[-1:]
    return stripped[:4] + "..." + stripped[-4:]


def mask_sensitive_text(value: str) -> str:
    stripped = value.strip()
    if stripped.lower().startswith("bearer "):
        token = stripped[7:].strip()
        return f"Bearer {mask_secret(token)}"
    return mask_secret(stripped)


def _mask_url_match(m: re.Match) -> str:
    scheme, host, rest = m.group(1), m.group(2), m.group(3) or ""
    if len(host) <= 4:
        masked = "*" * len(host)
    elif len(host) <= 8:
        masked = host[0] + "***" + host[-1]
    else:
        masked = host[:3] + "***" + host[-3:]
    return f"{scheme}{masked}{rest}"


def mask_url_host(value: str) -> str:
    """Mask the host portion of URLs in *value*."""
    return URL_HOST_RE.sub(_mask_url_match, value)


def sanitize_string_for_web(value: str, key_name: Optional[str] = None) -> str:
    if key_name and normalize_field_name(key_name) in SENSITIVE_FIELD_NAMES:
        return mask_sensitive_text(value)
    if key_name and normalize_field_name(key_name) in URL_FIELD_NAMES:
        return mask_url_host(value)

    masked = BEARER_TOKEN_RE.sub(lambda match: f"Bearer {mask_secret(match.group(1))}", value)
    return SK_TOKEN_RE.sub(lambda match: mask_secret(match.group(0)), masked)


import re as _re

_SHA256_HEX_RE = _re.compile(r'^[0-9a-f]{64}$')


def _extract_search_hashes(data: dict) -> list[str]:
    """Extract key hashes from search request data.

    Accepts ``key_hashes`` (pre-computed SHA-256 hex) or ``keys`` (raw, hashed
    server-side).  Returns a deduplicated list of hex hashes.
    """
    hashes: list[str] = []
    raw_hashes = data.get("key_hashes", [])
    if isinstance(raw_hashes, list):
        for h in raw_hashes:
            h = str(h).strip().lower()
            if _SHA256_HEX_RE.match(h):
                hashes.append(h)
    raw_keys = data.get("keys", [])
    if isinstance(raw_keys, list):
        for k in raw_keys:
            if isinstance(k, str) and k.strip():
                hashes.append(hash_api_key(k))
    return list(dict.fromkeys(hashes))  # deduplicate, preserve order


def sanitize_for_web(value: Any, *, key_name: Optional[str] = None) -> Any:
    if isinstance(value, dict):
        return {key: sanitize_for_web(item, key_name=key) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_for_web(item, key_name=key_name) for item in value]
    if isinstance(value, str):
        return sanitize_string_for_web(value, key_name=key_name)
    return value


def filter_request_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "host"
    }


def extract_bearer_token(headers: Dict[str, str]) -> Optional[str]:
    """Extract the raw Bearer token from request headers."""
    auth = headers.get("authorization", "") or headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return token
    return None


def filter_response_headers(headers: httpx.Headers) -> Dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def is_http2_available() -> bool:
    return importlib.util.find_spec("h2") is not None
    
def ensure_stream_usage(request_body: Any) -> Any:
    if not isinstance(request_body, dict) or not request_body.get("stream"):
        return request_body
    stream_options = request_body.get("stream_options")
    if isinstance(stream_options, dict) and stream_options.get("include_usage") is True:
        return request_body
    updated = dict(request_body)
    updated_stream_options = dict(stream_options) if isinstance(stream_options, dict) else {}
    updated_stream_options["include_usage"] = True
    updated["stream_options"] = updated_stream_options
    return updated


async def read_response_body(response: httpx.Response) -> bytes:
    if response.is_stream_consumed:
        return response.content
    return await response.aread()


async def stream_response_chunks(response: httpx.Response):
    if response.is_stream_consumed:
        yield response.content
        return
    async for chunk in response.aiter_raw():
        yield chunk


class Runtime:
    def __init__(self, settings: Settings, downstream_transport: Optional[httpx.AsyncBaseTransport] = None) -> None:
        self.settings = settings
        self.downstream_transport = downstream_transport
        self.log_store = LogStore(settings.jsonl_path, settings.sqlite_path, settings.queue_maxsize)
        self.http_client: Optional[httpx.AsyncClient] = None
        self._provider_cache: Dict[str, Dict[str, Any]] = {}
        self._sessions: Dict[str, Dict[str, Any]] = {}

    async def startup(self) -> None:
        await self.log_store.start()
        await self.refresh_provider_cache()
        timeout = httpx.Timeout(self.settings.request_timeout_seconds)
        transport = self.downstream_transport or httpx.AsyncHTTPTransport(
            retries=1,
            http2=is_http2_available(),
            limits=httpx.Limits(
                max_connections=200,
                max_keepalive_connections=40,
                keepalive_expiry=30,
            ),
        )
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
        )

    async def shutdown(self) -> None:
        if self.http_client is not None:
            await self.http_client.aclose()
        await self.log_store.stop()

    async def refresh_provider_cache(self) -> None:
        providers = await self.log_store.list_enabled_providers()
        self._provider_cache = {p["prefix_path"]: p for p in providers}

    def resolve_target(self, path: str) -> Tuple[str, str, str]:
        normalized_path = path.lstrip("/")
        if normalized_path:
            prefix, _, remainder = normalized_path.partition("/")
            # Check DB providers first
            if prefix in self._provider_cache:
                p = self._provider_cache[prefix]
                target_base = p["downstream_url"].rstrip("/")
                target_path = f"/{remainder}" if remainder else ""
                return p["name"], target_base, f"{target_base}{target_path}"
            # Then check config provider_routes
            if prefix in self.settings.provider_routes:
                target_base = self.settings.provider_routes[prefix]
                suffix = remainder
                target_path = f"/{suffix}" if suffix else ""
                return prefix, target_base, f"{target_base}{target_path}"
        target_path = f"/{normalized_path}" if normalized_path else ""
        return self.settings.default_provider_name, self.settings.downstream_url, f"{self.settings.downstream_url}{target_path}"

    def get_provider_apikey(self, path: str) -> Optional[str]:
        """Return provider's downstream_apikey if path matches a DB provider."""
        normalized_path = path.lstrip("/")
        if normalized_path:
            prefix = normalized_path.partition("/")[0]
            p = self._provider_cache.get(prefix)
            if p and p.get("downstream_apikey"):
                return p["downstream_apikey"]
        return None

    def create_session(self, user: Dict[str, Any]) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = {
            "id": user["id"],
            "name": user["name"],
            "role": user.get("role", "user"),
            "enabled": user.get("enabled", 1),
        }
        return token

    def get_session_user(self, token: str) -> Optional[Dict[str, Any]]:
        return self._sessions.get(token)

    def delete_session(self, token: str) -> None:
        self._sessions.pop(token, None)


def create_app(
    settings: Optional[Settings] = None,
    *,
    downstream_transport: Optional[httpx.AsyncBaseTransport] = None,
) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    runtime = Runtime(resolved_settings, downstream_transport=downstream_transport)
    static_dir = Path(__file__).parent / "static"
    admin_html = static_dir / "admin.html"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await runtime.startup()
        app.state.runtime = runtime
        yield
        await runtime.shutdown()

    app = FastAPI(title=resolved_settings.app_name, lifespan=lifespan)
    app.mount("/admin/assets", StaticFiles(directory=static_dir), name="admin-assets")

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Dict[str, Any]:
        return {
            "status": "ok",
            "downstream_url": resolved_settings.downstream_url,
            "jsonl_path": str(resolved_settings.jsonl_path),
            "sqlite_path": str(resolved_settings.sqlite_path),
            "provider_routes": resolved_settings.provider_routes,
            "queue_size": runtime.log_store.queue_size,
        }

    @app.get("/admin", include_in_schema=False)
    @app.get("/admin/logs", include_in_schema=False)
    async def admin_page() -> FileResponse:
        return FileResponse(admin_html)

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        return Response(status_code=204)

    def _admin_user() -> Dict[str, Any]:
        return {
            "id": "__admin__",
            "name": resolved_settings.admin_username,
            "role": "admin",
            "enabled": 1,
        }

    def _serialize_user(user: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": user["id"],
            "name": user["name"],
            "role": user.get("role", "user"),
            "enabled": int(bool(user.get("enabled", 1))),
            "created_at": user.get("created_at"),
        }

    def _serialize_provider(provider: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "id": provider["id"],
            "name": sanitize_string_for_web(str(provider["name"])),
            "prefix_path": sanitize_string_for_web(str(provider["prefix_path"])),
            "downstream_url": mask_url_host(str(provider.get("downstream_url") or "")),
            "enabled": int(bool(provider.get("enabled", 1))),
            "input_price": provider.get("input_price", 0),
            "output_price": provider.get("output_price", 0),
            "notes": sanitize_for_web(provider.get("notes")),
            "created_at": provider.get("created_at"),
            "has_downstream_apikey": bool(provider.get("downstream_apikey")),
        }
        if provider.get("downstream_apikey"):
            payload["downstream_apikey_masked"] = mask_secret(str(provider["downstream_apikey"]))
        return payload

    async def _enqueue_sanitized_log(entry: Dict[str, Any]) -> None:
        # Store masked payloads to avoid leaking secrets from DB/jsonl exports.
        await runtime.log_store.enqueue(sanitize_for_web(entry))

    # ── Auth helpers ──────────────────────────────────────────────────────

    async def _resolve_user(request: Request) -> Optional[Dict[str, Any]]:
        token = request.headers.get("x-session-token", "") or request.headers.get("x-api-key", "")
        if not token:
            return None
        return runtime.get_session_user(token)

    def _require_admin(user: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not user:
            raise HTTPException(status_code=401, detail="authentication required")
        if user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="admin access required")
        return user

    def _require_auth(user: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not user:
            raise HTTPException(status_code=401, detail="authentication required")
        return user

    async def _get_allowed_providers(user: Dict[str, Any]) -> Optional[List[str]]:
        """Return provider prefix_path list for filtering. None means no filter (admin)."""
        if user.get("role") == "admin":
            return None
        return await runtime.log_store.get_user_allowed_providers(user["id"])

    # ── Session / Login ───────────────────────────────────────────────────

    @app.post("/admin/api/login", include_in_schema=False)
    async def admin_login(request: Request) -> Dict[str, Any]:
        data = await request.json()
        name = str(data.get("name", "")).strip()
        password = str(data.get("password", "")).strip()
        if not name or not password:
            raise HTTPException(status_code=422, detail="请提供用户名和密码")
        if name == resolved_settings.admin_username and password == resolved_settings.admin_password:
            admin_user = _admin_user()
            return {"user": _serialize_user(admin_user), "session_token": runtime.create_session(admin_user)}
        user = await runtime.log_store.get_user_by_credentials(name, password)
        if not user or not user.get("enabled"):
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        provider_ids = await runtime.log_store.get_user_provider_ids(user["id"])
        return {
            "user": _serialize_user(user),
            "session_token": runtime.create_session(user),
            "provider_ids": provider_ids,
        }

    @app.post("/admin/api/logout", include_in_schema=False)
    async def admin_logout(request: Request) -> Dict[str, Any]:
        token = request.headers.get("x-session-token", "") or request.headers.get("x-api-key", "")
        if token:
            runtime.delete_session(token)
        return {"ok": True}

    @app.get("/admin/api/session", include_in_schema=False)
    async def admin_session(request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        user = _require_auth(user)
        result: Dict[str, Any] = {"user": _serialize_user(user)}
        if user.get("role") == "admin":
            providers = await runtime.log_store.list_providers()
            result["providers"] = [_serialize_provider(provider) for provider in providers]
        else:
            pids = await runtime.log_store.get_user_provider_ids(user["id"])
            result["provider_ids"] = pids
        return result

    # ── Overview ──────────────────────────────────────────────────────────

    @app.get("/admin/api/overview", include_in_schema=False)
    async def admin_overview(request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        user = _require_auth(user)
        allowed = await _get_allowed_providers(user)
        data = await runtime.log_store.overview(allowed_providers=allowed)
        result: Dict[str, Any] = {
            "title": resolved_settings.admin_title,
            "queue_size": runtime.log_store.queue_size,
            "data": data,
            "role": user.get("role", "user"),
        }
        if user.get("role") == "admin":
            result["downstream_url"] = resolved_settings.downstream_url
            result["provider_routes"] = resolved_settings.provider_routes
        return sanitize_for_web(result)

    @app.get("/admin/api/logs", include_in_schema=False)
    async def admin_logs(
        request: Request,
        q: str = Query(default=""),
        provider: str = Query(default=""),
        model: str = Query(default=""),
        status: Optional[int] = Query(default=None),
        method: str = Query(default=""),
        stream: Optional[bool] = Query(default=None),
        path_contains: str = Query(default=""),
        time_from: Optional[float] = Query(default=None),
        time_to: Optional[float] = Query(default=None),
        duration_min: Optional[float] = Query(default=None),
        duration_max: Optional[float] = Query(default=None),
        conv_fingerprint: str = Query(default=""),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=resolved_settings.admin_page_size_default, ge=1),
    ) -> Dict[str, Any]:
        user = await _resolve_user(request)
        user = _require_auth(user)
        allowed = await _get_allowed_providers(user)
        bounded_page_size = min(page_size, resolved_settings.admin_page_size_max)
        # Non-admin users can only see chat/completions and embeddings
        effective_path = path_contains
        if user.get("role") != "admin" and effective_path not in ("chat/completions", "embeddings"):
            effective_path = "chat/completions"
        payload = await runtime.log_store.list_logs(
            query=q,
            provider=provider,
            model=model,
            status=status,
            method=method,
            stream=stream,
            path_contains=effective_path,
            time_from=time_from,
            time_to=time_to,
            duration_min=duration_min,
            duration_max=duration_max,
            page=page,
            page_size=bounded_page_size,
            allowed_providers=allowed,
            conv_fingerprint=conv_fingerprint or None,
        )
        return sanitize_for_web(payload)

    @app.get("/admin/api/logs/{log_id}", include_in_schema=False)
    async def admin_log_detail(log_id: str, request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        user = _require_auth(user)
        log_entry = await runtime.log_store.get_log(log_id)
        if log_entry is None:
            raise HTTPException(status_code=404, detail="log not found")
        # Check provider permission for non-admin
        if user.get("role") != "admin":
            allowed = await _get_allowed_providers(user)
            if allowed is not None and log_entry.get("provider") not in allowed:
                raise HTTPException(status_code=403, detail="access denied")
        return sanitize_for_web(log_entry)

    @app.get("/admin/api/conversation/{fingerprint}", include_in_schema=False)
    async def admin_conversation_timeline(fingerprint: str, request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        user = _require_auth(user)
        allowed = await _get_allowed_providers(user)
        items = await runtime.log_store.list_conversation_logs(
            fingerprint, allowed_providers=allowed
        )
        return sanitize_for_web({"items": items, "fingerprint": fingerprint})

    # ── User management API ───────────────────────────────────────────────

    @app.get("/admin/api/users", include_in_schema=False)
    async def admin_list_users(
        request: Request,
        q: str = Query(default=""),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=resolved_settings.admin_page_size_default, ge=1),
    ) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        bounded_page_size = min(page_size, resolved_settings.admin_page_size_max)
        payload = await runtime.log_store.list_users(query=q, page=page, page_size=bounded_page_size)
        payload["items"] = [_serialize_user(item) for item in payload["items"]]
        return payload

    @app.post("/admin/api/users", include_in_schema=False)
    async def admin_create_user(request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        data = await request.json()
        name = str(data.get("name", "")).strip()
        if not name:
            raise HTTPException(status_code=422, detail="name is required")
        password = str(data.get("password", "")).strip() or None
        if not password:
            raise HTTPException(status_code=422, detail="password is required")
        api_key = str(data.get("api_key", "")).strip() or generate_api_key()
        new_user = await runtime.log_store.create_user(
            name=name,
            api_key=api_key,
            password=password,
            downstream_url=data.get("downstream_url") or None,
            downstream_apikey=data.get("downstream_apikey") or None,
            notes=data.get("notes") or None,
            role="user",
        )
        # Set provider permissions
        provider_ids = data.get("provider_ids")
        if isinstance(provider_ids, list):
            await runtime.log_store.set_user_providers(new_user["id"], provider_ids)
        payload = _serialize_user(new_user)
        payload["provider_ids"] = await runtime.log_store.get_user_provider_ids(new_user["id"])
        return payload

    @app.get("/admin/api/users/{user_id}", include_in_schema=False)
    async def admin_get_user(user_id: str, request: Request) -> Dict[str, Any]:
        caller = await _resolve_user(request)
        _require_admin(caller)
        user = await runtime.log_store.get_user(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="user not found")
        payload = _serialize_user(user)
        payload["provider_ids"] = await runtime.log_store.get_user_provider_ids(user_id)
        return payload

    @app.put("/admin/api/users/{user_id}", include_in_schema=False)
    async def admin_update_user(user_id: str, request: Request) -> Dict[str, Any]:
        caller = await _resolve_user(request)
        _require_admin(caller)
        data = await request.json()
        allowed_fields = {"name", "api_key", "downstream_url", "downstream_apikey", "notes", "enabled"}
        updates: Dict[str, Any] = {}
        for field in allowed_fields:
            if field not in data:
                continue
            if field == "name":
                name = str(data[field]).strip()
                if not name:
                    raise HTTPException(status_code=422, detail="name cannot be empty")
                updates[field] = name
            elif field == "enabled":
                updates[field] = int(bool(data[field]))
            else:
                updates[field] = data[field] or None
        # Handle password update
        password = str(data.get("password", "")).strip()
        if password:
            updates["password_hash"] = hash_password(password)
        user = await runtime.log_store.update_user(user_id, **updates)
        if user is None:
            raise HTTPException(status_code=404, detail="user not found")
        # Update provider permissions
        provider_ids = data.get("provider_ids")
        if isinstance(provider_ids, list):
            await runtime.log_store.set_user_providers(user_id, provider_ids)
        payload = _serialize_user(user)
        payload["provider_ids"] = await runtime.log_store.get_user_provider_ids(user_id)
        return payload

    @app.delete("/admin/api/users/{user_id}", include_in_schema=False)
    async def admin_delete_user(user_id: str, request: Request) -> Dict[str, Any]:
        caller = await _resolve_user(request)
        _require_admin(caller)
        deleted = await runtime.log_store.delete_user(user_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="user not found")
        return {"ok": True}

    # ── Token reanalysis API ─────────────────────────────────────────────

    @app.post("/admin/api/reanalyze", include_in_schema=False)
    async def admin_reanalyze(request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        result = await runtime.log_store.reanalyze_token_breakdowns()
        return result

    # ── Provider management API ──────────────────────────────────────────

    @app.get("/admin/api/providers", include_in_schema=False)
    async def admin_list_providers(request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        providers = await runtime.log_store.list_providers()
        return {"items": [_serialize_provider(provider) for provider in providers]}

    @app.post("/admin/api/providers", include_in_schema=False)
    async def admin_create_provider(request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        data = await request.json()
        name = str(data.get("name", "")).strip()
        prefix_path = str(data.get("prefix_path", "")).strip().strip("/")
        downstream_url = str(data.get("downstream_url", "")).strip()
        if not name or not prefix_path or not downstream_url:
            raise HTTPException(status_code=422, detail="name, prefix_path, downstream_url are required")
        provider = await runtime.log_store.create_provider(
            name=name,
            prefix_path=prefix_path,
            downstream_url=downstream_url,
            downstream_apikey=data.get("downstream_apikey") or None,
            input_price=float(data.get("input_price", 0)),
            output_price=float(data.get("output_price", 0)),
            notes=data.get("notes") or None,
        )
        await runtime.refresh_provider_cache()
        return _serialize_provider(provider)

    @app.get("/admin/api/providers/{provider_id}", include_in_schema=False)
    async def admin_get_provider(provider_id: str, request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        provider = await runtime.log_store.get_provider(provider_id)
        if provider is None:
            raise HTTPException(status_code=404, detail="provider not found")
        return _serialize_provider(provider)

    @app.put("/admin/api/providers/{provider_id}", include_in_schema=False)
    async def admin_update_provider(provider_id: str, request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        data = await request.json()
        allowed_fields = {"name", "prefix_path", "downstream_url", "downstream_apikey", "enabled", "input_price", "output_price", "notes"}
        updates: Dict[str, Any] = {}
        for field in allowed_fields:
            if field not in data:
                continue
            if field in ("name", "prefix_path", "downstream_url"):
                val = str(data[field]).strip()
                if not val:
                    raise HTTPException(status_code=422, detail=f"{field} cannot be empty")
                if field == "prefix_path":
                    val = val.strip("/")
                updates[field] = val
            elif field in ("input_price", "output_price"):
                updates[field] = float(data[field])
            elif field == "enabled":
                updates[field] = int(bool(data[field]))
            else:
                updates[field] = data[field] or None
        provider = await runtime.log_store.update_provider(provider_id, **updates)
        if provider is None:
            raise HTTPException(status_code=404, detail="provider not found")
        await runtime.refresh_provider_cache()
        return _serialize_provider(provider)

    @app.delete("/admin/api/providers/{provider_id}", include_in_schema=False)
    async def admin_delete_provider(provider_id: str, request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        deleted = await runtime.log_store.delete_provider(provider_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="provider not found")
        await runtime.refresh_provider_cache()
        return {"ok": True}

    # ── Search page (public, no auth) ─────────────────────────────────────

    search_html = static_dir / "search.html"

    @app.get("/search", include_in_schema=False)
    async def search_page() -> FileResponse:
        return FileResponse(search_html)

    @app.post("/search/api/verify-keys", include_in_schema=False)
    async def search_verify_keys(request: Request) -> Dict[str, Any]:
        """Verify API keys / key hashes and return per-hash record counts."""
        data = await request.json()
        hashes = _extract_search_hashes(data)
        if not hashes:
            raise HTTPException(status_code=422, detail="no valid keys or key_hashes provided")
        if len(hashes) > 50:
            raise HTTPException(status_code=422, detail="too many keys (max 50)")
        counts = await runtime.log_store.verify_api_key_hashes(hashes)
        results = {}
        for kh in hashes:
            results[kh] = {"count": counts.get(kh, 0)}
        return {"keys": results}

    @app.post("/search/api/logs", include_in_schema=False)
    async def search_logs(request: Request) -> Dict[str, Any]:
        """Search logs filtered by API keys/hashes. Non-admin: chat/completions + embeddings only."""
        data = await request.json()
        key_hashes = _extract_search_hashes(data)
        if not key_hashes:
            raise HTTPException(status_code=422, detail="at least one API key or key_hash is required")

        # For non-admin search, restrict path to chat/completions and embeddings
        path_contains = str(data.get("path_contains", "")).strip()
        allowed_paths = ["chat/completions", "embeddings"]
        if path_contains and path_contains not in allowed_paths:
            path_contains = "chat/completions"
        if not path_contains:
            path_contains = ""

        q = str(data.get("q", "")).strip()
        model = str(data.get("model", "")).strip()
        status_val = data.get("status")
        method_val = str(data.get("method", "")).strip()
        stream_val = data.get("stream")
        if isinstance(stream_val, str):
            stream_val = stream_val.lower() in ("true", "1")
        elif stream_val is not None:
            stream_val = bool(stream_val)
        time_from = data.get("time_from")
        time_to = data.get("time_to")
        duration_min = data.get("duration_min")
        duration_max = data.get("duration_max")
        conv_fp = str(data.get("conv_fingerprint", "")).strip()
        page = max(int(data.get("page", 1)), 1)
        page_size = min(max(int(data.get("page_size", resolved_settings.admin_page_size_default)), 1),
                        resolved_settings.admin_page_size_max)

        payload = await runtime.log_store.list_logs(
            query=q,
            provider="",
            model=model,
            status=int(status_val) if status_val is not None else None,
            method=method_val,
            stream=stream_val,
            path_contains=path_contains,
            time_from=float(time_from) if time_from is not None else None,
            time_to=float(time_to) if time_to is not None else None,
            duration_min=float(duration_min) if duration_min is not None else None,
            duration_max=float(duration_max) if duration_max is not None else None,
            page=page,
            page_size=page_size,
            api_key_hashes=key_hashes,
            conv_fingerprint=conv_fp or None,
        )
        return sanitize_for_web(payload)

    @app.post("/search/api/logs/{log_id}", include_in_schema=False)
    async def search_log_detail(log_id: str, request: Request) -> Dict[str, Any]:
        """Get log detail, verifying API key ownership."""
        data = await request.json()
        key_hashes = _extract_search_hashes(data)
        if not key_hashes:
            raise HTTPException(status_code=422, detail="at least one API key or key_hash is required")

        log_entry = await runtime.log_store.get_log_with_key_check(log_id, key_hashes)
        if log_entry is None:
            raise HTTPException(status_code=404, detail="log not found or access denied")
        return sanitize_for_web(log_entry)

    @app.post("/search/api/conversation/{fingerprint}", include_in_schema=False)
    async def search_conversation_timeline(fingerprint: str, request: Request) -> Dict[str, Any]:
        """Get conversation timeline filtered by API keys/hashes."""
        data = await request.json()
        key_hashes = _extract_search_hashes(data)
        if not key_hashes:
            raise HTTPException(status_code=422, detail="at least one API key or key_hash is required")

        items = await runtime.log_store.list_conversation_logs(
            fingerprint, api_key_hashes=key_hashes
        )
        return sanitize_for_web({"items": items, "fingerprint": fingerprint})

    @app.api_route("/", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"], include_in_schema=False)
    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"], include_in_schema=False)
    async def proxy(request: Request, path: str = "") -> Response:
        if runtime.http_client is None:
            raise HTTPException(status_code=503, detail="proxy client is not ready")

        started_at = time.perf_counter()
        raw_body = await request.body()
        request_body = decode_payload(raw_body)
        request_body = ensure_stream_usage(request_body)
        if isinstance(request_body, dict):
            raw_body = dumps_json(request_body).encode("utf-8")

        outgoing_headers = filter_request_headers(dict(request.headers))

        # ── user key lookup: identify caller and optionally override downstream ──
        user_info: Optional[Dict[str, Any]] = None
        _auth = outgoing_headers.get("authorization", "")
        if _auth.lower().startswith("bearer "):
            _bearer = _auth[7:].strip()
            _candidate = await runtime.log_store.get_user_by_apikey(_bearer)
            if _candidate and _candidate.get("enabled"):
                user_info = _candidate

        provider, _, target_url = runtime.resolve_target(path)
        # Provider-level apikey
        provider_apikey = runtime.get_provider_apikey(path)
        if provider_apikey and "authorization" not in {k.lower() for k in outgoing_headers}:
            outgoing_headers["authorization"] = f"Bearer {provider_apikey}"
        elif provider_apikey and not user_info:
            outgoing_headers["authorization"] = f"Bearer {provider_apikey}"
        if user_info:
            if user_info.get("downstream_url"):
                _ud = str(user_info["downstream_url"]).rstrip("/")
                _up = f"/{path.lstrip('/')}" if path.lstrip("/") else ""
                target_url = f"{_ud}{_up}"
            if user_info.get("downstream_apikey"):
                outgoing_headers["authorization"] = f"Bearer {user_info['downstream_apikey']}"

        if request.url.query:
            target_url = f"{target_url}?{request.url.query}"

        log_entry: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "method": request.method,
            "path": f"/{path}" if path else "/",
            "query_string": request.url.query,
            "provider": provider,
            "url": target_url,
            "client": request.client.host if request.client else None,
            "user_id": user_info["id"] if user_info else None,
            "user_name": user_info["name"] if user_info else None,
            "request_headers": dict(request.headers),
            "request_body": request_body,
        }

        # Store hashed API key for search-by-key feature
        _raw_bearer = extract_bearer_token(dict(request.headers))
        if _raw_bearer:
            log_entry["api_key_hash"] = hash_api_key(_raw_bearer)

        downstream_request = runtime.http_client.build_request(
            request.method,
            target_url,
            headers=outgoing_headers,
            content=raw_body or None,
        )

        try:
            upstream_response = await runtime.http_client.send(downstream_request, stream=True)
        except httpx.HTTPError as exc:
            log_entry["duration_ms"] = round((time.perf_counter() - started_at) * 1000, 3)
            log_entry["response_status"] = 502
            log_entry["error"] = str(exc)
            await _enqueue_sanitized_log(log_entry)
            return JSONResponse(
                status_code=502,
                content={"detail": "downstream request failed", "error": str(exc)},
            )

        response_headers = filter_response_headers(upstream_response.headers)
        response_was_preconsumed = upstream_response.is_stream_consumed
        is_sse = upstream_response.headers.get("content-type", "").lower().startswith("text/event-stream")

        if is_sse:
            async def stream_response():
                chunks = []
                stream_error: Optional[str] = None
                try:
                    async for chunk in stream_response_chunks(upstream_response):
                        chunks.append(chunk)
                        yield chunk
                except Exception as exc:
                    stream_error = str(exc)
                    raise
                finally:
                    await upstream_response.aclose()
                    combined = b"".join(chunks)
                    log_entry["duration_ms"] = round((time.perf_counter() - started_at) * 1000, 3)
                    log_entry["response_status"] = upstream_response.status_code
                    log_entry["response_headers"] = dict(upstream_response.headers)
                    log_entry["response_body"] = decode_payload(combined)
                    log_entry["response_size"] = len(combined)
                    if stream_error:
                        log_entry["error"] = stream_error
                    await _enqueue_sanitized_log(log_entry)

            return StreamingResponse(
                stream_response(),
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=upstream_response.headers.get("content-type"),
            )

        try:
            response_body_raw = await read_response_body(upstream_response)
        except Exception as exc:
            await upstream_response.aclose()
            log_entry["duration_ms"] = round((time.perf_counter() - started_at) * 1000, 3)
            log_entry["response_status"] = 502
            log_entry["response_headers"] = dict(upstream_response.headers)
            log_entry["error"] = str(exc)
            await _enqueue_sanitized_log(log_entry)
            return JSONResponse(
                status_code=502,
                content={"detail": "downstream response read failed", "error": str(exc)},
            )
        finally:
            if not upstream_response.is_closed:
                await upstream_response.aclose()

        if response_was_preconsumed and "content-encoding" in response_headers:
            response_headers.pop("content-encoding", None)

        log_entry["duration_ms"] = round((time.perf_counter() - started_at) * 1000, 3)
        log_entry["response_status"] = upstream_response.status_code
        log_entry["response_headers"] = dict(upstream_response.headers)
        log_entry["response_body"] = decode_payload(response_body_raw)
        log_entry["response_size"] = len(response_body_raw)
        await _enqueue_sanitized_log(log_entry)

        return Response(
            content=response_body_raw,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get("content-type"),
        )

    return app


try:
    app = create_app()
except ValueError as exc:
    if "ADMIN_USERNAME and ADMIN_PASSWORD must be set" not in str(exc):
        raise
    app = FastAPI(title="LLM Passthough Log")


def main() -> None:
    import os

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    workers = int(os.getenv("WORKERS", "1"))
    uvicorn.run("llm_passthough_log.app:app", host=host, port=port, workers=workers, reload=False)
