from __future__ import annotations

import importlib.util
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
from llm_passthough_log.storage import LogStore, decode_payload, generate_api_key, hash_password

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


def filter_request_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "host"
    }


def filter_response_headers(headers: httpx.Headers) -> Dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def is_http2_available() -> bool:
    return importlib.util.find_spec("h2") is not None


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

    async def startup(self) -> None:
        await self.log_store.start()
        await self.refresh_provider_cache()
        timeout = httpx.Timeout(self.settings.request_timeout_seconds)
        transport = self.downstream_transport or httpx.AsyncHTTPTransport(
            retries=1,
            http2=is_http2_available(),
        )
        self.http_client = httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=transport)

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

    # ── Auth helpers ──────────────────────────────────────────────────────

    async def _resolve_user(request: Request) -> Optional[Dict[str, Any]]:
        key = request.headers.get("x-api-key", "")
        if key:
            if resolved_settings.admin_api_key and key == resolved_settings.admin_api_key:
                return {"id": "__admin__", "name": "Admin", "role": "admin", "enabled": 1}
            user = await runtime.log_store.get_user_by_apikey(key)
            if user and user.get("enabled"):
                return user
            return None
        # No key: if admin_api_key not configured, allow anonymous admin access
        if not resolved_settings.admin_api_key:
            return {"id": "__anon__", "name": "Anonymous", "role": "admin", "enabled": 1}
        return None

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
        # Support name + password login
        name = str(data.get("name", "")).strip()
        password = str(data.get("password", "")).strip()
        if name and password:
            user = await runtime.log_store.get_user_by_credentials(name, password)
            if not user or not user.get("enabled"):
                raise HTTPException(status_code=401, detail="用户名或密码错误")
            provider_ids = await runtime.log_store.get_user_provider_ids(user["id"])
            return {
                "user": {"id": user["id"], "name": user["name"], "role": user.get("role", "user")},
                "api_key": user["api_key"],
                "provider_ids": provider_ids,
            }
        # Fallback: admin API key login
        api_key = str(data.get("api_key", "")).strip()
        if api_key:
            if resolved_settings.admin_api_key and api_key == resolved_settings.admin_api_key:
                return {"user": {"id": "__admin__", "name": "Admin", "role": "admin"}, "api_key": api_key}
            user = await runtime.log_store.get_user_by_apikey(api_key)
            if not user or not user.get("enabled"):
                raise HTTPException(status_code=401, detail="无效的 API Key")
            provider_ids = await runtime.log_store.get_user_provider_ids(user["id"])
            return {
                "user": {"id": user["id"], "name": user["name"], "role": user.get("role", "user")},
                "api_key": api_key,
                "provider_ids": provider_ids,
            }
        raise HTTPException(status_code=422, detail="请提供用户名和密码")

    @app.get("/admin/api/session", include_in_schema=False)
    async def admin_session(request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        user = _require_auth(user)
        result: Dict[str, Any] = {"user": {"id": user["id"], "name": user["name"], "role": user.get("role", "user")}}
        if user.get("role") == "admin":
            result["providers"] = await runtime.log_store.list_providers()
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
        return result

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
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=resolved_settings.admin_page_size_default, ge=1),
    ) -> Dict[str, Any]:
        user = await _resolve_user(request)
        user = _require_auth(user)
        allowed = await _get_allowed_providers(user)
        bounded_page_size = min(page_size, resolved_settings.admin_page_size_max)
        return await runtime.log_store.list_logs(
            query=q,
            provider=provider,
            model=model,
            status=status,
            method=method,
            stream=stream,
            path_contains=path_contains,
            time_from=time_from,
            time_to=time_to,
            duration_min=duration_min,
            duration_max=duration_max,
            page=page,
            page_size=bounded_page_size,
            allowed_providers=allowed,
        )

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
        return log_entry

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
        return await runtime.log_store.list_users(query=q, page=page, page_size=bounded_page_size)

    @app.post("/admin/api/users", include_in_schema=False)
    async def admin_create_user(request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        data = await request.json()
        name = str(data.get("name", "")).strip()
        if not name:
            raise HTTPException(status_code=422, detail="name is required")
        api_key = str(data.get("api_key", "")).strip() or generate_api_key()
        password = str(data.get("password", "")).strip() or None
        role = str(data.get("role", "user")).strip()
        if role not in ("admin", "user"):
            role = "user"
        new_user = await runtime.log_store.create_user(
            name=name,
            api_key=api_key,
            password=password,
            downstream_url=data.get("downstream_url") or None,
            downstream_apikey=data.get("downstream_apikey") or None,
            notes=data.get("notes") or None,
            role=role,
        )
        # Set provider permissions
        provider_ids = data.get("provider_ids")
        if isinstance(provider_ids, list):
            await runtime.log_store.set_user_providers(new_user["id"], provider_ids)
        return new_user

    @app.get("/admin/api/users/{user_id}", include_in_schema=False)
    async def admin_get_user(user_id: str, request: Request) -> Dict[str, Any]:
        caller = await _resolve_user(request)
        _require_admin(caller)
        user = await runtime.log_store.get_user(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="user not found")
        user["provider_ids"] = await runtime.log_store.get_user_provider_ids(user_id)
        return user

    @app.put("/admin/api/users/{user_id}", include_in_schema=False)
    async def admin_update_user(user_id: str, request: Request) -> Dict[str, Any]:
        caller = await _resolve_user(request)
        _require_admin(caller)
        data = await request.json()
        allowed_fields = {"name", "api_key", "downstream_url", "downstream_apikey", "enabled", "notes", "role"}
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
            elif field == "role":
                role = str(data[field]).strip()
                if role not in ("admin", "user"):
                    role = "user"
                updates[field] = role
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
        user["provider_ids"] = await runtime.log_store.get_user_provider_ids(user_id)
        return user

    @app.delete("/admin/api/users/{user_id}", include_in_schema=False)
    async def admin_delete_user(user_id: str, request: Request) -> Dict[str, Any]:
        caller = await _resolve_user(request)
        _require_admin(caller)
        deleted = await runtime.log_store.delete_user(user_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="user not found")
        return {"ok": True}

    # ── Provider management API ──────────────────────────────────────────

    @app.get("/admin/api/providers", include_in_schema=False)
    async def admin_list_providers(request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        providers = await runtime.log_store.list_providers()
        return {"items": providers}

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
        return provider

    @app.get("/admin/api/providers/{provider_id}", include_in_schema=False)
    async def admin_get_provider(provider_id: str, request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        provider = await runtime.log_store.get_provider(provider_id)
        if provider is None:
            raise HTTPException(status_code=404, detail="provider not found")
        return provider

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
        return provider

    @app.delete("/admin/api/providers/{provider_id}", include_in_schema=False)
    async def admin_delete_provider(provider_id: str, request: Request) -> Dict[str, Any]:
        user = await _resolve_user(request)
        _require_admin(user)
        deleted = await runtime.log_store.delete_provider(provider_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="provider not found")
        await runtime.refresh_provider_cache()
        return {"ok": True}

    @app.api_route("/", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"], include_in_schema=False)
    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"], include_in_schema=False)
    async def proxy(request: Request, path: str = "") -> Response:
        if runtime.http_client is None:
            raise HTTPException(status_code=503, detail="proxy client is not ready")

        started_at = time.perf_counter()
        raw_body = await request.body()
        request_body = decode_payload(raw_body)

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
            await runtime.log_store.enqueue(log_entry)
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
                    await runtime.log_store.enqueue(log_entry)

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
            await runtime.log_store.enqueue(log_entry)
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
        await runtime.log_store.enqueue(log_entry)

        return Response(
            content=response_body_raw,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get("content-type"),
        )

    return app


app = create_app()


def main() -> None:
    import os

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    workers = int(os.getenv("WORKERS", "1"))
    uvicorn.run("llm_passthough_log.app:app", host=host, port=port, workers=workers, reload=False)
