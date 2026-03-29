from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


PREVIEW_BEARER_TOKEN_RE = re.compile(r"(?i)\bbearer\s+([^\s,;]+)")
PREVIEW_SK_TOKEN_RE = re.compile(r"\bsk-[A-Za-z0-9._\-]+\b")


def _mask_preview_secret(value: str) -> str:
    text = value.strip()
    if not text:
        return text
    if text.lower().startswith("sk-"):
        return "***" if len(text) <= 6 else "***..." + text[-4:]
    if len(text) <= 4:
        return "*" * len(text)
    if len(text) <= 8:
        return text[:1] + "***" + text[-1:]
    return text[:4] + "..." + text[-4:]


def sanitize_preview_text(value: str) -> str:
    masked = PREVIEW_BEARER_TOKEN_RE.sub(lambda match: f"Bearer {_mask_preview_secret(match.group(1))}", value)
    return PREVIEW_SK_TOKEN_RE.sub(lambda match: _mask_preview_secret(match.group(0)), masked)


def decode_payload(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return raw.decode("utf-8", errors="replace")


def dumps_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))


def extract_model(payload: Any) -> Optional[str]:
    if isinstance(payload, dict):
        model = payload.get("model")
        if isinstance(model, str) and model.strip():
            return model.strip()
    return None


def extract_stream(payload: Any) -> bool:
    return bool(payload.get("stream")) if isinstance(payload, dict) else False


def generate_api_key() -> str:
    """Generate a cryptographically random sk-prefixed API key."""
    return "sk-" + secrets.token_urlsafe(32)


def hash_password(password: str) -> str:
    """Hash password with PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex() + ":" + key.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored PBKDF2 hash."""
    try:
        salt_hex, key_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(key.hex(), key_hex)
    except (ValueError, AttributeError):
        return False


def build_preview(entry: Dict[str, Any], limit: int = 220) -> str:
    request_body = entry.get("request_body")
    response_body = entry.get("response_body")
    candidates: List[str] = []
    if isinstance(request_body, dict):
        for key in ("prompt", "input"):
            value = request_body.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append(value.strip())
        messages = request_body.get("messages")
        if isinstance(messages, list):
            for message in messages:
                if not isinstance(message, dict):
                    continue
                content = message.get("content")
                if isinstance(content, str) and content.strip():
                    candidates.append(content.strip())
                    break
    if isinstance(response_body, dict):
        choices = response_body.get("choices")
        if isinstance(choices, list) and choices:
            first_choice = choices[0]
            if isinstance(first_choice, dict):
                message = first_choice.get("message")
                if isinstance(message, dict):
                    content = message.get("content")
                    if isinstance(content, str) and content.strip():
                        candidates.append(content.strip())
    if not candidates:
        raw = dumps_json(request_body if request_body is not None else response_body)
        candidates.append(raw)
    preview = " | ".join(item.replace("\n", " ") for item in candidates if item)
    return sanitize_preview_text(preview[:limit])


class LogStore:
    def __init__(self, jsonl_path: Path, sqlite_path: Path, queue_maxsize: int = 5000) -> None:
        self._jsonl_path = jsonl_path
        self._sqlite_path = sqlite_path
        self._error_path = jsonl_path.with_name("log-writer-errors.log")
        self._queue_maxsize = queue_maxsize
        self._queue: Optional[asyncio.Queue[Optional[Dict[str, Any]]]] = None
        self._worker_task: Optional[asyncio.Task[None]] = None

    @property
    def queue_size(self) -> int:
        if self._queue is None:
            return 0
        return self._queue.qsize()

    async def start(self) -> None:
        self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(self._init_db)
        self._queue = asyncio.Queue(maxsize=self._queue_maxsize)
        self._worker_task = asyncio.create_task(self._worker(), name="log-store-worker")

    async def stop(self) -> None:
        if self._queue is None:
            return
        await self._queue.put(None)
        if self._worker_task is not None:
            await self._worker_task
            self._worker_task = None
        self._queue = None

    async def enqueue(self, entry: Dict[str, Any]) -> None:
        if self._queue is None:
            raise RuntimeError("log queue is not started")
        await self._queue.put(entry)

    async def overview(self, *, allowed_providers: Optional[List[str]] = None) -> Dict[str, Any]:
        return await asyncio.to_thread(self._overview_sync, allowed_providers)

    async def list_logs(
        self,
        *,
        query: str,
        provider: str,
        model: str,
        status: Optional[int],
        method: str,
        stream: Optional[bool],
        path_contains: str,
        time_from: Optional[float],
        time_to: Optional[float],
        duration_min: Optional[float],
        duration_max: Optional[float],
        page: int,
        page_size: int,
        allowed_providers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return await asyncio.to_thread(
            self._list_logs_sync,
            query,
            provider,
            model,
            status,
            method,
            stream,
            path_contains,
            time_from,
            time_to,
            duration_min,
            duration_max,
            page,
            page_size,
            allowed_providers,
        )

    async def get_log(self, log_id: str) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._get_log_sync, log_id)

    async def _worker(self) -> None:
        if self._queue is None:
            return
        while True:
            item = await self._queue.get()
            try:
                if item is None:
                    return
                try:
                    await asyncio.to_thread(self._write_entry_sync, item)
                except Exception as exc:
                    await asyncio.to_thread(self._write_worker_error_sync, item, exc)
            finally:
                self._queue.task_done()

    def _write_worker_error_sync(self, entry: Dict[str, Any], exc: Exception) -> None:
        payload = {
            "timestamp": time.time(),
            "entry_id": entry.get("id"),
            "error": str(exc),
        }
        with self._error_path.open("a", encoding="utf-8") as handle:
            handle.write(dumps_json(payload))
            handle.write("\n")

    def _init_db(self) -> None:
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    query_string TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    request_model TEXT,
                    request_stream INTEGER NOT NULL,
                    response_status INTEGER,
                    duration_ms REAL,
                    search_blob TEXT NOT NULL,
                    preview TEXT NOT NULL,
                    entry_json TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_provider ON logs(provider)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_request_model ON logs(request_model)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_response_status ON logs(response_status)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    api_key TEXT NOT NULL UNIQUE,
                    downstream_url TEXT,
                    downstream_apikey TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    notes TEXT,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS providers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    prefix_path TEXT NOT NULL UNIQUE,
                    downstream_url TEXT NOT NULL,
                    downstream_apikey TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    input_price REAL NOT NULL DEFAULT 0,
                    output_price REAL NOT NULL DEFAULT 0,
                    notes TEXT,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_providers (
                    user_id TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    PRIMARY KEY (user_id, provider_id)
                )
                """
            )
            # Migrations for existing tables
            cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
            if "role" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
            if "password_hash" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
            cols = {r[1] for r in conn.execute("PRAGMA table_info(logs)").fetchall()}
            if "estimated_cost" not in cols:
                conn.execute("ALTER TABLE logs ADD COLUMN estimated_cost REAL DEFAULT 0")
            if "user_id" not in cols:
                conn.execute("ALTER TABLE logs ADD COLUMN user_id TEXT")
            conn.commit()

    def _write_entry_sync(self, entry: Dict[str, Any]) -> None:
        request_body = entry.get("request_body")
        response_body = entry.get("response_body")
        search_blob = "\n".join(
            dumps_json(part).lower()
            for part in (
                entry.get("url", ""),
                request_body,
                response_body,
                entry.get("error"),
            )
            if part is not None
        )
        preview = build_preview(entry)
        estimated_cost = self._compute_cost_sync(entry)
        entry["estimated_cost"] = estimated_cost
        line = dumps_json(entry)

        with self._jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO logs (
                    id, created_at, method, path, query_string, target_url,
                    provider, request_model, request_stream, response_status,
                    duration_ms, search_blob, preview, entry_json,
                    estimated_cost, user_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["id"],
                    float(entry.get("timestamp", time.time())),
                    entry.get("method", "GET"),
                    entry.get("path", ""),
                    entry.get("query_string", ""),
                    entry.get("url", ""),
                    entry.get("provider", "default"),
                    extract_model(request_body),
                    int(extract_stream(request_body)),
                    entry.get("response_status"),
                    entry.get("duration_ms"),
                    search_blob,
                    preview,
                    line,
                    estimated_cost,
                    entry.get("user_id"),
                ),
            )
            conn.commit()

    def _overview_sync(self, allowed_providers: Optional[List[str]] = None) -> Dict[str, Any]:
        prov_filter = ""
        prov_params: List[Any] = []
        if allowed_providers is not None:
            if not allowed_providers:
                return {"totals": {}, "providers": [], "statuses": [], "recent": []}
            placeholders = ",".join("?" * len(allowed_providers))
            prov_filter = f"WHERE provider IN ({placeholders})"
            prov_params = list(allowed_providers)
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.row_factory = sqlite3.Row
            totals = conn.execute(
                f"""
                SELECT
                    COUNT(*) AS total_requests,
                    COALESCE(SUM(CASE WHEN request_stream = 1 THEN 1 ELSE 0 END), 0) AS stream_requests,
                    COALESCE(SUM(CASE WHEN response_status >= 400 THEN 1 ELSE 0 END), 0) AS error_requests,
                    COUNT(DISTINCT provider) AS providers,
                    COUNT(DISTINCT COALESCE(request_model, '')) AS models,
                    MAX(created_at) AS latest_request_at,
                    COALESCE(SUM(COALESCE(estimated_cost, 0)), 0) AS total_cost
                FROM logs {prov_filter}
                """,
                prov_params,
            ).fetchone()
            provider_rows = conn.execute(
                f"SELECT provider, COUNT(*) AS count FROM logs {prov_filter} GROUP BY provider ORDER BY count DESC LIMIT 6",
                prov_params,
            ).fetchall()
            status_rows = conn.execute(
                f"SELECT COALESCE(response_status, 0) AS status, COUNT(*) AS count FROM logs {prov_filter} GROUP BY COALESCE(response_status, 0) ORDER BY count DESC LIMIT 6",
                prov_params,
            ).fetchall()
            recent_rows = conn.execute(
                f"SELECT id, method, path, provider, request_model, response_status, created_at, preview FROM logs {prov_filter} ORDER BY created_at DESC LIMIT 8",
                prov_params,
            ).fetchall()
        return {
            "totals": dict(totals) if totals else {},
            "providers": [dict(row) for row in provider_rows],
            "statuses": [dict(row) for row in status_rows],
            "recent": [
                {**dict(row), "preview": sanitize_preview_text(str(dict(row).get("preview") or ""))}
                for row in recent_rows
            ],
        }

    def _list_logs_sync(
        self,
        query: str,
        provider: str,
        model: str,
        status: Optional[int],
        method: str,
        stream: Optional[bool],
        path_contains: str,
        time_from: Optional[float],
        time_to: Optional[float],
        duration_min: Optional[float],
        duration_max: Optional[float],
        page: int,
        page_size: int,
        allowed_providers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        where: List[str] = []
        params: List[Any] = []
        if allowed_providers is not None:
            if not allowed_providers:
                return {"items": [], "pagination": {"page": 1, "page_size": page_size, "total": 0, "pages": 1}}
            placeholders = ",".join("?" * len(allowed_providers))
            where.append(f"provider IN ({placeholders})")
            params.extend(allowed_providers)
        if query:
            where.append("search_blob LIKE ?")
            params.append(f"%{query.lower()}%")
        if provider:
            where.append("provider = ?")
            params.append(provider)
        if model:
            where.append("request_model = ?")
            params.append(model)
        if status is not None:
            where.append("response_status = ?")
            params.append(status)
        if method:
            where.append("method = ?")
            params.append(method.upper())
        if stream is not None:
            where.append("request_stream = ?")
            params.append(int(stream))
        if path_contains:
            where.append("path LIKE ?")
            params.append(f"%{path_contains}%")
        if time_from is not None:
            where.append("created_at >= ?")
            params.append(time_from)
        if time_to is not None:
            where.append("created_at <= ?")
            params.append(time_to)
        if duration_min is not None:
            where.append("duration_ms >= ?")
            params.append(duration_min)
        if duration_max is not None:
            where.append("duration_ms <= ?")
            params.append(duration_max)
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        offset = max(page - 1, 0) * page_size
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.row_factory = sqlite3.Row
            total_row = conn.execute(
                f"SELECT COUNT(*) AS total FROM logs {where_sql}",
                params,
            ).fetchone()
            rows = conn.execute(
                f"""
                SELECT id, created_at, method, path, query_string, target_url, provider,
                       request_model, request_stream, response_status, duration_ms, preview,
                       estimated_cost
                FROM logs
                {where_sql}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, offset],
            ).fetchall()
        total = int(total_row["total"]) if total_row else 0
        items = []
        for row in rows:
            payload = dict(row)
            payload["preview"] = sanitize_preview_text(str(payload.get("preview") or ""))
            items.append(payload)
        return {
            "items": items,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "pages": max((total + page_size - 1) // page_size, 1),
            },
        }

    def _get_log_sync(self, log_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self._sqlite_path) as conn:
            row = conn.execute("SELECT entry_json FROM logs WHERE id = ?", (log_id,)).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    # ── Users ────────────────────────────────────────────────────────────

    async def create_user(
        self,
        name: str,
        api_key: str,
        *,
        password: Optional[str] = None,
        downstream_url: Optional[str] = None,
        downstream_apikey: Optional[str] = None,
        notes: Optional[str] = None,
        role: str = "user",
    ) -> Dict[str, Any]:
        return await asyncio.to_thread(
            self._create_user_sync, name, api_key, password, downstream_url, downstream_apikey, notes, role
        )

    async def list_users(self, *, query: str = "", page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        return await asyncio.to_thread(self._list_users_sync, query, page, page_size)

    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._get_user_sync, user_id)

    async def get_user_by_apikey(self, api_key: str) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._get_user_by_apikey_sync, api_key)

    async def get_user_by_credentials(self, name: str, password: str) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._get_user_by_credentials_sync, name, password)

    async def update_user(self, user_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._update_user_sync, user_id, fields)

    async def delete_user(self, user_id: str) -> bool:
        return await asyncio.to_thread(self._delete_user_sync, user_id)

    def _create_user_sync(
        self,
        name: str,
        api_key: str,
        password: Optional[str],
        downstream_url: Optional[str],
        downstream_apikey: Optional[str],
        notes: Optional[str],
        role: str = "user",
    ) -> Dict[str, Any]:
        user_id = str(uuid.uuid4())
        created_at = time.time()
        pw_hash = hash_password(password) if password else None
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute(
                """
                INSERT INTO users (id, name, api_key, downstream_url, downstream_apikey, enabled, notes, created_at, role, password_hash)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                """,
                (user_id, name, api_key, downstream_url or None, downstream_apikey or None, notes or None, created_at, role, pw_hash),
            )
            conn.commit()
        result = self._get_user_sync(user_id)
        assert result is not None
        return result

    def _list_users_sync(self, query: str, page: int, page_size: int) -> Dict[str, Any]:
        where: List[str] = []
        params: List[Any] = []
        if query:
            where.append("(name LIKE ? OR notes LIKE ?)")
            params.extend([f"%{query}%", f"%{query}%"])
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        offset = max(page - 1, 0) * page_size
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.row_factory = sqlite3.Row
            total_row = conn.execute(
                f"SELECT COUNT(*) AS total FROM users {where_sql}", params
            ).fetchone()
            rows = conn.execute(
                f"""
                SELECT id, name, api_key, downstream_url, downstream_apikey, enabled, notes, created_at, role
                FROM users {where_sql}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, offset],
            ).fetchall()
        total = int(total_row["total"]) if total_row else 0
        return {
            "items": [dict(row) for row in rows],
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "pages": max((total + page_size - 1) // page_size, 1),
            },
        }

    def _get_user_sync(self, user_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id, name, api_key, downstream_url, downstream_apikey, enabled, notes, created_at, role FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        return dict(row) if row else None

    def _get_user_by_apikey_sync(self, api_key: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id, name, api_key, downstream_url, downstream_apikey, enabled, notes, created_at, role FROM users WHERE api_key = ?",
                (api_key,),
            ).fetchone()
        return dict(row) if row else None

    def _get_user_by_credentials_sync(self, name: str, password: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id, name, api_key, downstream_url, downstream_apikey, enabled, notes, created_at, role, password_hash FROM users WHERE name = ?",
                (name,),
            ).fetchone()
        if not row:
            return None
        user = dict(row)
        pw_hash = user.pop("password_hash", None)
        if not pw_hash or not verify_password(password, pw_hash):
            return None
        return user

    def _update_user_sync(self, user_id: str, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        allowed = {"name", "api_key", "downstream_url", "downstream_apikey", "enabled", "notes", "role", "password_hash"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self._get_user_sync(user_id)
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values: List[Any] = list(updates.values())
        values.append(user_id)
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
            conn.commit()
        return self._get_user_sync(user_id)

    def _delete_user_sync(self, user_id: str) -> bool:
        with sqlite3.connect(self._sqlite_path) as conn:
            cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.execute("DELETE FROM user_providers WHERE user_id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount > 0

    # ── Providers ────────────────────────────────────────────────────────

    async def create_provider(
        self,
        name: str,
        prefix_path: str,
        downstream_url: str,
        *,
        downstream_apikey: Optional[str] = None,
        input_price: float = 0,
        output_price: float = 0,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await asyncio.to_thread(
            self._create_provider_sync, name, prefix_path, downstream_url,
            downstream_apikey, input_price, output_price, notes,
        )

    async def list_providers(self) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._list_providers_sync)

    async def get_provider(self, provider_id: str) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._get_provider_sync, provider_id)

    async def update_provider(self, provider_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._update_provider_sync, provider_id, fields)

    async def delete_provider(self, provider_id: str) -> bool:
        return await asyncio.to_thread(self._delete_provider_sync, provider_id)

    async def list_enabled_providers(self) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._list_enabled_providers_sync)

    def _create_provider_sync(
        self, name: str, prefix_path: str, downstream_url: str,
        downstream_apikey: Optional[str], input_price: float, output_price: float,
        notes: Optional[str],
    ) -> Dict[str, Any]:
        provider_id = str(uuid.uuid4())
        created_at = time.time()
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute(
                """
                INSERT INTO providers (id, name, prefix_path, downstream_url, downstream_apikey,
                    enabled, input_price, output_price, notes, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                """,
                (provider_id, name, prefix_path, downstream_url,
                 downstream_apikey or None, input_price, output_price, notes or None, created_at),
            )
            conn.commit()
        result = self._get_provider_sync(provider_id)
        assert result is not None
        return result

    def _list_providers_sync(self) -> List[Dict[str, Any]]:
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, name, prefix_path, downstream_url, downstream_apikey, enabled, input_price, output_price, notes, created_at FROM providers ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def _get_provider_sync(self, provider_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id, name, prefix_path, downstream_url, downstream_apikey, enabled, input_price, output_price, notes, created_at FROM providers WHERE id = ?",
                (provider_id,),
            ).fetchone()
        return dict(row) if row else None

    def _update_provider_sync(self, provider_id: str, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        allowed = {"name", "prefix_path", "downstream_url", "downstream_apikey", "enabled", "input_price", "output_price", "notes"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self._get_provider_sync(provider_id)
        if "enabled" in updates:
            updates["enabled"] = int(bool(updates["enabled"]))
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values: List[Any] = list(updates.values())
        values.append(provider_id)
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute(f"UPDATE providers SET {set_clause} WHERE id = ?", values)
            conn.commit()
        return self._get_provider_sync(provider_id)

    def _delete_provider_sync(self, provider_id: str) -> bool:
        with sqlite3.connect(self._sqlite_path) as conn:
            cursor = conn.execute("DELETE FROM providers WHERE id = ?", (provider_id,))
            conn.execute("DELETE FROM user_providers WHERE provider_id = ?", (provider_id,))
            conn.commit()
            return cursor.rowcount > 0

    def _list_enabled_providers_sync(self) -> List[Dict[str, Any]]:
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, name, prefix_path, downstream_url, downstream_apikey, enabled, input_price, output_price FROM providers WHERE enabled = 1"
            ).fetchall()
        return [dict(row) for row in rows]

    # ── User-Provider permissions ────────────────────────────────────────

    async def set_user_providers(self, user_id: str, provider_ids: List[str]) -> None:
        await asyncio.to_thread(self._set_user_providers_sync, user_id, provider_ids)

    async def get_user_provider_ids(self, user_id: str) -> List[str]:
        return await asyncio.to_thread(self._get_user_provider_ids_sync, user_id)

    async def get_user_allowed_providers(self, user_id: str) -> List[str]:
        """Return list of prefix_path values the user has access to."""
        return await asyncio.to_thread(self._get_user_allowed_providers_sync, user_id)

    def _set_user_providers_sync(self, user_id: str, provider_ids: List[str]) -> None:
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute("DELETE FROM user_providers WHERE user_id = ?", (user_id,))
            for pid in provider_ids:
                conn.execute("INSERT OR IGNORE INTO user_providers (user_id, provider_id) VALUES (?, ?)", (user_id, pid))
            conn.commit()

    def _get_user_provider_ids_sync(self, user_id: str) -> List[str]:
        with sqlite3.connect(self._sqlite_path) as conn:
            rows = conn.execute("SELECT provider_id FROM user_providers WHERE user_id = ?", (user_id,)).fetchall()
        return [r[0] for r in rows]

    def _get_user_allowed_providers_sync(self, user_id: str) -> List[str]:
        with sqlite3.connect(self._sqlite_path) as conn:
            rows = conn.execute(
                "SELECT p.prefix_path FROM user_providers up JOIN providers p ON up.provider_id = p.id WHERE up.user_id = ? AND p.enabled = 1",
                (user_id,),
            ).fetchall()
        return [r[0] for r in rows]

    # ── Cost helpers ─────────────────────────────────────────────────────

    def _compute_cost_sync(self, entry: Dict[str, Any]) -> float:
        usage = self._extract_usage(entry)
        if not usage:
            return 0.0
        provider_name = entry.get("provider", "")
        pricing = self._get_provider_pricing_sync(provider_name)
        if not pricing:
            return 0.0
        input_tokens = usage.get("prompt_tokens", 0) or 0
        output_tokens = usage.get("completion_tokens", 0) or 0
        return round((input_tokens * pricing[0] + output_tokens * pricing[1]) / 1_000_000, 8)

    @staticmethod
    def _extract_usage(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        rb = entry.get("response_body")
        if isinstance(rb, dict):
            u = rb.get("usage")
            if isinstance(u, dict):
                return u
        if isinstance(rb, str):
            for line in reversed(rb.split("\n")):
                if line.startswith("data: ") and "usage" in line:
                    payload = line[6:].strip()
                    if payload == "[DONE]":
                        continue
                    try:
                        chunk = json.loads(payload)
                        u = chunk.get("usage")
                        if isinstance(u, dict) and u.get("total_tokens"):
                            return u
                    except Exception:
                        pass
        return None

    def _get_provider_pricing_sync(self, provider_name: str) -> Optional[tuple]:
        with sqlite3.connect(self._sqlite_path) as conn:
            row = conn.execute(
                "SELECT input_price, output_price FROM providers WHERE prefix_path = ? OR name = ?",
                (provider_name, provider_name),
            ).fetchone()
        if row and (row[0] or row[1]):
            return (row[0], row[1])
        return None
