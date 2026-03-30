from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
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


def compute_conversation_fingerprint(
    request_body: Any,
    model: Optional[str] = None,
    client: Optional[str] = None,
) -> Optional[str]:
    """Generate a fingerprint to group related multi-turn conversations.

    Uses SHA-256 of (system_prompt_prefix + model + client) truncated to 12 hex chars.
    Returns None if no messages are found.
    """
    if not isinstance(request_body, dict):
        return None
    messages = request_body.get("messages")
    if not isinstance(messages, list) or not messages:
        return None
    # Extract system prompt (first message with role=system)
    system_content = ""
    for msg in messages:
        if isinstance(msg, dict) and msg.get("role") == "system":
            content = msg.get("content", "")
            if isinstance(content, str):
                system_content = content[:500]  # first 500 chars to bound hash input
            elif isinstance(content, list):
                parts = []
                for p in content:
                    if isinstance(p, dict) and isinstance(p.get("text"), str):
                        parts.append(p["text"])
                system_content = "\n".join(parts)[:500]
            break
    seed = f"{system_content}|{model or ''}|{client or ''}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]


def extract_msg_count(request_body: Any) -> int:
    """Return the number of messages in a chat completion request."""
    if isinstance(request_body, dict):
        messages = request_body.get("messages")
        if isinstance(messages, list):
            return len(messages)
    return 0


# ── Token estimation & breakdown analysis ────────────────────────────────────

def _estimate_token_count(text: str) -> int:
    """Estimate token count using CJK 0.7t/char + EN 1.3t/word heuristic."""
    if not text:
        return 0
    s = str(text)
    cjk_chars = len(re.findall(r"[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]", s))
    cjk_punct = len(re.findall(r"[\u3000-\u303f\uff01-\uff60\ufe30-\ufe4f\u2018-\u201f\u2026\u2014]", s))
    en_words = re.findall(r"[a-zA-Z]+", s)
    en_letters = sum(len(w) for w in en_words)
    digit_seqs = re.findall(r"\d+", s)
    digit_chars = sum(len(d) for d in digit_seqs)
    ws_chars = len(re.findall(r"\s", s))
    other_chars = max(0, len(s) - cjk_chars - cjk_punct - en_letters - digit_chars - ws_chars)

    tokens = (
        cjk_chars * 0.7
        + cjk_punct * 1.0
        + len(en_words) * 1.3
        + digit_chars / 3.3
        + ws_chars * 0.15
        + other_chars * 1.0
    )
    return max(1, round(tokens))


def _collect_content_text(value: Any) -> str:
    """Recursively extract text from various content formats."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(_collect_content_text(item) for item in value)
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"]
        if isinstance(value.get("content"), str):
            return value["content"]
        if isinstance(value.get("content"), list):
            return "\n".join(_collect_content_text(p) for p in value["content"])
        return "\n".join(_collect_content_text(v) for v in value.values())
    return str(value)


def _parse_sse_response(raw: str) -> Optional[Dict[str, Any]]:
    """Extract response content from SSE stream text."""
    reasoning = ""
    content = ""
    tool_calls: List[Dict[str, Any]] = []
    usage = None
    for ln in raw.split("\n"):
        if not ln.startswith("data: "):
            continue
        payload = ln[6:].strip()
        if payload == "[DONE]":
            continue
        try:
            c = json.loads(payload)
            if c.get("usage"):
                usage = c["usage"]
            for ch in c.get("choices", []):
                d = ch.get("delta", {})
                if d.get("reasoning_content"):
                    reasoning += d["reasoning_content"]
                if d.get("content"):
                    content += d["content"]
                if d.get("tool_calls"):
                    for tc in d["tool_calls"]:
                        idx = tc.get("index", len(tool_calls))
                        while len(tool_calls) <= idx:
                            tool_calls.append({"function": {"name": "", "arguments": ""}})
                        if tc.get("function"):
                            if tc["function"].get("name"):
                                tool_calls[idx]["function"]["name"] += tc["function"]["name"]
                            if tc["function"].get("arguments"):
                                tool_calls[idx]["function"]["arguments"] += tc["function"]["arguments"]
        except Exception:
            pass
    return {
        "reasoning": reasoning,
        "content": content,
        "tool_calls": tool_calls if tool_calls else None,
        "usage": usage,
    }


def analyze_token_breakdown(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Analyze token breakdown from request/response.

    Returns a dict with:
      - prompt_breakdown: list of {role, tokens, chars, count} for each message role
      - completion_breakdown: list of {category, tokens, chars} for completion parts
      - has_real_usage: whether API returned actual usage data
      - usage: the real usage object if available
    """
    request_body = entry.get("request_body")
    response_body = entry.get("response_body")
    if not isinstance(request_body, dict):
        return None

    messages = request_body.get("messages")
    if not isinstance(messages, list) or not messages:
        return None

    # ── Prompt breakdown by role ──
    role_map: Dict[str, Dict[str, Any]] = {}

    def add_role(role: str, text: str, count: int = 1) -> None:
        if not text:
            return
        if role not in role_map:
            role_map[role] = {"text": "", "chars": 0, "tokens": 0, "count": 0}
        role_map[role]["text"] += text + "\n"
        role_map[role]["count"] += count

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role", "user")).lower()
        text = _collect_content_text(msg.get("content"))
        # tool_calls in assistant messages → count separately
        if isinstance(msg.get("tool_calls"), list):
            tc_text = "\n".join(
                (tc.get("function", {}).get("name", "") + " " + tc.get("function", {}).get("arguments", ""))
                for tc in msg["tool_calls"]
                if isinstance(tc, dict)
            )
            add_role("assistant", tc_text)
        add_role(role, text)

    # tools / functions schema
    if isinstance(request_body.get("tools"), list):
        schema_text = json.dumps(request_body["tools"], ensure_ascii=False)
        add_role("tools_schema", schema_text)
    elif isinstance(request_body.get("functions"), list):
        schema_text = json.dumps(request_body["functions"], ensure_ascii=False)
        add_role("tools_schema", schema_text)

    # Calculate tokens per role
    prompt_breakdown = []
    total_prompt_est = 0
    for role, info in role_map.items():
        info["chars"] = len(info["text"])
        info["tokens"] = _estimate_token_count(info["text"])
        total_prompt_est += info["tokens"]
        prompt_breakdown.append({
            "role": role,
            "tokens": info["tokens"],
            "chars": info["chars"],
            "count": info["count"],
        })

    # Sort descending by tokens
    prompt_breakdown.sort(key=lambda x: x["tokens"], reverse=True)

    # ── Response / completion breakdown ──
    resp_info = None
    if isinstance(response_body, dict):
        ch = (response_body.get("choices") or [None])[0]
        if isinstance(ch, dict):
            m = ch.get("message", {})
            resp_info = {
                "reasoning": m.get("reasoning_content", ""),
                "content": m.get("content", ""),
                "tool_calls": m.get("tool_calls"),
                "usage": response_body.get("usage"),
            }
    elif isinstance(response_body, str):
        resp_info = _parse_sse_response(response_body)

    completion_breakdown = []
    if resp_info:
        if resp_info.get("content"):
            txt = resp_info["content"]
            completion_breakdown.append({
                "category": "text_output",
                "label": "文本输出",
                "tokens": _estimate_token_count(txt),
                "chars": len(txt),
            })
        if resp_info.get("reasoning"):
            txt = resp_info["reasoning"]
            completion_breakdown.append({
                "category": "reasoning",
                "label": "推理",
                "tokens": _estimate_token_count(txt),
                "chars": len(txt),
            })
        if resp_info.get("tool_calls"):
            tc_text = "\n".join(
                (tc.get("function", {}).get("name", "") + " " + tc.get("function", {}).get("arguments", ""))
                for tc in resp_info["tool_calls"]
                if isinstance(tc, dict)
            )
            if tc_text.strip():
                completion_breakdown.append({
                    "category": "tool_calls",
                    "label": "工具调用",
                    "tokens": _estimate_token_count(tc_text),
                    "chars": len(tc_text),
                })

    completion_breakdown.sort(key=lambda x: x["tokens"], reverse=True)

    # ── Extract real usage ──
    real_usage = None
    if resp_info and isinstance(resp_info.get("usage"), dict):
        real_usage = resp_info["usage"]
    elif isinstance(response_body, dict) and isinstance(response_body.get("usage"), dict):
        real_usage = response_body["usage"]

    # If we have real usage, scale estimated breakdown proportionally
    if real_usage and total_prompt_est > 0:
        real_prompt = real_usage.get("prompt_tokens", 0)
        if real_prompt > 0:
            for item in prompt_breakdown:
                item["tokens"] = round(item["tokens"] / total_prompt_est * real_prompt)
            # Mark as scaled
            for item in prompt_breakdown:
                item["scaled"] = True

    if real_usage and completion_breakdown:
        real_compl = real_usage.get("completion_tokens", 0)
        est_compl_total = sum(c["tokens"] for c in completion_breakdown) or 1
        if real_compl > 0:
            for item in completion_breakdown:
                item["tokens"] = round(item["tokens"] / est_compl_total * real_compl)
                item["scaled"] = True

    if not prompt_breakdown and not completion_breakdown:
        return None

    return {
        "prompt_breakdown": prompt_breakdown,
        "completion_breakdown": completion_breakdown,
        "has_real_usage": real_usage is not None,
    }


def hash_api_key(api_key: str) -> str:
    """Compute a SHA-256 hash of an API key for storage/matching."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


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
    _BATCH_SIZE = 64  # max entries per write transaction
    _BATCH_LINGER_SECONDS = 0.1  # max wait before flushing a partial batch
    _USER_CACHE_TTL = 60.0  # seconds to cache user lookups

    def __init__(self, jsonl_path: Path, sqlite_path: Path, queue_maxsize: int = 5000) -> None:
        self._jsonl_path = jsonl_path
        self._sqlite_path = sqlite_path
        self._error_path = jsonl_path.with_name("log-writer-errors.log")
        self._queue_maxsize = queue_maxsize
        self._queue: Optional[asyncio.Queue[Optional[Dict[str, Any]]]] = None
        self._worker_task: Optional[asyncio.Task[None]] = None
        # Persistent connections: _read_conn for reads, _write_conn for writes
        self._read_conn: Optional[sqlite3.Connection] = None
        self._write_conn: Optional[sqlite3.Connection] = None
        self._conn_lock = threading.Lock()
        # User API key cache: api_key -> (user_dict | None, expiry_time)
        self._user_cache: Dict[str, tuple] = {}
        self._user_cache_lock = threading.Lock()
        # Provider pricing cache: provider_name -> (pricing_tuple | None, expiry_time)
        self._pricing_cache: Dict[str, tuple] = {}
        self._pricing_cache_lock = threading.Lock()

    def _get_read_conn(self) -> sqlite3.Connection:
        with self._conn_lock:
            if self._read_conn is None:
                conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA query_only=ON")
                self._read_conn = conn
            return self._read_conn

    def _get_write_conn(self) -> sqlite3.Connection:
        with self._conn_lock:
            if self._write_conn is None:
                conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                self._write_conn = conn
            return self._write_conn

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
        with self._conn_lock:
            if self._read_conn is not None:
                self._read_conn.close()
                self._read_conn = None
            if self._write_conn is not None:
                self._write_conn.close()
                self._write_conn = None

    async def enqueue(self, entry: Dict[str, Any]) -> None:
        if self._queue is None:
            raise RuntimeError("log queue is not started")
        try:
            self._queue.put_nowait(entry)
        except asyncio.QueueFull:
            # Under extreme load, drop oldest isn't safe; just await
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
        api_key_hashes: Optional[List[str]] = None,
        conv_fingerprint: Optional[str] = None,
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
            api_key_hashes,
            conv_fingerprint,
        )

    async def get_log(self, log_id: str) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._get_log_sync, log_id)

    async def _worker(self) -> None:
        if self._queue is None:
            return
        while True:
            # Wait for first item
            item = await self._queue.get()
            if item is None:
                self._queue.task_done()
                return
            batch = [item]
            # Drain up to _BATCH_SIZE - 1 more items with short linger
            try:
                deadline = asyncio.get_event_loop().time() + self._BATCH_LINGER_SECONDS
                while len(batch) < self._BATCH_SIZE:
                    remaining = deadline - asyncio.get_event_loop().time()
                    if remaining <= 0:
                        break
                    try:
                        next_item = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                    except asyncio.TimeoutError:
                        break
                    if next_item is None:
                        self._queue.task_done()
                        # Flush remaining batch then exit
                        if batch:
                            try:
                                await asyncio.to_thread(self._write_batch_sync, batch)
                            except Exception:
                                for entry in batch:
                                    try:
                                        await asyncio.to_thread(self._write_worker_error_sync, entry, Exception("batch write failed"))
                                    except Exception:
                                        pass
                            for _ in batch:
                                self._queue.task_done()
                        return
                    batch.append(next_item)
            except Exception:
                pass
            # Write the batch
            try:
                await asyncio.to_thread(self._write_batch_sync, batch)
            except Exception:
                # Fallback: try writing entries one by one
                for entry in batch:
                    try:
                        await asyncio.to_thread(self._write_entry_sync, entry)
                    except Exception as exc:
                        await asyncio.to_thread(self._write_worker_error_sync, entry, exc)
            for _ in batch:
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
            if "conv_fingerprint" not in cols:
                conn.execute("ALTER TABLE logs ADD COLUMN conv_fingerprint TEXT")
            if "msg_count" not in cols:
                conn.execute("ALTER TABLE logs ADD COLUMN msg_count INTEGER DEFAULT 0")
            if "api_key_hash" not in cols:
                conn.execute("ALTER TABLE logs ADD COLUMN api_key_hash TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_conv_fingerprint ON logs(conv_fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_api_key_hash ON logs(api_key_hash)")
            conn.commit()

    def _prepare_entry(self, entry: Dict[str, Any]) -> tuple:
        """Prepare an entry for writing; returns (line, db_params) tuple."""
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
        conv_fp = compute_conversation_fingerprint(
            request_body,
            model=extract_model(request_body),
            client=entry.get("client"),
        )
        mc = extract_msg_count(request_body)
        entry["conv_fingerprint"] = conv_fp
        entry["msg_count"] = mc
        token_analysis = analyze_token_breakdown(entry)
        if token_analysis:
            entry["token_analysis"] = token_analysis
        line = dumps_json(entry)
        db_params = (
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
            conv_fp,
            mc,
            entry.get("api_key_hash"),
        )
        return line, db_params

    _INSERT_SQL = """
        INSERT OR REPLACE INTO logs (
            id, created_at, method, path, query_string, target_url,
            provider, request_model, request_stream, response_status,
            duration_ms, search_blob, preview, entry_json,
            estimated_cost, user_id, conv_fingerprint, msg_count,
            api_key_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    def _write_batch_sync(self, entries: List[Dict[str, Any]]) -> None:
        """Write multiple entries in a single JSONL append + single DB transaction."""
        prepared = []
        for entry in entries:
            try:
                prepared.append(self._prepare_entry(entry))
            except Exception as exc:
                self._write_worker_error_sync(entry, exc)
        if not prepared:
            return
        # Batch append to JSONL
        with self._jsonl_path.open("a", encoding="utf-8") as handle:
            for line, _ in prepared:
                handle.write(line)
                handle.write("\n")
        # Batch insert to SQLite in one transaction
        conn = self._get_write_conn()
        conn.executemany(self._INSERT_SQL, [params for _, params in prepared])
        conn.commit()

    def _write_entry_sync(self, entry: Dict[str, Any]) -> None:
        line, db_params = self._prepare_entry(entry)
        with self._jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")
        conn = self._get_write_conn()
        conn.execute(self._INSERT_SQL, db_params)
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
        conn = self._get_read_conn()
        with self._conn_lock:
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
        api_key_hashes: Optional[List[str]] = None,
        conv_fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        where: List[str] = []
        params: List[Any] = []
        if allowed_providers is not None:
            if not allowed_providers:
                return {"items": [], "pagination": {"page": 1, "page_size": page_size, "total": 0, "pages": 1}}
            placeholders = ",".join("?" * len(allowed_providers))
            where.append(f"provider IN ({placeholders})")
            params.extend(allowed_providers)
        if api_key_hashes is not None:
            if not api_key_hashes:
                return {"items": [], "pagination": {"page": 1, "page_size": page_size, "total": 0, "pages": 1}}
            placeholders = ",".join("?" * len(api_key_hashes))
            where.append(f"api_key_hash IN ({placeholders})")
            params.extend(api_key_hashes)
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
        if conv_fingerprint:
            where.append("conv_fingerprint = ?")
            params.append(conv_fingerprint)
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        offset = max(page - 1, 0) * page_size
        conn = self._get_read_conn()
        with self._conn_lock:
            conn.row_factory = sqlite3.Row
            total_row = conn.execute(
                f"SELECT COUNT(*) AS total FROM logs {where_sql}",
                params,
            ).fetchone()
            rows = conn.execute(
                f"""
                SELECT id, created_at, method, path, query_string, target_url, provider,
                       request_model, request_stream, response_status, duration_ms, preview,
                       estimated_cost, conv_fingerprint, msg_count
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
        conn = self._get_read_conn()
        with self._conn_lock:
            row = conn.execute("SELECT entry_json FROM logs WHERE id = ?", (log_id,)).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    async def get_log_with_key_check(self, log_id: str, api_key_hashes: List[str]) -> Optional[Dict[str, Any]]:
        """Get a log entry only if its api_key_hash matches one of the provided hashes."""
        return await asyncio.to_thread(self._get_log_with_key_check_sync, log_id, api_key_hashes)

    def _get_log_with_key_check_sync(self, log_id: str, api_key_hashes: List[str]) -> Optional[Dict[str, Any]]:
        if not api_key_hashes:
            return None
        conn = self._get_read_conn()
        placeholders = ",".join("?" * len(api_key_hashes))
        with self._conn_lock:
            row = conn.execute(
                f"SELECT entry_json FROM logs WHERE id = ? AND api_key_hash IN ({placeholders})",
                [log_id, *api_key_hashes],
            ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    async def verify_api_key_hashes(self, key_hashes: List[str]) -> Dict[str, int]:
        """Return a mapping of key_hash -> record count for each matching hash."""
        return await asyncio.to_thread(self._verify_api_key_hashes_sync, key_hashes)

    def _verify_api_key_hashes_sync(self, key_hashes: List[str]) -> Dict[str, int]:
        if not key_hashes:
            return {}
        conn = self._get_read_conn()
        result: Dict[str, int] = {}
        with self._conn_lock:
            for kh in key_hashes:
                row = conn.execute(
                    "SELECT COUNT(*) FROM logs WHERE api_key_hash = ?", (kh,)
                ).fetchone()
                result[kh] = row[0] if row else 0
        return result

    # ── Batch reanalysis ─────────────────────────────────────────────────

    async def reanalyze_token_breakdowns(self) -> Dict[str, int]:
        return await asyncio.to_thread(self._reanalyze_token_breakdowns_sync)

    def _reanalyze_token_breakdowns_sync(self) -> Dict[str, int]:
        """Re-run analyze_token_breakdown on all stored entries and update."""
        total = 0
        updated = 0
        conn = self._get_write_conn()
        rows = conn.execute("SELECT id, entry_json FROM logs").fetchall()
        total = len(rows)
        for row_id, entry_json_str in rows:
            entry = json.loads(entry_json_str)
            new_analysis = analyze_token_breakdown(entry)
            old_analysis = entry.get("token_analysis")
            if new_analysis != old_analysis:
                if new_analysis:
                    entry["token_analysis"] = new_analysis
                elif "token_analysis" in entry:
                    del entry["token_analysis"]
                new_json = dumps_json(entry)
                conn.execute(
                    "UPDATE logs SET entry_json = ? WHERE id = ?",
                    (new_json, row_id),
                )
                updated += 1
        conn.commit()
        return {"total": total, "updated": updated}

    # ── Conversation timeline ────────────────────────────────────────────

    async def list_conversation_logs(
        self,
        fingerprint: str,
        *,
        allowed_providers: Optional[List[str]] = None,
        api_key_hashes: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(
            self._list_conversation_logs_sync, fingerprint, allowed_providers, api_key_hashes
        )

    def _list_conversation_logs_sync(
        self,
        fingerprint: str,
        allowed_providers: Optional[List[str]] = None,
        api_key_hashes: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        where = ["conv_fingerprint = ?"]
        params: List[Any] = [fingerprint]
        if allowed_providers is not None:
            if not allowed_providers:
                return []
            placeholders = ",".join("?" * len(allowed_providers))
            where.append(f"provider IN ({placeholders})")
            params.extend(allowed_providers)
        if api_key_hashes is not None:
            if not api_key_hashes:
                return []
            placeholders = ",".join("?" * len(api_key_hashes))
            where.append(f"api_key_hash IN ({placeholders})")
            params.extend(api_key_hashes)
        where_sql = "WHERE " + " AND ".join(where)
        conn = self._get_read_conn()
        with self._conn_lock:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT id, created_at, method, path, provider,
                       request_model, request_stream, response_status,
                       duration_ms, preview, estimated_cost, msg_count
                FROM logs
                {where_sql}
                ORDER BY created_at ASC
                LIMIT 200
                """,
                params,
            ).fetchall()
        return [
            {**dict(row), "preview": sanitize_preview_text(str(dict(row).get("preview") or ""))}
            for row in rows
        ]

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
        conn = self._get_write_conn()
        conn.execute(
            """
            INSERT INTO users (id, name, api_key, downstream_url, downstream_apikey, enabled, notes, created_at, role, password_hash)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
            """,
            (user_id, name, api_key, downstream_url or None, downstream_apikey or None, notes or None, created_at, role, pw_hash),
        )
        conn.commit()
        # Invalidate user cache
        with self._user_cache_lock:
            self._user_cache.clear()
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
        conn = self._get_read_conn()
        with self._conn_lock:
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
        conn = self._get_read_conn()
        with self._conn_lock:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id, name, api_key, downstream_url, downstream_apikey, enabled, notes, created_at, role FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        return dict(row) if row else None

    def _get_user_by_apikey_sync(self, api_key: str) -> Optional[Dict[str, Any]]:
        # Check cache first
        now = time.time()
        with self._user_cache_lock:
            cached = self._user_cache.get(api_key)
            if cached and cached[1] > now:
                return cached[0]
        conn = self._get_read_conn()
        with self._conn_lock:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id, name, api_key, downstream_url, downstream_apikey, enabled, notes, created_at, role FROM users WHERE api_key = ?",
                (api_key,),
            ).fetchone()
        result = dict(row) if row else None
        with self._user_cache_lock:
            self._user_cache[api_key] = (result, now + self._USER_CACHE_TTL)
        return result

    def _get_user_by_credentials_sync(self, name: str, password: str) -> Optional[Dict[str, Any]]:
        conn = self._get_read_conn()
        with self._conn_lock:
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
        conn = self._get_write_conn()
        conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
        conn.commit()
        # Invalidate user cache
        with self._user_cache_lock:
            self._user_cache.clear()
        return self._get_user_sync(user_id)

    def _delete_user_sync(self, user_id: str) -> bool:
        conn = self._get_write_conn()
        cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.execute("DELETE FROM user_providers WHERE user_id = ?", (user_id,))
        conn.commit()
        # Invalidate user cache
        with self._user_cache_lock:
            self._user_cache.clear()
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
        conn = self._get_write_conn()
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
        # Invalidate pricing cache
        with self._pricing_cache_lock:
            self._pricing_cache.clear()
        result = self._get_provider_sync(provider_id)
        assert result is not None
        return result

    def _list_providers_sync(self) -> List[Dict[str, Any]]:
        conn = self._get_read_conn()
        with self._conn_lock:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, name, prefix_path, downstream_url, downstream_apikey, enabled, input_price, output_price, notes, created_at FROM providers ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def _get_provider_sync(self, provider_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_read_conn()
        with self._conn_lock:
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
        conn = self._get_write_conn()
        conn.execute(f"UPDATE providers SET {set_clause} WHERE id = ?", values)
        conn.commit()
        # Invalidate pricing cache
        with self._pricing_cache_lock:
            self._pricing_cache.clear()
        return self._get_provider_sync(provider_id)

    def _delete_provider_sync(self, provider_id: str) -> bool:
        conn = self._get_write_conn()
        cursor = conn.execute("DELETE FROM providers WHERE id = ?", (provider_id,))
        conn.execute("DELETE FROM user_providers WHERE provider_id = ?",(provider_id,))
        conn.commit()
        # Invalidate pricing cache
        with self._pricing_cache_lock:
            self._pricing_cache.clear()
        return cursor.rowcount > 0

    def _list_enabled_providers_sync(self) -> List[Dict[str, Any]]:
        conn = self._get_read_conn()
        with self._conn_lock:
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
        conn = self._get_write_conn()
        conn.execute("DELETE FROM user_providers WHERE user_id = ?", (user_id,))
        for pid in provider_ids:
            conn.execute("INSERT OR IGNORE INTO user_providers (user_id, provider_id) VALUES (?, ?)", (user_id, pid))
        conn.commit()

    def _get_user_provider_ids_sync(self, user_id: str) -> List[str]:
        conn = self._get_read_conn()
        with self._conn_lock:
            rows = conn.execute("SELECT provider_id FROM user_providers WHERE user_id = ?", (user_id,)).fetchall()
        return [r[0] for r in rows]

    def _get_user_allowed_providers_sync(self, user_id: str) -> List[str]:
        conn = self._get_read_conn()
        with self._conn_lock:
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
        now = time.time()
        with self._pricing_cache_lock:
            cached = self._pricing_cache.get(provider_name)
            if cached and cached[1] > now:
                return cached[0]
        conn = self._get_read_conn()
        with self._conn_lock:
            row = conn.execute(
                "SELECT input_price, output_price FROM providers WHERE prefix_path = ? OR name = ?",
                (provider_name, provider_name),
            ).fetchone()
        result = (row[0], row[1]) if row and (row[0] or row[1]) else None
        with self._pricing_cache_lock:
            self._pricing_cache[provider_name] = (result, now + self._USER_CACHE_TTL)
        return result
