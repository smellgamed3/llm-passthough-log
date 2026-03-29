from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse


def _resolve_path(value: str, base_dir: Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (base_dir / path).resolve()


@dataclass(frozen=True)
class Settings:
    app_name: str
    downstream_url: str
    log_dir: Path
    jsonl_path: Path
    sqlite_path: Path
    request_timeout_seconds: float
    admin_title: str
    provider_routes: Dict[str, str]
    queue_maxsize: int
    admin_page_size_default: int
    admin_page_size_max: int
    default_provider_name: str
    admin_api_key: Optional[str]

    @classmethod
    def from_env(cls, base_dir: Optional[Path] = None) -> "Settings":
        resolved_base_dir = (base_dir or Path.cwd()).resolve()
        log_dir = _resolve_path(os.getenv("LOG_DIR", "data"), resolved_base_dir)
        downstream_url = os.getenv("DOWNSTREAM_URL", "https://api.openai.com").rstrip("/")
        routes_raw = os.getenv("PROVIDER_ROUTES_JSON", "").strip()
        provider_routes: Dict[str, str] = {}
        if routes_raw:
            parsed = json.loads(routes_raw)
            provider_routes = {
                str(prefix).strip("/"): str(target).rstrip("/")
                for prefix, target in parsed.items()
                if str(prefix).strip("/") and str(target).strip()
            }
        provider_name = urlparse(downstream_url).netloc or "default"
        return cls(
            app_name=os.getenv("APP_NAME", "LLM Passthough Log"),
            downstream_url=downstream_url,
            log_dir=log_dir,
            jsonl_path=log_dir / "logs.jsonl",
            sqlite_path=log_dir / "logs.db",
            request_timeout_seconds=float(os.getenv("REQUEST_TIMEOUT_SECONDS", "300")),
            admin_title=os.getenv("ADMIN_TITLE", "LLM 透明代理控制台"),
            provider_routes=provider_routes,
            queue_maxsize=int(os.getenv("LOG_QUEUE_MAXSIZE", "5000")),
            admin_page_size_default=int(os.getenv("ADMIN_PAGE_SIZE_DEFAULT", "20")),
            admin_page_size_max=int(os.getenv("ADMIN_PAGE_SIZE_MAX", "100")),
            default_provider_name=provider_name,
            admin_api_key=os.getenv("ADMIN_API_KEY") or None,
        )

    def resolve_target(self, path: str) -> Tuple[str, str, str]:
        normalized_path = path.lstrip("/")
        if self.provider_routes and normalized_path:
            prefix, _, remainder = normalized_path.partition("/")
            if prefix in self.provider_routes:
                target_base = self.provider_routes[prefix]
                suffix = remainder
                target_path = f"/{suffix}" if suffix else ""
                return prefix, target_base, f"{target_base}{target_path}"
        target_path = f"/{normalized_path}" if normalized_path else ""
        return self.default_provider_name, self.downstream_url, f"{self.downstream_url}{target_path}"
