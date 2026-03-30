

# LLM 透明代理 — 需求与技术方案

---

## 1. 需求

### 1.1 目标

在客户端与 LLM Provider 之间部署透明代理，**完整记录所有对话内容**，对上下游零侵入。

### 1.2 功能需求

| 编号 | 需求 | 说明 |
|---|---|---|
| F1 | 透明转发 | 客户端仅需修改 `base_url`，其余代码不变 |
| F2 | 完整记录请求 | 包含 prompt、model、temperature、max_tokens 等所有参数 |
| F3 | 完整记录响应 | 包含返回内容、token 用量、finish_reason 等 |
| F4 | 流式支持 | SSE 流式响应逐 chunk 转发，结束后拼接完整内容记录 |
| F5 | 多 Provider 兼容 | OpenAI / Claude / Gemini / Azure / Ollama / vLLM 等，无需逐一适配 |
| F6 | Headers 透传 | 完整转发 Authorization 等认证头 |

### 1.3 非功能需求

| 编号 | 需求 | 说明 |
|---|---|---|
| N1 | 低延迟 | 代理引入的额外延迟 < 10ms |
| N2 | 高可用 | 代理故障不应导致数据丢失，日志异步写入 |
| N3 | 可部署性 | 单文件部署，依赖最小化 |

---

## 2. 技术方案

### 2.1 架构

```
Client ──→ LLM Proxy (FastAPI) ──→ LLM Provider
                  │
                  ↓
             JSONL 日志
```

**核心原则：HTTP 层透传，不解析 LLM 协议。** 代理只做字节级转发 + 原始记录，因此天然兼容所有基于 HTTP 的 LLM API。

### 2.2 技术选型

| 组件 | 选择 | 理由 |
|---|---|---|
| 框架 | FastAPI | 原生 async，性能好，代码量少 |
| HTTP 客户端 | httpx | 支持 async + streaming |
| 日志格式 | JSONL | 零依赖，一行一条记录，便于后续分析 |
| 部署 | uvicorn | 单命令启动 |

### 2.3 核心实现

```python name=llm_proxy.py
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from httpx import AsyncClient
import json, time, uuid, os

app = FastAPI()
client = AsyncClient(timeout=300)
DOWNSTREAM_URL = os.getenv("DOWNSTREAM_URL", "https://api.openai.com")

# ── 工具函数 ──

def save_log(entry: dict):
    with open("logs.jsonl", "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")

def try_parse(raw: bytes):
    try:
        return json.loads(raw)
    except Exception:
        return raw.decode("utf-8", errors="replace")

# ── 透明代理入口 ──

@app.api_route("/{path:path}", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
async def proxy(request: Request, path: str):
    body = await request.body()
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "content-length")}

    target_url = f"{DOWNSTREAM_URL}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    log_entry = {
        "id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "method": request.method,
        "url": target_url,
        "request_headers": dict(request.headers),
        "request_body": try_parse(body),
    }

    # 流式检测
    is_stream = False
    if body:
        try:
            is_stream = json.loads(body).get("stream", False)
        except Exception:
            pass

    if is_stream:
        return await _handle_stream(request.method, target_url, headers, body, log_entry)
    return await _handle_normal(request.method, target_url, headers, body, log_entry)

# ── 非流式 ──

async def _handle_normal(method, url, headers, body, log_entry):
    resp = await client.request(method=method, url=url, headers=headers, content=body)
    log_entry["response_status"] = resp.status_code
    log_entry["response_headers"] = dict(resp.headers)
    log_entry["response_body"] = try_parse(resp.content)
    save_log(log_entry)
    return Response(
        content=resp.content, status_code=resp.status_code,
        headers={k: v for k, v in resp.headers.items()
                 if k.lower() not in ("content-encoding","transfer-encoding","content-length")},
    )

# ── 流式 ──

async def _handle_stream(method, url, headers, body, log_entry):
    async def stream_and_log():
        collected = []
        async with client.stream(method, url, headers=headers, content=body) as resp:
            log_entry["response_status"] = resp.status_code
            log_entry["response_headers"] = dict(resp.headers)
            async for chunk in resp.aiter_bytes():
                collected.append(chunk.decode("utf-8", errors="replace"))
                yield chunk
        log_entry["response_body_chunks"] = collected
        save_log(log_entry)
    return StreamingResponse(stream_and_log(), media_type="text/event-stream")
```

### 2.4 日志格式

每条记录为一行 JSON，包含完整原始数据：

```json name=log_example.jsonl
{
  "id": "a1b2c3d4",
  "timestamp": 1711670400.0,
  "method": "POST",
  "url": "https://api.openai.com/v1/chat/completions",
  "request_headers": {"authorization": "Bearer sk-xxx", "content-type": "application/json"},
  "request_body": {
    "model": "gpt-4",
    "temperature": 0.7,
    "max_tokens": 2000,
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "什么是量子计算？"}
    ]
  },
  "response_status": 200,
  "response_body": {
    "choices": [{"message": {"role": "assistant", "content": "量子计算是..."}}],
    "usage": {"prompt_tokens": 25, "completion_tokens": 150}
  }
}
```

### 2.5 客户端接入

客户端仅需修改一行配置：

```python name=client_usage.py
from openai import OpenAI

client = OpenAI(
    api_key="sk-xxx",
    base_url="http://localhost:8000/v1",  # 原为 https://api.openai.com/v1
)
```

### 2.6 部署

```bash name=run.sh
pip install fastapi httpx uvicorn
DOWNSTREAM_URL=https://api.openai.com uvicorn llm_proxy:app --host 0.0.0.0 --port 8000
```

### 2.7 多 Provider 路由（可选扩展）

```python name=multi_provider.py
# 通过 URL 前缀路由到不同后端
# http://proxy:8000/openai/v1/chat/completions → https://api.openai.com
# http://proxy:8000/claude/v1/messages          → https://api.anthropic.com
ROUTES = {
    "openai": "https://api.openai.com",
    "claude": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com",
    "ollama": "http://localhost:11434",
}
```

---

## 3. 兼容性

| Provider | 是否兼容 | 原因 |
|---|---|---|
| OpenAI / Azure OpenAI | ✅ | HTTP + SSE |
| Claude (Anthropic) | ✅ | HTTP + SSE |
| Gemini | ✅ | HTTP |
| Ollama / vLLM / TGI | ✅ | HTTP + SSE |
| 任意 REST API | ✅ | HTTP 透传 |
| gRPC / WebSocket | ⚠️ | 需额外适配 |

**兼容的根本原因：** 代理在 HTTP 层工作，不解析任何 LLM 特定协议，因此对所有基于 HTTP 的 LLM API 天然兼容。

---

## 4. 演进历史

| 版本 | 内容 | 状态 |
|---|---|---|
| v0.1 | 单文件透明代理 + JSONL 日志 | ✅ |
| v0.1.3 | 敏感信息脱敏（API Key、Bearer Token） | ✅ |
| v0.2 | 多轮对话关联 + 会话时间线 | ✅ |
| v0.3 | Token 结构分析 + 管理台批量重分析 | ✅ |
| v0.4 | 高负载优化、URL 域名脱敏 | ✅ |
| v1.0 | 公开搜索页面（/search）、API Key 权限隔离、非 admin 用户记录限制 | ✅ |
| **v1.1** | **搜索页友好视图：Token 用量分析、Prompt/Completion 构成明细、请求参数展示** | **✅ 当前** |
| v1.2+ | 多实例部署、集中式日志收集、速率限制 | 计划中 |