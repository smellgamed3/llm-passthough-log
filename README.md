# LLM Passthough Log

基于 FastAPI 和 httpx 的透明 LLM HTTP 代理，支持：

- 原样转发任意 HTTP 请求到下游 LLM Provider
- 完整记录请求、响应、SSE 流式返回、错误信息
- JSONL 原始日志落盘
- SQLite 索引，支持管理后台检索与统计
- 基于 uv 的 Python 项目管理

## 运行

```bash
uv sync
uv run llm-proxy
```

默认启动地址：

- 代理入口：http://127.0.0.1:8000
- 管理页面：http://127.0.0.1:8000/admin

## 常用环境变量

```bash
DOWNSTREAM_URL=https://api.openai.com
LOG_DIR=./data
LOG_QUEUE_MAXSIZE=5000
REQUEST_TIMEOUT_SECONDS=300
ADMIN_TITLE="LLM 透明代理控制台"
PROVIDER_ROUTES_JSON='{"openai":"https://api.openai.com","claude":"https://api.anthropic.com"}'
```

当配置了 `PROVIDER_ROUTES_JSON` 时，可通过前缀路由到不同 Provider：

- `/openai/v1/chat/completions`
- `/claude/v1/messages`

## 开发

```bash
uv sync --extra dev
uv run pytest
```
