# LLM Passthough Log

基于 FastAPI 和 httpx 的透明 LLM HTTP 代理，支持：

- 原样转发任意 HTTP 请求到下游 LLM Provider
- 完整记录请求、响应、SSE 流式返回、错误信息
- 管理后台强制账号密码登录，管理员账号仅可通过 `.env` 指定
- JSONL 原始日志落盘
- SQLite 索引，支持管理后台检索与统计
- 自动为流式聊天请求补充 `stream_options.include_usage=true`，恢复 token 用量可视化
- 入库阶段自动完成 Token 结构分析（prompt 按角色、completion 按类别）并持久化
- 支持基于新规则批量重分析历史记录（管理台一键触发）
- 多轮对话关联：自动识别同一会话的请求并在 UI 中可视化
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
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="change-me"
PROVIDER_ROUTES_JSON='{"openai":"https://api.openai.com","claude":"https://api.anthropic.com"}'
```

说明：

- 管理后台必须先登录后才能使用
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` 必填，且管理员只能通过 `.env` 手动维护
- web 管理台仅允许 admin 创建、编辑、删除普通用户
- 普通用户通过账号密码登录后，只能查看自己被授权的 provider 数据

## Token 用量可视化

- 对于流式请求，代理会自动补齐 `stream_options.include_usage=true`，便于记录 provider 返回的官方 token 用量
- 日志入库时会进行 `token_analysis`：
	- prompt 按常见消息来源拆分：`system`、`user`、`assistant`、`tool`、`tools_schema`
	- completion 按输出类别拆分：`text_output`、`reasoning`、`tool_calls`
- 当 provider 返回真实 `usage` 时，面板优先展示真实总量，并按结构分析结果做比例映射展示
- 对于历史日志或 provider 未返回 `usage` 的场景，详情页会展示估算版 token 面板，便于快速做 prompt 优化
- 当 Token 统计规则升级后，可在管理台概览页点击「重新分析 Token」批量更新历史数据；后端接口：`POST /admin/api/reanalyze`（管理员权限）

当配置了 `PROVIDER_ROUTES_JSON` 时，可通过前缀路由到不同 Provider：

- `/openai/v1/chat/completions`
- `/claude/v1/messages`

## 多轮对话关联

代理会根据请求中的 system prompt、model、client IP 自动计算会话指纹 (`conv_fingerprint`)，将属于同一多轮对话的请求关联在一起：

- Trace 列表中显示彩色会话标识和消息数，点击可筛选同一会话的所有请求
- 详情面板新增「会话时间线」标签页，按时间顺序展示同一会话的全部调用
- 支持通过 API `GET /admin/api/conversation/{fingerprint}` 查询会话时间线

## 开发

```bash
uv sync --extra dev
uv run pytest
```

## 性能与并发优化

项目在高负载场景下做了以下优化，确保代理延迟低、吞吐量高：

- **SQLite 读写分离**：持久化复用读/写连接（WAL 模式 + `synchronous=NORMAL`），避免每次请求新建连接
- **日志批量写入**：后台 worker 批量收集最多 64 条日志，单事务写入 SQLite + 一次性追加 JSONL，大幅降低 I/O 开销
- **用户认证缓存**：API Key 查询结果带 60s TTL 缓存，代理热路径不再逐次查库
- **Provider 价格缓存**：同样 60s TTL，避免每条日志写入时查询价格表
- **httpx 连接池调优**：max_connections=200, max_keepalive=40, keepalive_expiry=30s，适配 LLM 长连接场景

## 版本

- 当前版本：`0.3.0`
- 最新标签：`v0.3.0`
