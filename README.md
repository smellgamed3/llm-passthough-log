# LLM Passthough Log

基于 FastAPI 和 httpx 的透明 LLM HTTP 代理，支持：

- 原样转发任意 HTTP 请求到下游 LLM Provider
- 完整记录请求、响应、SSE 流式返回、错误信息
- 管理后台强制账号密码登录，管理员账号仅可通过 `.env` 指定
- **公开搜索页面**：无需登录，通过 API Key 识别身份，仅查看自己 Key 关联的记录
- JSONL 原始日志落盘 + SQLite 索引检索
- 自动为流式请求补充 `stream_options.include_usage=true`
- Token 结构分析（prompt 按角色、completion 按类别）+ 批量重分析
- 多轮对话关联 + 会话时间线可视化
- 敏感信息脱敏：API Key、Bearer Token、下游 URL 域名等全链路自动脱敏
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
- 非 admin 用户在管理台只能查看 LLM 对话和 Embeddings 两类记录

## 公开搜索页面 (`/search`)

项目提供一个无需登录的公开搜索入口，任何人可以通过提供 API Key 来查看与该 Key 关联的日志记录：

- **访问地址**：`http://127.0.0.1:8000/search`
- **Key 管理**：页面顶部支持添加多个 API Key，可设置别名、快速切换、多选合并查看
- **权限隔离**：仅展示与用户提供的 API Key 匹配的记录，无法查看其他人的数据
- **内容限制**：仅可查看 LLM 对话和 Embeddings 两类记录
- **Key 脱敏**：页面上 API Key 始终脱敏显示（如 `sk-xxxx…abcd`）
- **友好视图**：默认 Tab 展示 Token 用量分析、Prompt 构成明细、Completion 构成明细、请求参数，与管理台一致
- **额外特性**：每个 Key 分配独立颜色标识、支持内联编辑别名、面板可折叠

技术实现：代理转发时从请求的 `Authorization` 头提取原始 Bearer Token，计算 SHA-256 哈希存入 `api_key_hash` 字段。搜索页 POST 提交原始 Key，后端哈希后匹配，不暴露哈希值给客户端。

## Token 用量可视化

- 流式请求自动补齐 `stream_options.include_usage=true`
- 入库时 `token_analysis`：prompt 按角色拆分，completion 按类别拆分
- 优先展示 provider 真实 `usage`，结构分析做比例映射
- 管理台支持一键「重新分析 Token」批量更新历史数据

## 多 Provider 路由

配置 `PROVIDER_ROUTES_JSON` 后可通过前缀路由到不同 Provider：

- `/openai/v1/chat/completions`
- `/claude/v1/messages`

## 多轮对话关联

根据 system prompt、model、client IP 自动计算会话指纹 (`conv_fingerprint`)，关联同一对话的多次请求。Trace 列表显示彩色标识，详情页有会话时间线标签页。

## 敏感信息脱敏

日志持久化、API 返回、前端展示三层均自动脱敏：

- **API Key / Bearer Token**：`sk-xxx...xxxx` 格式保留首尾
- **下游 URL 域名**：主机名脱敏，保留 scheme、端口和路径
- **Provider downstream_apikey**：仅返回掩码字段，原始值不出库
- **全链路覆盖**：入库、API、前端 JS 三层校验

## 开发

```bash
uv sync --extra dev
uv run pytest
```

## 性能与并发优化

- SQLite 读写分离（WAL + `synchronous=NORMAL`）
- 后台 worker 批量写入（最多 64 条/批）
- 用户认证 + Provider 价格 60s TTL 缓存
- httpx 连接池调优（200 connections, 40 keepalive）

## 版本

- 当前版本：`1.1.0`
- 最新标签：`v1.1.0`
