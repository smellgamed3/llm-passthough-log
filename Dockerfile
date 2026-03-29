# ---- build stage ----
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# 先复制依赖声明，利用 Docker 层缓存
COPY pyproject.toml uv.lock* README.md ./
RUN uv sync --no-dev --no-install-project

# 复制源码并安装项目本身
COPY src/ src/
RUN uv sync --no-dev

# ---- runtime stage ----
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY src/ src/

ENV PATH="/app/.venv/bin:$PATH" \
    HOST=0.0.0.0 \
    PORT=8000 \
    LOG_DIR=/app/data

VOLUME /app/data
EXPOSE 8000

ENTRYPOINT ["llm-proxy"]
