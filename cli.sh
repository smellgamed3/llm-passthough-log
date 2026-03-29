#!/usr/bin/env bash
# ===========================================
# LLM 透明代理 — 快捷操作脚本
# ===========================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="$SCRIPT_DIR/.env"
PID_FILE="$SCRIPT_DIR/data/.pid"
LOG_FILE="$SCRIPT_DIR/data/server.log"

# ---------- 加载 .env ----------
load_env() {
    if [[ -f "$ENV_FILE" ]]; then
        set -a
        # shellcheck source=/dev/null
        source "$ENV_FILE"
        set +a
    else
        echo "⚠  未找到 .env，使用默认配置（可从 .env.example 复制）"
    fi
}

# ---------- 确保 data 目录 ----------
ensure_dirs() {
    mkdir -p "$SCRIPT_DIR/data"
}

# ---------- 获取运行中的 PID ----------
running_pid() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return 0
        fi
        rm -f "$PID_FILE"
    fi
    return 1
}

# ========== 命令：start ==========
cmd_start() {
    load_env
    ensure_dirs

    if pid=$(running_pid); then
        echo "✦  代理已在运行 (PID: $pid)"
        return 0
    fi

    local host="${HOST:-0.0.0.0}"
    local port="${PORT:-8000}"

    echo "▸  启动 LLM 透明代理  →  ${host}:${port}"
    nohup uv run llm-proxy > "$LOG_FILE" 2>&1 &
    local new_pid=$!
    echo "$new_pid" > "$PID_FILE"
    sleep 1

    if kill -0 "$new_pid" 2>/dev/null; then
        echo "✔  已启动 (PID: $new_pid)"
        echo "   日志: $LOG_FILE"
        echo "   管理后台: http://${host}:${port}/admin"
    else
        echo "✘  启动失败，请查看日志: $LOG_FILE"
        rm -f "$PID_FILE"
        return 1
    fi
}

# ========== 命令：stop ==========
cmd_stop() {
    if pid=$(running_pid); then
        echo "▸  停止代理 (PID: $pid) ..."
        kill "$pid"
        # 等待进程退出，最长 10 秒
        for i in $(seq 1 10); do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        if kill -0 "$pid" 2>/dev/null; then
            echo "⚠  进程未退出，强制终止 ..."
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
        echo "✔  已停止"
    else
        echo "✦  代理未在运行"
    fi
}

# ========== 命令：restart ==========
cmd_restart() {
    cmd_stop
    sleep 1
    cmd_start
}

# ========== 命令：status ==========
cmd_status() {
    load_env
    local host="${HOST:-0.0.0.0}"
    local port="${PORT:-8000}"

    if pid=$(running_pid); then
        echo "✔  代理运行中 (PID: $pid)"
        echo "   地址: http://${host}:${port}"
        echo "   后台: http://${host}:${port}/admin"
        # 尝试健康检查
        if command -v curl &>/dev/null; then
            local health
            health=$(curl -sf "http://127.0.0.1:${port}/healthz" 2>/dev/null) || true
            if [[ -n "$health" ]]; then
                echo "   健康: $health"
            fi
        fi
    else
        echo "✘  代理未在运行"
    fi
}

# ========== 命令：logs ==========
cmd_logs() {
    if [[ -f "$LOG_FILE" ]]; then
        local lines="${1:-50}"
        echo "▸  最近 ${lines} 行日志 ($LOG_FILE):"
        echo "─────────────────────────────────"
        tail -n "$lines" "$LOG_FILE"
    else
        echo "✦  暂无日志文件"
    fi
}

# ========== 命令：follow ==========
cmd_follow() {
    if [[ -f "$LOG_FILE" ]]; then
        echo "▸  实时日志 (Ctrl+C 退出):"
        tail -f "$LOG_FILE"
    else
        echo "✦  暂无日志文件"
    fi
}

# ========== 命令：dev ==========
cmd_dev() {
    load_env
    ensure_dirs
    local host="${HOST:-0.0.0.0}"
    local port="${PORT:-8000}"
    echo "▸  开发模式启动 (热更新)  →  http://${host}:${port}/admin"
    echo "   监听目录: src/  |  Ctrl+C 退出"
    uv run uvicorn llm_passthough_log.app:app \
        --host "$host" \
        --port "$port" \
        --reload \
        --reload-dir src
}

# ========== 命令：test ==========
cmd_test() {
    echo "▸  运行测试 ..."
    uv run python -m pytest "$@"
}

# ========== 命令：clean ==========
cmd_clean() {
    echo "▸  清理数据文件 ..."
    read -rp "确认删除 data/ 下所有日志？[y/N] " answer
    if [[ "${answer,,}" == "y" ]]; then
        rm -rf "$SCRIPT_DIR/data"
        echo "✔  已清理"
    else
        echo "✦  已取消"
    fi
}

# ========== 帮助 ==========
cmd_help() {
    cat <<EOF
╔══════════════════════════════════════════════╗
║    LLM 透明代理 — 快捷操作                   ║
╚══════════════════════════════════════════════╝

用法: ./cli.sh <命令> [参数]

命令:
  start       后台启动代理服务
  stop        停止代理服务
  restart     重启代理服务
  status      查看运行状态与健康检查
    logs [N]    查看最近 N 行日志 (默认 50)
    log [N]     logs 的别名
  follow      实时跟踪日志输出
  dev         开发模式启动 (自动 reload)
  test        运行测试 (支持传递 pytest 参数)
  clean       清理数据目录
  help        显示本帮助

配置:
  编辑 .env 文件设置环境变量（从 .env.example 复制）

示例:
  ./cli.sh start              # 后台启动
  ./cli.sh dev                # 开发模式
  ./cli.sh logs 100           # 查看最近 100 行
  ./cli.sh test -v            # 详细测试输出
  ./cli.sh status             # 查看状态
EOF
}

# ========== 入口 ==========
case "${1:-help}" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    restart) cmd_restart ;;
    status)  cmd_status ;;
    logs|log) cmd_logs "${2:-50}" ;;
    follow)  cmd_follow ;;
    dev)     cmd_dev ;;
    test)    shift; cmd_test "$@" ;;
    clean)   cmd_clean ;;
    help|-h|--help) cmd_help ;;
    *)
        echo "✘  未知命令: $1"
        echo ""
        cmd_help
        exit 1
        ;;
esac
