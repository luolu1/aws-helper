#!/usr/bin/env bash
# 一键启动演示站：moto 模拟 AWS 后端 + AWS 小助手 Web 面板
#
# 用法：
#   ./aws_helper/demo/start.sh              # 只听本机 127.0.0.1
#   ./aws_helper/demo/start.sh 0.0.0.0      # 对外暴露（演示用）
#   ./aws_helper/demo/start.sh 0.0.0.0 9000 # 指定端口
set -euo pipefail

BIND_HOST="${1:-127.0.0.1}"
WEB_PORT="${2:-8765}"
MOTO_PORT="${MOTO_PORT:-5001}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_DIR="${AWS_HELPER_DEMO_DIR:-/tmp/aws-helper-demo}"

export AWS_HELPER_DATA="$RUN_DIR/data"
export AWS_HELPER_ENDPOINT_URL="http://127.0.0.1:${MOTO_PORT}"
export AWS_HELPER_PASSWORD="${AWS_HELPER_PASSWORD:-Demo!Passw0rd}"
export AWS_HELPER_SESSION_KEY="${AWS_HELPER_SESSION_KEY:-$(python3 -c 'import secrets;print(secrets.token_hex(32))')}"
export PYTHONPATH="$PROJECT_ROOT"

mkdir -p "$RUN_DIR/data"

echo "==> 清理旧进程"
pkill -f "moto.server .*${MOTO_PORT}" 2>/dev/null || true
pkill -f "uvicorn aws_helper.web.app" 2>/dev/null || true
sleep 2

echo "==> 启动 moto（模拟 AWS EC2 API，端口 ${MOTO_PORT}）"
cd "$PROJECT_ROOT"
setsid nohup python3 -m moto.server -p "$MOTO_PORT" -H 127.0.0.1 \
  > "$RUN_DIR/moto.log" 2>&1 < /dev/null &

for i in $(seq 1 30); do
  if curl -sf -o /dev/null "http://127.0.0.1:${MOTO_PORT}/moto-api/"; then
    echo "    moto 就绪"
    break
  fi
  [ "$i" = "30" ] && { echo "    moto 启动失败，见 $RUN_DIR/moto.log"; exit 1; }
  sleep 1
done

echo "==> 预置演示数据"
python3 "$PROJECT_ROOT/aws_helper/demo/seed.py"

echo "==> 启动 Web 面板（${BIND_HOST}:${WEB_PORT}）"
setsid nohup python3 -m uvicorn aws_helper.web.app:app \
  --host "$BIND_HOST" --port "$WEB_PORT" \
  > "$RUN_DIR/web.log" 2>&1 < /dev/null &

for i in $(seq 1 30); do
  if curl -sf -o /dev/null "http://127.0.0.1:${WEB_PORT}/healthz"; then
    echo "    面板就绪"
    break
  fi
  [ "$i" = "30" ] && { echo "    面板启动失败，见 $RUN_DIR/web.log"; exit 1; }
  sleep 1
done

echo
echo "======================================================"
echo "  演示站已启动"
echo "  地址    : http://${BIND_HOST}:${WEB_PORT}"
echo "  密码    : ${AWS_HELPER_PASSWORD}"
echo "  忘密码  : AWS_HELPER_DATA=$RUN_DIR/data python3 -m aws_helper.cli reset-password"
echo "  日志    : $RUN_DIR/web.log  |  $RUN_DIR/moto.log"
echo "  后端    : moto 模拟，不产生任何真实 AWS 费用"
echo "======================================================"
