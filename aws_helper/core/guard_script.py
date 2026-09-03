"""生成装在实例上的「被墙自愈」探测脚本。

面板从海外探测判断不了「被墙」—— 墙是单向的，从境外连实例通常一直是通的。
所以把探测放到实例自己身上：实例从境内视角连一个国内站点，连不上说明出网
被拦，这时才上报给面板，面板给它换 IP。

**探测正常不上报**，只在被墙时才发一次请求 —— 这是用户明确要求的，省下
面板的开销和无意义的流量。但完全不通信面板就分不清「一切正常」和「脚本挂了」，
所以另有一个低频心跳（默认 10 倍探测间隔），只带一个时间戳。

跟 ddns_script 一样刻意用 bash + curl：脚本要能丢到任何一台机器上跑。
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit

INSTALL_PATH = "/usr/local/bin/aws-helper-guard"
ENV_PATH = "/etc/aws-helper-guard.env"
SERVICE_NAME = "aws-helper-guard"
STATE_DIR = "/var/lib/aws-helper-guard"

# 默认探测目标。选百度是因为它几乎不会整站挂，且 443 一直开着。
DEFAULT_TARGET = "www.baidu.com:443"

_HOST_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$"
)


class GuardScriptError(ValueError):
    """生成脚本的参数不合法。"""


@dataclass
class GuardRequest:
    instance_id: str = ""
    report_url: str = ""
    token: str = ""
    target: str = DEFAULT_TARGET
    interval_sec: int = 60
    fail_threshold: int = 3
    timeout_sec: int = 5


def parse_target(raw: str) -> tuple[str, int]:
    """把用户填的探测目标解析成 (主机, 端口)。

    接受 `host`、`host:port`、`https://host/path` 几种写法 —— 用户大概率
    会直接粘一个网址进来，报错不如兼容。不带端口时按 443（国内站点基本
    全上了 HTTPS，且 443 比 80 更少被中间设备干扰）。
    """
    text = (raw or "").strip()
    if not text:
        return _split_hostport(DEFAULT_TARGET)
    if "://" in text:
        parts = urlsplit(text)
        host = parts.hostname or ""
        port = parts.port or (80 if parts.scheme == "http" else 443)
        if not host:
            raise GuardScriptError(f"解析不出主机名: {raw}")
        return _check_host(host), port
    return _split_hostport(text)


def _split_hostport(text: str) -> tuple[str, int]:
    if text.count(":") == 1:
        host, _, port_text = text.partition(":")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise GuardScriptError(f"端口不是数字: {port_text}") from exc
        if not 1 <= port <= 65535:
            raise GuardScriptError(f"端口超出范围: {port}")
        return _check_host(host), port
    return _check_host(text), 443


def _check_host(host: str) -> str:
    host = host.strip().strip(".").lower()
    if not host:
        raise GuardScriptError("探测目标不能为空")
    try:
        # 填 IP 也允许，直接放过
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOST_RE.match(host):
        raise GuardScriptError(f"探测目标格式不对: {host}")
    return host


def _validate(req: GuardRequest) -> tuple[GuardRequest, str, int]:
    if not req.report_url.strip():
        raise GuardScriptError("缺少上报地址")
    if not req.token.strip():
        raise GuardScriptError("缺少上报凭证")

    url = req.report_url.strip()
    if not url.startswith(("http://", "https://")):
        raise GuardScriptError("上报地址必须以 http:// 或 https:// 开头")

    host, port = parse_target(req.target)

    # 探测太密集没有意义：换一次 IP 本身要几十秒，而且频繁 TCP 连同一个
    # 站点看起来像扫描。下限 20 秒。
    interval = max(20, min(int(req.interval_sec), 3600))
    threshold = max(1, min(int(req.fail_threshold), 20))
    timeout = max(1, min(int(req.timeout_sec), 30))

    return (
        GuardRequest(
            instance_id=req.instance_id.strip(),
            report_url=url,
            token=req.token.strip(),
            target=f"{host}:{port}",
            interval_sec=interval,
            fail_threshold=threshold,
            timeout_sec=timeout,
        ),
        host,
        port,
    )


def _guard_body() -> str:
    """常驻探测脚本。装到实例上由 systemd 拉起，自己 sleep 循环。

    用常驻循环而不是 timer：探测间隔可以短到 20 秒，timer 在这个粒度上
    每次都要拉起一个新进程，开销比 sleep 大得多。
    """
    return r'''#!/usr/bin/env bash
# 被墙自愈探测器 —— 由 aws-helper 面板生成，独立运行，不依赖面板存活
set -uo pipefail

CONF="${GUARD_ENV_FILE:-/etc/aws-helper-guard.env}"
[ -r "$CONF" ] || { echo "读不到配置 $CONF" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"

: "${GUARD_REPORT_URL:?配置缺少 GUARD_REPORT_URL}"
: "${GUARD_TOKEN:?配置缺少 GUARD_TOKEN}"
# 创建时部署不知道实例 ID，开机后从 IMDS 读取。手工生成脚本仍会写死 ID，
# 优先使用配置值，IMDS 只在它为空时兜底。
if [ -z "${GUARD_INSTANCE_ID:-}" ]; then
    GUARD_INSTANCE_ID=$(curl -fsS --max-time 3 \
        http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || true)
fi
: "${GUARD_INSTANCE_ID:?配置缺少实例 ID，且无法从 EC2 IMDS 读取}"
GUARD_HOST="${GUARD_HOST:-www.baidu.com}"
GUARD_PORT="${GUARD_PORT:-443}"
GUARD_INTERVAL="${GUARD_INTERVAL:-60}"
GUARD_THRESHOLD="${GUARD_THRESHOLD:-3}"
GUARD_TIMEOUT="${GUARD_TIMEOUT:-5}"
STATE_DIR="${GUARD_STATE_DIR:-/var/lib/aws-helper-guard}"
mkdir -p "$STATE_DIR"

log() { printf '%s %s\n' "$(date '+%F %T')" "$*"; }

# 探测：TCP 连国内站点。用 bash 内建的 /dev/tcp，不额外依赖 nc。
# 超时靠 timeout 命令控制 —— /dev/tcp 自己没有超时参数，连不上时会
# 一直挂到内核放弃（可能几分钟），那样整个循环就卡死了。
probe() {
    timeout "$GUARD_TIMEOUT" bash -c \
        "exec 3<>/dev/tcp/${GUARD_HOST}/${GUARD_PORT}" 2>/dev/null
}

# 上报。只在判定被墙时调用，正常情况一个包都不发。
# --max-time 防止面板挂了把脚本拖住；失败不退出，下一轮继续探测。
report() {
    local kind="$1" detail="$2" code
    code=$(curl -sS -o "$STATE_DIR/last-report.json" -w '%{http_code}' \
        --max-time 15 \
        -X POST "$GUARD_REPORT_URL" \
        -H 'Content-Type: application/json' \
        -H "X-Guard-Token: $GUARD_TOKEN" \
        -d "{\"instance_id\":\"$GUARD_INSTANCE_ID\",\"kind\":\"$kind\",\"detail\":\"$detail\"}" \
        2>>"$STATE_DIR/report-error.log") || code="000"
    if [ "$code" = "200" ]; then
        log "上报成功（$kind）: $(cat "$STATE_DIR/last-report.json" 2>/dev/null | head -c 200)"
        return 0
    fi
    log "上报失败（$kind）HTTP $code: $(cat "$STATE_DIR/last-report.json" 2>/dev/null | head -c 200)"
    return 1
}

fails=0
# 心跳间隔取探测间隔的 10 倍：正常时不上报是用户要求的，但面板要能区分
# 「一切正常」和「脚本挂了」，所以留一个低频心跳。
heartbeat_every=$((GUARD_INTERVAL * 10))
last_heartbeat=0

log "启动：每 ${GUARD_INTERVAL}s 探测 ${GUARD_HOST}:${GUARD_PORT}，连续 ${GUARD_THRESHOLD} 次失败上报"
report started "启动探测 ${GUARD_HOST}:${GUARD_PORT}" || true
last_heartbeat=$(date +%s)

while :; do
    if probe; then
        if [ "$fails" -gt 0 ]; then
            log "恢复连通（此前失败 $fails 次）"
            fails=0
        fi
    else
        fails=$((fails + 1))
        log "探测失败 ${fails}/${GUARD_THRESHOLD}（${GUARD_HOST}:${GUARD_PORT} 不可达）"
        if [ "$fails" -ge "$GUARD_THRESHOLD" ]; then
            log "达到阈值，上报面板请求换 IP"
            if report blocked "连续 ${fails} 次连不上 ${GUARD_HOST}:${GUARD_PORT}"; then
                # 上报成功就归零。面板换 IP 要几十秒到几分钟，这段时间继续
                # 探测会立刻又达到阈值、重复上报 —— 面板侧有冷却，但没必要
                # 把请求打过去。多等一个换 IP 的周期。
                fails=0
                log "等待面板换 IP 生效，暂停探测 120s"
                sleep 120
                last_heartbeat=$(date +%s)
                continue
            fi
        fi
    fi

    now=$(date +%s)
    if [ $((now - last_heartbeat)) -ge "$heartbeat_every" ]; then
        report alive "探测正常" || true
        last_heartbeat=$now
    fi

    sleep "$GUARD_INTERVAL"
done
'''


def render_script(req: GuardRequest) -> str:
    """渲染一键部署脚本。复制到实例上以 root 执行即可。"""
    cfg, host, port = _validate(req)
    guard = _guard_body()

    return f'''#!/usr/bin/env bash
#
# 被墙自愈探测器 —— 由 AWS 小助手面板生成
#
#   实例     : {cfg.instance_id}
#   探测目标 : {host}:{port}
#   探测间隔 : {cfg.interval_sec} 秒
#   触发条件 : 连续 {cfg.fail_threshold} 次连不上
#
# 干什么：从这台实例的视角连一个国内站点。连不上说明出网被拦，
#         上报面板换 IP。探测正常时不上报，只有低频心跳。
#
# 用法（在实例上以 root 执行）:
#   bash guard-deploy.sh
#
# 注意：本文件含上报凭证，等同于「让面板给这台实例换 IP」的权限。
#       部署完成后建议删除本文件。
#
set -euo pipefail

RED=$'\\033[31m'; GREEN=$'\\033[32m'; YELLOW=$'\\033[33m'; RESET=$'\\033[0m'
info() {{ printf '%s==>%s %s\\n' "$YELLOW" "$RESET" "$*"; }}
ok()   {{ printf '%s✓%s %s\\n' "$GREEN" "$RESET" "$*"; }}
err()  {{ printf '%s✗%s %s\\n' "$RED" "$RESET" "$*" >&2; }}

[ "$(id -u)" = "0" ] || {{ err "请用 root 执行（sudo bash $0）"; exit 1; }}

command -v curl >/dev/null 2>&1 || {{
    info "安装 curl"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq curl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q curl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q curl
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl bash
    else
        err "没有 curl 且无法自动安装，请手动装好再执行"
        exit 1
    fi
}}

info "写入探测脚本 {INSTALL_PATH}"
cat > {INSTALL_PATH} <<'GUARD_EOF'
{guard}GUARD_EOF
chmod 755 {INSTALL_PATH}

info "写入配置 {ENV_PATH}"
# 先建文件再收权限，避免凭证有一瞬间是全局可读的
touch {ENV_PATH}
chmod 600 {ENV_PATH}
cat > {ENV_PATH} <<EOF
GUARD_REPORT_URL={shlex.quote(cfg.report_url)}
GUARD_TOKEN={shlex.quote(cfg.token)}
GUARD_INSTANCE_ID={shlex.quote(cfg.instance_id)}
GUARD_HOST={shlex.quote(host)}
GUARD_PORT={port}
GUARD_INTERVAL={cfg.interval_sec}
GUARD_THRESHOLD={cfg.fail_threshold}
GUARD_TIMEOUT={cfg.timeout_sec}
GUARD_STATE_DIR={STATE_DIR}
EOF

install -d -m 700 {STATE_DIR}

info "写入 systemd 单元"
cat > /etc/systemd/system/{SERVICE_NAME}.service <<'UNIT'
[Unit]
Description=被墙自愈探测（由 aws-helper 面板生成）
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={INSTALL_PATH}
Restart=always
RestartSec=10
# 只读系统盘，仅状态目录可写
ProtectSystem=strict
ReadWritePaths={STATE_DIR}
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable {SERVICE_NAME}.service >/dev/null 2>&1 || true
systemctl restart {SERVICE_NAME}.service

info "等服务起稳"
sleep 3
if systemctl is-active --quiet {SERVICE_NAME}.service; then
    ok "服务运行中"
else
    err "服务没起来，日志如下："
    journalctl -u {SERVICE_NAME}.service -n 30 --no-pager || true
    exit 1
fi

info "验证能连上面板"
sleep 2
if grep -q '"ok"' {STATE_DIR}/last-report.json 2>/dev/null; then
    ok "面板已收到上报"
else
    err "还没收到面板的成功响应，可能是上报地址不通或凭证不对"
    err "看日志： journalctl -u {SERVICE_NAME} -n 30"
    [ -s {STATE_DIR}/report-error.log ] && sed 's/^/    /' {STATE_DIR}/report-error.log >&2
fi

echo
echo "----------------------------------------------------------------------"
ok "部署完成"
echo "  实例      : {cfg.instance_id}"
echo "  探测目标  : {host}:{port}"
echo "  探测间隔  : {cfg.interval_sec} 秒"
echo "  触发条件  : 连续 {cfg.fail_threshold} 次失败"
echo "  探测脚本  : {INSTALL_PATH}"
echo "  配置文件  : {ENV_PATH}（权限 600，含上报凭证）"
echo
echo "  常用命令:"
echo "    systemctl status {SERVICE_NAME}       # 看运行状态"
echo "    journalctl -u {SERVICE_NAME} -f       # 实时看探测日志"
echo "    systemctl restart {SERVICE_NAME}      # 改完配置重启"
echo
echo "  卸载:"
echo "    systemctl disable --now {SERVICE_NAME}"
echo "    rm -f /etc/systemd/system/{SERVICE_NAME}.service {INSTALL_PATH} {ENV_PATH}"
echo "    systemctl daemon-reload"
echo "----------------------------------------------------------------------"
'''
