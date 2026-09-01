"""生成可直接在目标机器上跑的 DDNS 一键部署脚本。

面板这边填好供应商、区域、主机名、Token，生成一段自包含的 bash，
复制到任意机器执行即可 —— 目标机器不需要 Python、不需要连这个面板、
也不需要数据库。

刻意用 bash + curl 而不是 Python：这脚本要能丢到任何一台机器上跑，
包括只有 busybox 的精简系统。curl 几乎一定有，Python 未必。
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

# 安装路径。跟 aws-helper 自己的部署分开，两者互不影响。
INSTALL_PATH = "/usr/local/bin/ddns-update"
ENV_PATH = "/etc/ddns-update.env"
SERVICE_NAME = "ddns-update"
STATE_DIR = "/var/lib/ddns-update"

_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")
# Cloudflare 的 Token 是 40 字符的 base62；不强行卡长度，只挡住明显的误粘贴
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{20,200}$")


class ScriptError(ValueError):
    """生成脚本的参数不合法。"""


@dataclass
class ScriptRequest:
    provider: str = "cloudflare"
    zone: str = ""
    hostname: str = ""
    token: str = ""
    want_ipv4: bool = True
    want_ipv6: bool = False
    proxied: bool = False
    ttl: int = 1
    interval_sec: int = 300
    schedule: str = "systemd"


def _validate(req: ScriptRequest) -> ScriptRequest:
    if req.provider != "cloudflare":
        raise ScriptError(f"暂不支持的 DNS 供应商: {req.provider}")

    zone = req.zone.strip().lower().rstrip(".")
    hostname = req.hostname.strip().lower().rstrip(".")
    token = req.token.strip()

    if not zone:
        raise ScriptError("请填写区域根域名")
    if not hostname:
        raise ScriptError("请填写完整主机名")
    if not _HOSTNAME_RE.match(zone):
        raise ScriptError(f"区域根域名格式不对: {zone}")
    if not _HOSTNAME_RE.match(hostname):
        raise ScriptError(f"主机名格式不对: {hostname}")
    if hostname != zone and not hostname.endswith("." + zone):
        raise ScriptError(f"主机名 {hostname} 不属于区域 {zone}")
    if not token:
        raise ScriptError("请填写 API Token")
    if not _TOKEN_RE.match(token):
        raise ScriptError("API Token 含非法字符或长度异常，确认粘贴完整且没带空格")
    if not (req.want_ipv4 or req.want_ipv6):
        raise ScriptError("至少要开启 IPv4 或 IPv6 之一")
    if req.schedule not in ("systemd", "cron"):
        raise ScriptError(f"未知的运行方式: {req.schedule}")

    interval = max(60, min(int(req.interval_sec), 86400))
    ttl = 1 if req.proxied else max(1, min(int(req.ttl), 86400))

    return ScriptRequest(
        provider=req.provider,
        zone=zone,
        hostname=hostname,
        token=token,
        want_ipv4=bool(req.want_ipv4),
        want_ipv6=bool(req.want_ipv6),
        proxied=bool(req.proxied),
        ttl=ttl,
        interval_sec=interval,
        schedule=req.schedule,
    )


def _updater_body() -> str:
    """真正干活的更新脚本，装到目标机器上由 systemd/cron 反复执行。"""
    return r'''#!/usr/bin/env bash
# DDNS 更新器 —— 由 aws-helper 面板生成，可独立运行
set -euo pipefail

CONF="${DDNS_ENV_FILE:-/etc/ddns-update.env}"
[ -r "$CONF" ] || { echo "读不到配置 $CONF" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"

: "${CF_TOKEN:?配置缺少 CF_TOKEN}"
: "${DDNS_ZONE:?配置缺少 DDNS_ZONE}"
: "${DDNS_HOSTNAME:?配置缺少 DDNS_HOSTNAME}"
CF_API="${CF_API:-https://api.cloudflare.com/client/v4}"
DDNS_TTL="${DDNS_TTL:-1}"
DDNS_PROXIED="${DDNS_PROXIED:-false}"
STATE_DIR="${DDNS_STATE_DIR:-/var/lib/ddns-update}"
mkdir -p "$STATE_DIR"

# 写 stderr：zone_id 之类的函数是在 $(...) 里调用的，日志写 stdout 会被
# 命令替换吞掉当成返回值，用户什么都看不到。
log() { printf '%s %s\n' "$(date '+%F %T')" "$*" >&2; }

# 提取 JSON 字段。装 jq 就用 jq，没有就退回 grep —— 不为一个 DDNS 脚本
# 强制用户装依赖。
json_get() {
    local key="$1" body="$2"
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$body" | jq -r "$key // empty" 2>/dev/null || true
    else
        # 只用于取 result[0].id / result[0].content 这类简单标量
        local name="${key##*.}"
        printf '%s' "$body" \
            | grep -o "\"${name}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
            | head -1 | sed 's/.*:[[:space:]]*"//; s/"$//'
    fi
}

cf_ok() {
    local body="$1"
    printf '%s' "$body" | grep -q '"success"[[:space:]]*:[[:space:]]*true'
}

cf_error() {
    local body="$1" msg
    msg=$(printf '%s' "$body" \
        | grep -o '"message"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | head -2 | sed 's/.*:[[:space:]]*"//; s/"$//' | paste -sd'；' -)
    printf '%s' "${msg:-未知错误}"
}

cf_call() {
    local method="$1" path="$2" data="${3:-}"
    local args=(-sS -X "$method" -H "Authorization: Bearer ${CF_TOKEN}"
                -H "Content-Type: application/json" --max-time 20)
    [ -n "$data" ] && args+=(-d "$data")
    curl "${args[@]}" "${CF_API}${path}"
}

# 取本机公网 IP。v4/v6 用各自的探测点 —— api.ipify.org 只有 A 记录，
# 强制走 v6 会连不上，那不是"没有 v6"而是探测点不支持。
detect_ip() {
    local ver="$1" flag src ip
    if [ "$ver" = "4" ]; then
        flag="-4"
        set -- "https://one.one.one.one/cdn-cgi/trace" "https://api.ipify.org" "https://ipv4.icanhazip.com"
    else
        flag="-6"
        set -- "https://one.one.one.one/cdn-cgi/trace" "https://api6.ipify.org" "https://ipv6.icanhazip.com"
    fi
    for src in "$@"; do
        ip=$(curl -sS $flag --max-time 10 "$src" 2>/dev/null || true)
        case "$src" in
            *cdn-cgi/trace) ip=$(printf '%s' "$ip" | sed -n 's/^ip=//p') ;;
        esac
        ip=$(printf '%s' "$ip" | tr -d '[:space:]')
        [ -z "$ip" ] && continue
        # 校验版本对得上：探测点偶尔会回错误页或另一个协议族的地址
        if [ "$ver" = "4" ]; then
            printf '%s' "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && { printf '%s' "$ip"; return 0; }
        else
            printf '%s' "$ip" | grep -q ':' && { printf '%s' "$ip"; return 0; }
        fi
    done
    return 1
}

ZONE_CACHE="$STATE_DIR/zone_id"
zone_id() {
    if [ -s "$ZONE_CACHE" ]; then cat "$ZONE_CACHE"; return 0; fi
    local body zid
    body=$(cf_call GET "/zones?name=${DDNS_ZONE}")
    cf_ok "$body" || { log "查询区域失败: $(cf_error "$body")"; return 1; }
    zid=$(json_get '.result[0].id' "$body")
    if [ -z "$zid" ]; then
        # 单区域 Token 查不到别的区域时返回空数组而不是 403
        log "找不到区域 ${DDNS_ZONE} —— 确认域名已托管，且 Token 权限范围覆盖它"
        return 1
    fi
    printf '%s' "$zid" > "$ZONE_CACHE"
    printf '%s' "$zid"
}

sync_one() {
    local rtype="$1" ip="$2" body rec_id cur
    body=$(cf_call GET "/zones/${ZID}/dns_records?type=${rtype}&name.exact=${DDNS_HOSTNAME}")
    cf_ok "$body" || { log "${rtype} 查询失败: $(cf_error "$body")"; return 1; }

    rec_id=$(json_get '.result[0].id' "$body")
    cur=$(json_get '.result[0].content' "$body")

    if [ -z "$rec_id" ]; then
        local ttl="$DDNS_TTL"
        [ "$DDNS_PROXIED" = "true" ] && ttl=1
        body=$(cf_call POST "/zones/${ZID}/dns_records" \
            "{\"type\":\"${rtype}\",\"name\":\"${DDNS_HOSTNAME}\",\"content\":\"${ip}\",\"ttl\":${ttl},\"proxied\":${DDNS_PROXIED}}")
        cf_ok "$body" || { log "${rtype} 新建失败: $(cf_error "$body")"; return 1; }
        log "${rtype} 已新建 -> ${ip}"
        return 0
    fi

    # IP 没变就什么都不做。照发一次也能跑（PATCH 幂等），但 Cloudflare 的
    # 限流额度是账号级共享的（1200 次/5 分钟），白烧没意义。
    if [ "$cur" = "$ip" ]; then
        log "${rtype} 未变化（${ip}）"
        return 0
    fi

    # 用 PATCH 不用 PUT：PUT 是整条替换，漏传 proxied/ttl 会被重置成默认值，
    # 控制台里开的橙云会被静默关掉、自定义 TTL 也会丢。
    body=$(cf_call PATCH "/zones/${ZID}/dns_records/${rec_id}" "{\"content\":\"${ip}\"}")
    cf_ok "$body" || { log "${rtype} 更新失败: $(cf_error "$body")"; return 1; }
    log "${rtype} ${cur} -> ${ip}"
}

# 区域只解析一次。放在循环里的话，Token 配错时 A 和 AAAA 会各报一遍同样的错。
ZID=$(zone_id) || exit 1

rc=0
if [ "${DDNS_WANT_IPV4:-true}" = "true" ]; then
    if ip4=$(detect_ip 4); then
        sync_one A "$ip4" || rc=1
    else
        log "取不到 IPv4 地址"
        rc=1
    fi
fi

if [ "${DDNS_WANT_IPV6:-false}" = "true" ]; then
    if ip6=$(detect_ip 6); then
        sync_one AAAA "$ip6" || rc=1
    else
        # 机器没有 v6 连通性是常态，不当失败 —— 否则会连带影响退出码，
        # systemd 会当成服务失败反复重启。
        log "没有 IPv6 连通性，跳过 AAAA"
    fi
fi

exit $rc
'''


def render_script(req: ScriptRequest) -> str:
    """渲染一键部署脚本。复制到目标机器上执行即可。"""
    cfg = _validate(req)

    bool_str = lambda v: "true" if v else "false"  # noqa: E731
    updater = _updater_body()
    quoted_token = shlex.quote(cfg.token)

    if cfg.schedule == "systemd":
        schedule_block = f'''
info "写入 systemd 单元与定时器"
cat > /etc/systemd/system/{SERVICE_NAME}.service <<'UNIT'
[Unit]
Description=DDNS 更新（由 aws-helper 面板生成）
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={INSTALL_PATH}
# 只读系统盘，仅状态目录可写
ProtectSystem=strict
ReadWritePaths={STATE_DIR}
NoNewPrivileges=true
PrivateTmp=true
UNIT

cat > /etc/systemd/system/{SERVICE_NAME}.timer <<'TIMER'
[Unit]
Description=定期跑 DDNS 更新

[Timer]
# 开机 1 分钟后跑第一次，之后每隔 {cfg.interval_sec} 秒
OnBootSec=1min
OnUnitActiveSec={cfg.interval_sec}s
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now {SERVICE_NAME}.timer

info "立刻跑一次"
if systemctl start {SERVICE_NAME}.service; then
    ok "首次同步完成"
else
    err "首次同步失败，日志如下："
    journalctl -u {SERVICE_NAME}.service -n 30 --no-pager || true
    exit 1
fi

echo
echo "----------------------------------------------------------------------"
ok "部署完成（systemd timer）"
echo "  主机名    : {cfg.hostname}"
echo "  记录类型  : {'A' if cfg.want_ipv4 else ''}{' + ' if cfg.want_ipv4 and cfg.want_ipv6 else ''}{'AAAA' if cfg.want_ipv6 else ''}"
echo "  检查间隔  : {cfg.interval_sec} 秒"
echo "  更新脚本  : {INSTALL_PATH}"
echo "  配置文件  : {ENV_PATH}（权限 600，含 API Token）"
echo
echo "  常用命令:"
echo "    systemctl list-timers {SERVICE_NAME}.timer   # 看下次执行时间"
echo "    systemctl start {SERVICE_NAME}               # 立刻同步一次"
echo "    journalctl -u {SERVICE_NAME} -n 50           # 看日志"
echo "    {INSTALL_PATH}                               # 手动跑，直接看输出"
echo
echo "  卸载:"
echo "    systemctl disable --now {SERVICE_NAME}.timer"
echo "    rm -f /etc/systemd/system/{SERVICE_NAME}.{{service,timer}} {INSTALL_PATH} {ENV_PATH}"
echo "    systemctl daemon-reload"
echo "----------------------------------------------------------------------"
'''
    else:
        schedule_block = f'''
info "写入 cron 任务"
CRON_LINE="*/{max(1, cfg.interval_sec // 60)} * * * * {INSTALL_PATH} >> /var/log/{SERVICE_NAME}.log 2>&1"
# 先删掉自己之前写的那行再加，避免重复执行脚本时越堆越多
( crontab -l 2>/dev/null | grep -vF "{INSTALL_PATH}" ; echo "$CRON_LINE" ) | crontab -

info "立刻跑一次"
if {INSTALL_PATH}; then
    ok "首次同步完成"
else
    err "首次同步失败，检查上面的输出"
    exit 1
fi

echo
echo "----------------------------------------------------------------------"
ok "部署完成（cron）"
echo "  主机名    : {cfg.hostname}"
echo "  检查间隔  : 每 {max(1, cfg.interval_sec // 60)} 分钟"
echo "  更新脚本  : {INSTALL_PATH}"
echo "  配置文件  : {ENV_PATH}（权限 600，含 API Token）"
echo "  日志      : /var/log/{SERVICE_NAME}.log"
echo
echo "  卸载:"
echo "    crontab -l | grep -vF {INSTALL_PATH} | crontab -"
echo "    rm -f {INSTALL_PATH} {ENV_PATH}"
echo "----------------------------------------------------------------------"
'''

    return f'''#!/usr/bin/env bash
#
# DDNS 一键部署 —— 由 AWS 小助手面板生成
#
#   供应商 : Cloudflare
#   区域   : {cfg.zone}
#   主机名 : {cfg.hostname}
#
# 用法（在目标机器上以 root 执行）:
#   bash ddns-deploy.sh
#
# 注意：本文件含 Cloudflare API Token，等同于该区域 DNS 的修改权限。
#       部署完成后建议删除本文件，并清理 shell 历史。
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
        apk add --no-cache curl
    else
        err "没有 curl 且无法自动安装，请手动装好再执行"
        exit 1
    fi
}}

info "写入更新脚本 {INSTALL_PATH}"
cat > {INSTALL_PATH} <<'DDNS_UPDATER_EOF'
{updater}DDNS_UPDATER_EOF
chmod 755 {INSTALL_PATH}

info "写入配置 {ENV_PATH}"
# 先建文件再收权限，避免 Token 有一瞬间是全局可读的
touch {ENV_PATH}
chmod 600 {ENV_PATH}
cat > {ENV_PATH} <<EOF
CF_TOKEN={quoted_token}
DDNS_ZONE={cfg.zone}
DDNS_HOSTNAME={cfg.hostname}
DDNS_WANT_IPV4={bool_str(cfg.want_ipv4)}
DDNS_WANT_IPV6={bool_str(cfg.want_ipv6)}
DDNS_PROXIED={bool_str(cfg.proxied)}
DDNS_TTL={cfg.ttl}
DDNS_STATE_DIR={STATE_DIR}
EOF

install -d -m 700 {STATE_DIR}

info "校验 Token 与区域"
if ! {INSTALL_PATH} >/tmp/ddns-first-run.log 2>&1; then
    err "校验失败："
    sed 's/^/    /' /tmp/ddns-first-run.log >&2
    err "常见原因：Token 无效、权限不是 Zone→DNS→Edit、区域范围没覆盖 {cfg.zone}"
    exit 1
fi
sed 's/^/    /' /tmp/ddns-first-run.log
rm -f /tmp/ddns-first-run.log
{schedule_block}'''
