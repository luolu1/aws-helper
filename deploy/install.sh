#!/usr/bin/env bash
#
# AWS 小助手 一键部署脚本
#
#   systemd 模式（Python 虚拟环境，隔离依赖）：
#       sudo bash deploy/install.sh --mode systemd
#
#   Docker Compose 模式：
#       sudo bash deploy/install.sh --mode docker
#
#   不带 --mode 时进入交互选择。装完用 aws-helper 命令管理。
#
set -euo pipefail

APP_NAME="aws-helper"
SERVICE_NAME="aws-helper"
INSTALL_DIR="/opt/aws-helper"
DATA_DIR="/var/lib/aws-helper"
CONFIG_DIR="/etc/aws-helper"
ENV_FILE="$CONFIG_DIR/aws-helper.env"
SERVICE_USER="awshelper"
MANAGE_BIN="/usr/local/bin/aws-helper"

MODE=""
BIND_HOST="127.0.0.1"
PORT="8765"
PASSWORD=""
ASSUME_YES="no"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'; C_BLUE=$'\033[36m'

info()  { printf '%s==>%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()    { printf '%s  ok%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s警告%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()   { printf '%s错误%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

usage() {
    cat <<EOF
AWS 小助手 部署脚本

用法: sudo bash deploy/install.sh [选项]

选项:
  --mode systemd|docker   部署方式，省略则交互询问
  --host ADDR             监听地址，默认 127.0.0.1
                          填 0.0.0.0 会对外暴露，务必配 HTTPS 反代
  --port PORT             监听端口，默认 8765
  --password PASS         指定初始密码，省略则自动生成强密码
  --yes                   非交互，全部用默认值
  -h, --help              显示本帮助

部署方式区别:
  systemd  在 $INSTALL_DIR/venv 建独立虚拟环境，不污染系统 Python，
           以 $SERVICE_USER 用户运行，开机自启
  docker   构建镜像用 docker compose 运行，数据存命名卷
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --mode)     MODE="${2:-}"; shift 2 ;;
            --mode=*)   MODE="${1#*=}"; shift ;;
            --host)     BIND_HOST="${2:-}"; shift 2 ;;
            --host=*)   BIND_HOST="${1#*=}"; shift ;;
            --port)     PORT="${2:-}"; shift 2 ;;
            --port=*)   PORT="${1#*=}"; shift ;;
            --password) PASSWORD="${2:-}"; shift 2 ;;
            --password=*) PASSWORD="${1#*=}"; shift ;;
            --yes|-y)   ASSUME_YES="yes"; shift ;;
            -h|--help)  usage; exit 0 ;;
            *)          die "未知参数: $1（--help 查看用法）" ;;
        esac
    done

    case "$MODE" in
        ""|systemd|docker) ;;
        *) die "--mode 只能是 systemd 或 docker" ;;
    esac
    [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
        || die "端口不合法: $PORT"
}

require_root() {
    [ "$(id -u)" = "0" ] || die "需要 root 权限，请用 sudo 运行"
}

detect_pkg_manager() {
    for candidate in apt-get dnf yum apk zypper; do
        if command -v "$candidate" >/dev/null 2>&1; then
            echo "$candidate"
            return
        fi
    done
    echo ""
}

install_packages() {
    local pkgs=("$@")
    [ ${#pkgs[@]} -eq 0 ] && return 0
    local pm
    pm="$(detect_pkg_manager)"
    case "$pm" in
        apt-get)
            DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}"
            ;;
        dnf) dnf install -y -q "${pkgs[@]}" ;;
        yum) yum install -y -q "${pkgs[@]}" ;;
        apk) apk add --no-cache "${pkgs[@]}" ;;
        zypper) zypper --non-interactive install "${pkgs[@]}" ;;
        *) die "无法识别包管理器，请手动安装: ${pkgs[*]}" ;;
    esac
}

choose_mode() {
    [ -n "$MODE" ] && return 0
    if [ "$ASSUME_YES" = "yes" ]; then
        MODE="systemd"
        return 0
    fi
    if [ ! -t 0 ]; then
        die "非交互环境请用 --mode systemd 或 --mode docker 指定部署方式"
    fi

    echo
    echo "${C_BOLD}选择部署方式${C_RESET}"
    echo "  1) systemd + Python 虚拟环境（推荐，依赖隔离，开机自启）"
    echo "  2) Docker Compose（镜像隔离，数据存命名卷）"
    echo
    local choice
    while true; do
        read -r -p "请输入 1 或 2 [1]: " choice
        choice="${choice:-1}"
        case "$choice" in
            1) MODE="systemd"; break ;;
            2) MODE="docker"; break ;;
            *) echo "只能输入 1 或 2" ;;
        esac
    done
}

ask_host_port() {
    [ "$ASSUME_YES" = "yes" ] && return 0
    [ -t 0 ] || return 0

    local answer
    read -r -p "监听地址 [$BIND_HOST]: " answer
    BIND_HOST="${answer:-$BIND_HOST}"
    read -r -p "监听端口 [$PORT]: " answer
    PORT="${answer:-$PORT}"
    [[ "$PORT" =~ ^[0-9]+$ ]] || die "端口不合法: $PORT"

    if [ "$BIND_HOST" != "127.0.0.1" ] && [ "$BIND_HOST" != "localhost" ]; then
        warn "监听 $BIND_HOST 会把面板暴露到网络上。"
        warn "面板持有你的 AWS 凭据，请务必放到 HTTPS 反代之后。"
        read -r -p "确认继续？[y/N]: " answer
        case "${answer,,}" in
            y|yes) ;;
            *) die "已取消" ;;
        esac
    fi
}

port_in_use() {
    if command -v ss >/dev/null 2>&1; then
        ss -tln 2>/dev/null | grep -qE "[:.]${PORT}[[:space:]]"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tln 2>/dev/null | grep -qE "[:.]${PORT}[[:space:]]"
    else
        return 1
    fi
}

port_holder() {
    if command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -E "[:.]${PORT}[[:space:]]" | head -1
    fi
}

port_listener_pid() {
    port_holder | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2
}

# 监听进程属于本次部署（同一个 systemd 服务，或本程序的容器）吗
is_our_process() {
    local pid="$1"
    [ -n "$pid" ] || return 1

    if [ "$MODE" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
        local main_pid
        main_pid="$(systemctl show -p MainPID --value "${SERVICE_NAME}.service" 2>/dev/null)"
        [ -n "$main_pid" ] && [ "$main_pid" != "0" ] && [ "$main_pid" = "$pid" ] && return 0
        # cgroup 里带服务名说明是该 unit 的子进程
        grep -qs "${SERVICE_NAME}.service" "/proc/$pid/cgroup" && return 0
        return 1
    fi

    if [ "$MODE" = "docker" ]; then
        grep -qsE 'docker|containerd' "/proc/$pid/cgroup" && return 0
        docker ps --filter "name=^${APP_NAME}$" --format '{{.Names}}' 2>/dev/null \
            | grep -q . && return 0
        return 1
    fi
    return 1
}

# 端口被别的进程占着时必须拦住安装：服务会起不来并反复重启，
# 而摘要却打印"部署完成 + 初始密码"，用户拿着能用的密码却登不进去。
ensure_port_available() {
    port_in_use || return 0

    # 判定"是不是本程序占的"要看监听进程本身，不能只看服务是否存在：
    # 服务可能正因端口被别人占用而反复重启，那时它并没有真的持有端口。
    local holder_pid
    holder_pid="$(port_listener_pid)"
    if [ -n "$holder_pid" ] && is_our_process "$holder_pid"; then
        if [ "$MODE" = "docker" ]; then
            info "端口 $PORT 由本程序容器占用，重装时会自动重建"
        else
            info "端口 $PORT 由本程序自身占用，重装时会自动重启"
        fi
        return 0
    fi

    warn "端口 $PORT 已被其他进程占用："
    warn "  $(port_holder)"
    die "请换端口（--port 其他端口）或先停掉占用进程后重试"
}

gen_secret() {
    # 优先用 python，缺失时退回 openssl / urandom
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import secrets;print(secrets.token_hex(32))'
    elif command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

# 库里已经有密码时，安装脚本不应再宣称"初始密码是 X"
db_has_password() {
    local db="$1"
    [ -f "$db" ] || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    python3 - "$db" <<'PY' 2>/dev/null
import sqlite3, sys
try:
    conn = sqlite3.connect(sys.argv[1])
    row = conn.execute(
        "SELECT 1 FROM settings WHERE key='admin_password_hash' AND value<>''"
    ).fetchone()
    sys.exit(0 if row else 1)
except Exception:
    sys.exit(1)
PY
}

gen_password() {
    if command -v python3 >/dev/null 2>&1 \
        && python3 -c "import sys; sys.path.insert(0, '$SOURCE_DIR'); import aws_helper.auth" 2>/dev/null; then
        python3 -c "
import sys
sys.path.insert(0, '$SOURCE_DIR')
from aws_helper.auth import generate_password
print(generate_password())
"
    else
        # 保证包含大小写、数字、符号，满足面板的强度要求
        local body
        body="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 14)"
        printf '%sA9!\n' "$body"
    fi
}

write_env_file() {
    local session_key="$1" password="$2"
    mkdir -p "$CONFIG_DIR"
    if [ -f "$ENV_FILE" ]; then
        info "配置已存在，保留原有密码和会话密钥：$ENV_FILE"
        # 端口和监听地址允许更新，密钥类不动
        sed -i "s|^AWS_HELPER_HOST=.*|AWS_HELPER_HOST=$BIND_HOST|" "$ENV_FILE"
        sed -i "s|^AWS_HELPER_PORT=.*|AWS_HELPER_PORT=$PORT|" "$ENV_FILE"
        return 0
    fi

    cat > "$ENV_FILE" <<EOF
# AWS 小助手 运行配置（由 install.sh 生成）
#
# AWS_HELPER_PASSWORD 仅作为首次启动的初始密码，
# 密码写入数据库后此项不再生效 —— 改密码请用面板或
#   aws-helper reset-password

AWS_HELPER_HOST=$BIND_HOST
AWS_HELPER_PORT=$PORT
AWS_HELPER_DATA=$DATA_DIR
AWS_HELPER_PASSWORD=$password
AWS_HELPER_SESSION_KEY=$session_key
AWS_HELPER_SESSION_TTL=86400
EOF
    chmod 600 "$ENV_FILE"
    ok "已写入配置 $ENV_FILE（权限 600）"
}

sync_source() {
    info "复制程序文件到 $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete \
            --exclude '__pycache__' --exclude '*.pyc' \
            --exclude '.git' --exclude 'venv' \
            "$SOURCE_DIR/aws_helper" "$INSTALL_DIR/"
    else
        rm -rf "$INSTALL_DIR/aws_helper"
        cp -r "$SOURCE_DIR/aws_helper" "$INSTALL_DIR/"
        find "$INSTALL_DIR/aws_helper" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
    fi
    cp "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"
    ok "程序文件就位"
}

# ---------------------------------------------------------------- systemd

install_systemd() {
    command -v systemctl >/dev/null 2>&1 || die "系统里没有 systemd，请改用 --mode docker"

    info "检查系统依赖"
    local need=()
    command -v python3 >/dev/null 2>&1 || need+=(python3)
    python3 -c 'import venv' 2>/dev/null || need+=(python3-venv)
    python3 -c 'import ensurepip' 2>/dev/null || need+=(python3-venv)
    if [ ${#need[@]} -gt 0 ]; then
        info "安装缺失依赖: ${need[*]}"
        install_packages "${need[@]}"
    fi
    python3 -c 'import venv, ensurepip' 2>/dev/null \
        || die "python3 venv 模块不可用，请手动安装 python3-venv 后重试"

    local py_version
    py_version="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
    ok "Python $py_version"
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
        || die "需要 Python 3.10 或更高版本，当前 $py_version"

    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        info "创建系统用户 $SERVICE_USER"
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
            || useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
    fi
    ok "服务用户 $SERVICE_USER"

    sync_source

    info "创建 Python 虚拟环境（隔离依赖，不动系统 Python）"
    if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
        python3 -m venv "$INSTALL_DIR/venv"
    fi
    "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip setuptools wheel
    ok "虚拟环境 $INSTALL_DIR/venv"

    info "安装 Python 依赖（较慢，请稍候）"
    "$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
    "$INSTALL_DIR/venv/bin/python" -c "
import sys
sys.path.insert(0, '$INSTALL_DIR')
import aws_helper.web.app  # noqa
print('导入自检通过')
" >/dev/null || die "依赖装好但程序导入失败，请检查上面的错误"
    ok "依赖安装完成"

    mkdir -p "$DATA_DIR"
    chown -R "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    ok "数据目录 $DATA_DIR"

    local password session_key
    if db_has_password "$DATA_DIR/aws-helper.db"; then
        # 已有密码时不能再打印新生成的值 —— 它不会生效，只会误导用户
        password=""
        info "检测到已有数据，沿用原密码（忘记了用 aws-helper reset-password）"
    else
        password="${PASSWORD:-$(gen_password)}"
    fi
    session_key="$(gen_secret)"
    write_env_file "$session_key" "${password:-$(gen_password)}"
    chown root:"$SERVICE_USER" "$ENV_FILE"
    chmod 640 "$ENV_FILE"

    info "写入 systemd 单元"
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=AWS 小助手 — 一键开机 / 换 IP / 开机脚本
Documentation=file://$INSTALL_DIR/aws_helper/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
Environment=PYTHONPATH=$INSTALL_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$INSTALL_DIR/venv/bin/python -m uvicorn aws_helper.web.app:app \\
    --host \${AWS_HELPER_HOST} --port \${AWS_HELPER_PORT}
Restart=on-failure
RestartSec=5

# 收紧权限：只允许写数据目录
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    systemctl restart "${SERVICE_NAME}.service"
    ok "服务已启动并设为开机自启"

    install_manage_script "systemd"
    wait_healthy "$password"
}

# ---------------------------------------------------------------- docker

# 只认真正能跟 docker 守护进程通话的 compose。
# 光看命令存在不够 —— 例如 docker-compose 1.29 在新版 requests 下会抛
# "Not supported URL scheme http+docker" 而完全不可用。
compose_works() {
    timeout 25 "$@" version >/dev/null 2>&1 || return 1
    timeout 25 "$@" ls >/dev/null 2>&1 && return 0
    # v1 没有 ls 子命令，用 config 在一个临时空项目上验证守护进程连通性
    local probe
    probe="$(mktemp -d)"
    printf 'services:\n  probe:\n    image: hello-world\n' > "$probe/docker-compose.yml"
    local rc=0
    ( cd "$probe" && timeout 25 "$@" ps >/dev/null 2>&1 ) || rc=1
    rm -rf "$probe"
    return $rc
}

compose_cmd() {
    if compose_works docker compose; then
        echo "docker compose"
        return
    fi
    if command -v docker-compose >/dev/null 2>&1 && compose_works docker-compose; then
        echo "docker-compose"
        return
    fi
    echo ""
}

# 官方 compose v2 是单文件二进制，直接放到 cli-plugins 目录即可。
install_compose_plugin() {
    local arch plugin_dir url
    case "$(uname -m)" in
        x86_64|amd64)  arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        armv7l)        arch="armv7" ;;
        *) warn "未知架构 $(uname -m)，无法自动安装 compose 插件"; return 1 ;;
    esac

    plugin_dir="/usr/local/lib/docker/cli-plugins"
    mkdir -p "$plugin_dir"
    url="https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${arch}"

    info "下载 docker compose v2 插件（$arch）"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$plugin_dir/docker-compose" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$plugin_dir/docker-compose" || return 1
    else
        warn "缺少 curl/wget，无法下载 compose 插件"
        return 1
    fi
    chmod +x "$plugin_dir/docker-compose"

    if compose_works docker compose; then
        ok "compose v2 插件安装成功"
        return 0
    fi
    warn "compose 插件安装后仍不可用"
    return 1
}

install_docker() {
    command -v docker >/dev/null 2>&1 \
        || die "未检测到 docker，请先安装：https://docs.docker.com/engine/install/"
    docker info >/dev/null 2>&1 \
        || die "docker 守护进程不可用，请先 systemctl start docker"

    info "检查 docker compose 可用性"
    local compose
    compose="$(compose_cmd)"
    if [ -z "$compose" ]; then
        warn "没有可用的 docker compose（命令缺失或无法连接守护进程）"
        install_compose_plugin || true
        compose="$(compose_cmd)"
    fi
    [ -n "$compose" ] || die "docker compose 不可用。请参考 https://docs.docker.com/compose/install/ 手动安装后重试"
    ok "使用 $compose"

    info "复制部署文件到 $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    sync_source
    cp "$SOURCE_DIR/Dockerfile" "$INSTALL_DIR/Dockerfile"
    cp "$SOURCE_DIR/docker-compose.yml" "$INSTALL_DIR/docker-compose.yml"
    [ -f "$SOURCE_DIR/.dockerignore" ] && cp "$SOURCE_DIR/.dockerignore" "$INSTALL_DIR/.dockerignore"

    local password session_key
    session_key="$(gen_secret)"
    if docker volume inspect aws-helper-data >/dev/null 2>&1; then
        password=""
        info "检测到已有数据卷，沿用原密码（忘记了用 aws-helper reset-password）"
    else
        password="${PASSWORD:-$(gen_password)}"
    fi

    # compose 读取同目录 .env；密钥类不覆盖已有值
    if [ -f "$INSTALL_DIR/.env" ]; then
        info "保留已有 $INSTALL_DIR/.env 中的密码与会话密钥"
        sed -i "s|^AWS_HELPER_BIND=.*|AWS_HELPER_BIND=$BIND_HOST|" "$INSTALL_DIR/.env"
        sed -i "s|^AWS_HELPER_PORT=.*|AWS_HELPER_PORT=$PORT|" "$INSTALL_DIR/.env"
    else
        # 卷已存在但 .env 丢了：env 里的值不会生效，随便填个占位即可
        local env_password="${password:-$(gen_password)}"
        cat > "$INSTALL_DIR/.env" <<EOF
# AWS 小助手 Docker 部署配置（由 install.sh 生成）
AWS_HELPER_BIND=$BIND_HOST
AWS_HELPER_PORT=$PORT
AWS_HELPER_PASSWORD=$env_password
AWS_HELPER_SESSION_KEY=$session_key
AWS_HELPER_SESSION_TTL=86400
EOF
        chmod 600 "$INSTALL_DIR/.env"
        ok "已写入 $INSTALL_DIR/.env（权限 600）"
    fi

    info "构建镜像（首次较慢）"
    ( cd "$INSTALL_DIR" && $compose build )
    ok "镜像构建完成"

    info "启动容器"
    ( cd "$INSTALL_DIR" && $compose up -d )
    ok "容器已启动"

    install_manage_script "docker" "$compose"
    wait_healthy "$password"
}

# ---------------------------------------------------------------- 管理命令

install_manage_script() {
    local mode="$1"
    local COMPOSE_BIN="${2:-}"
    # 每种部署方式都有专属命令，两种方式并存时互不覆盖；
    # aws-helper 指向最近一次安装的那套。
    local target="${MANAGE_BIN}-${mode}"

    cat > "$target" <<EOF
#!/usr/bin/env bash
# AWS 小助手 管理命令（由 install.sh 生成，部署方式: $mode）
set -euo pipefail

MODE="$mode"
INSTALL_DIR="$INSTALL_DIR"
DATA_DIR="$DATA_DIR"
CONFIG_DIR="$CONFIG_DIR"
ENV_FILE="$ENV_FILE"
SERVICE_NAME="$SERVICE_NAME"
SERVICE_USER="$SERVICE_USER"
COMPOSE_BIN="${COMPOSE_BIN:-docker compose}"
EOF

    cat >> "$target" <<'EOF'

compose() {
    ( cd "$INSTALL_DIR" && $COMPOSE_BIN "$@" )
}

usage() {
    cat <<USAGE
AWS 小助手 管理命令（部署方式: $MODE）

  aws-helper start              启动
  aws-helper stop               停止
  aws-helper restart            重启
  aws-helper status             查看运行状态
  aws-helper logs [-f]          查看日志
  aws-helper reset-password     重置登录密码（忘记密码时用）
  aws-helper info               查看密码/会话/登录记录
  aws-helper logout-all         下线所有登录会话
  aws-helper update             更新程序并重启
  aws-helper uninstall          卸载（会询问是否删除数据）
USAGE
}

app_cli() {
    if [ "$MODE" = "docker" ]; then
        compose exec -T aws-helper python -m aws_helper.cli "$@"
    else
        sudo -u "$SERVICE_USER" \
            env AWS_HELPER_DATA="$DATA_DIR" PYTHONPATH="$INSTALL_DIR" \
            "$INSTALL_DIR/venv/bin/python" -m aws_helper.cli "$@"
    fi
}

case "${1:-}" in
    start)
        if [ "$MODE" = "docker" ]; then compose up -d; else systemctl start "$SERVICE_NAME"; fi
        echo "已启动"
        ;;
    stop)
        if [ "$MODE" = "docker" ]; then compose stop; else systemctl stop "$SERVICE_NAME"; fi
        echo "已停止"
        ;;
    restart)
        if [ "$MODE" = "docker" ]; then compose restart; else systemctl restart "$SERVICE_NAME"; fi
        echo "已重启"
        ;;
    status)
        if [ "$MODE" = "docker" ]; then
            compose ps
        else
            systemctl status "$SERVICE_NAME" --no-pager || true
        fi
        ;;
    logs)
        shift || true
        if [ "$MODE" = "docker" ]; then
            compose logs --tail=200 "$@" aws-helper
        else
            journalctl -u "$SERVICE_NAME" -n 200 "$@"
        fi
        ;;
    reset-password)
        shift || true
        app_cli reset-password "$@"
        ;;
    info)
        app_cli status
        ;;
    logout-all)
        app_cli logout-all
        ;;
    update)
        echo "请在源码目录重新执行 install.sh 完成更新："
        echo "  sudo bash deploy/install.sh --mode $MODE --yes"
        ;;
    uninstall)
        read -r -p "确认卸载 AWS 小助手？[y/N]: " yn
        case "${yn,,}" in y|yes) ;; *) echo "已取消"; exit 0 ;; esac

        if [ "$MODE" = "docker" ]; then
            compose down || true
        else
            systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
            rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
            systemctl daemon-reload
        fi

        read -r -p "同时删除数据（AWS 凭据、密码、日志）？[y/N]: " yn
        case "${yn,,}" in
            y|yes)
                if [ "$MODE" = "docker" ]; then
                    compose down -v || true
                else
                    rm -rf "$DATA_DIR"
                fi
                rm -rf "$CONFIG_DIR"
                echo "数据已删除"
                ;;
            *)
                if [ "$MODE" = "docker" ]; then
                    echo "数据保留在 docker 卷中（docker volume ls 可查看）"
                else
                    echo "数据保留在 $DATA_DIR"
                fi
                ;;
        esac

        # 只在没有别的部署方式残留时才删共享的安装目录
        local other
        other="$([ "$MODE" = "docker" ] && echo systemd || echo docker)"
        if [ -x "/usr/local/bin/aws-helper-$other" ]; then
            echo "检测到另一种部署（$other）仍然存在，保留 $INSTALL_DIR"
        else
            rm -rf "$INSTALL_DIR"
        fi

        # aws-helper 软链若指向本次卸载的脚本则重新指向另一种，否则删掉
        if [ -x "/usr/local/bin/aws-helper-$other" ]; then
            ln -sf "/usr/local/bin/aws-helper-$other" /usr/local/bin/aws-helper
        else
            rm -f /usr/local/bin/aws-helper
        fi
        rm -f "/usr/local/bin/aws-helper-$MODE"
        echo "卸载完成"
        ;;
    ''|-h|--help|help)
        usage
        ;;
    *)
        echo "未知命令: $1" >&2
        usage
        exit 1
        ;;
esac
EOF

    chmod 755 "$target"
    # aws-helper 始终指向最近一次安装，同时保留 -systemd / -docker 专属入口
    ln -sf "$target" "$MANAGE_BIN"
    ok "管理命令已装到 $target"
    ok "并已把 $MANAGE_BIN 指向它（另一种部署用 ${MANAGE_BIN}-<mode>）"
}

# ---------------------------------------------------------------- 收尾

wait_healthy() {
    local password="$1"
    local probe_host="$BIND_HOST"
    [ "$probe_host" = "0.0.0.0" ] && probe_host="127.0.0.1"

    info "等待服务就绪"
    local i
    for i in $(seq 1 40); do
        if command -v curl >/dev/null 2>&1; then
            if curl -sf -o /dev/null "http://${probe_host}:${PORT}/healthz"; then
                ok "服务健康检查通过"
                print_summary "$password" "ok"
                return 0
            fi
        else
            # 没有 curl 时退化为端口探测
            if port_in_use; then
                ok "端口 $PORT 已监听"
                print_summary "$password" "ok"
                return 0
            fi
        fi
        sleep 1
    done

    warn "40 秒内未能确认服务就绪"
    if [ "$MODE" = "docker" ]; then
        warn "查看日志: aws-helper logs"
    else
        warn "查看日志: journalctl -u ${SERVICE_NAME} -n 50"
    fi
    print_summary "" "fail"
    # 非 0 退出码，让调用方和 CI 能发现部署没成功
    return 1
}

print_summary() {
    local password="$1" state="$2"
    local show_host="$BIND_HOST"
    [ "$show_host" = "0.0.0.0" ] && show_host="服务器IP"

    echo
    echo "======================================================================"
    if [ "$state" = "ok" ]; then
        printf '%s  AWS 小助手部署完成%s\n' "$C_BOLD$C_GREEN" "$C_RESET"
    else
        printf '%s  部署已执行，但服务状态未确认%s\n' "$C_BOLD$C_YELLOW" "$C_RESET"
    fi
    echo "----------------------------------------------------------------------"
    echo "  部署方式  : $MODE"
    echo "  访问地址  : http://${show_host}:${PORT}"
    if [ -n "$password" ]; then
        printf '  初始密码  : %s%s%s\n' "$C_BOLD" "$password" "$C_RESET"
        echo "              （登录后请在「用户面板」修改）"
    else
        echo "  登录密码  : 沿用原有密码（本次未修改）"
        echo "              忘记了执行: aws-helper reset-password"
    fi
    if [ "$MODE" = "systemd" ]; then
        echo "  虚拟环境  : $INSTALL_DIR/venv"
        echo "  数据目录  : $DATA_DIR"
        echo "  配置文件  : $ENV_FILE"
    else
        echo "  数据卷    : docker volume（aws-helper-data）"
        echo "  配置文件  : $INSTALL_DIR/.env"
    fi
    echo "----------------------------------------------------------------------"
    echo "  常用命令:"
    echo "    aws-helper status            查看状态"
    echo "    aws-helper logs -f          跟踪日志"
    echo "    aws-helper restart          重启"
    echo "    aws-helper reset-password   忘记密码时重置"
    echo "    aws-helper uninstall        卸载"
    if [ "$BIND_HOST" != "127.0.0.1" ] && [ "$BIND_HOST" != "localhost" ]; then
        echo "----------------------------------------------------------------------"
        printf '%s  面板已对外暴露且持有你的 AWS 凭据。%s\n' "$C_YELLOW" "$C_RESET"
        printf '%s  强烈建议放到 HTTPS 反代之后，并只对可信 IP 开放。%s\n' "$C_YELLOW" "$C_RESET"
    fi
    echo "======================================================================"
    echo
}

main() {
    parse_args "$@"
    require_root

    [ -d "$SOURCE_DIR/aws_helper" ] \
        || die "找不到 aws_helper 目录，请在项目根目录运行本脚本"

    choose_mode
    # 两种部署方式各用独立目录，可以并存互不干扰
    if [ "$MODE" = "docker" ]; then
        INSTALL_DIR="${INSTALL_DIR}-docker"
    fi
    ask_host_port
    ensure_port_available

    echo
    info "开始部署（方式: $MODE，监听 ${BIND_HOST}:${PORT}）"
    case "$MODE" in
        systemd) install_systemd ;;
        docker)  install_docker ;;
    esac
}

main "$@"
