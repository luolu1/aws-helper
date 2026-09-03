"""部署脚本与容器配置的静态检查。

不启动真实服务（那需要 root 和 docker），但保证：
- shell 脚本语法正确、关键分支存在
- Dockerfile / compose 的安全设置没被误删
- requirements.txt 覆盖了程序真正 import 的第三方包
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / "deploy" / "install.sh"
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE = ROOT / "docker-compose.yml"
REQUIREMENTS = ROOT / "requirements.txt"


# ---------- 文件存在 ----------


@pytest.mark.parametrize(
    "path", [INSTALL_SH, DOCKERFILE, COMPOSE, REQUIREMENTS]
)
def test_deploy_files_exist(path):
    assert path.is_file(), f"缺少部署文件 {path.name}"


def test_install_script_executable():
    assert INSTALL_SH.stat().st_mode & 0o111, "install.sh 需要可执行权限"


# ---------- shell 语法 ----------


@pytest.mark.skipif(not shutil.which("bash"), reason="需要 bash")
def test_install_script_syntax():
    result = subprocess.run(
        ["bash", "-n", str(INSTALL_SH)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not shutil.which("bash"), reason="需要 bash")
def test_install_script_help_works():
    result = subprocess.run(
        ["bash", str(INSTALL_SH), "--help"], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "--mode" in result.stdout
    assert "systemd" in result.stdout
    assert "docker" in result.stdout


@pytest.mark.skipif(not shutil.which("bash"), reason="需要 bash")
def test_install_script_rejects_bad_mode():
    result = subprocess.run(
        ["bash", str(INSTALL_SH), "--mode", "k8s"], capture_output=True, text=True
    )
    assert result.returncode != 0
    assert "systemd" in result.stderr


@pytest.mark.skipif(not shutil.which("bash"), reason="需要 bash")
def test_install_script_rejects_bad_port():
    result = subprocess.run(
        ["bash", str(INSTALL_SH), "--port", "99999"], capture_output=True, text=True
    )
    assert result.returncode != 0
    assert "端口" in result.stderr


@pytest.mark.skipif(not shutil.which("bash"), reason="需要 bash")
def test_generated_manage_script_syntax():
    """install.sh 里内嵌的 aws-helper 脚本也必须语法正确。

    它是用 heredoc 拼出来的，语法错误在安装时不会暴露，
    只有用户执行 aws-helper 才炸 —— 所以这里提取出来单独检查。
    """
    text = INSTALL_SH.read_text()
    start = text.index('cat > "$target" <<EOF')
    end = text.index('chmod 755 "$target"')
    body = text[start:end]

    chunks = re.findall(r"<<'EOF'\n(.*?)\nEOF\n", body, re.S)
    assert chunks, "没能提取到管理脚本正文"

    script = "\n".join(
        [
            'MODE="systemd"',
            'INSTALL_DIR="/tmp/x"',
            'DATA_DIR="/tmp/x/data"',
            'CONFIG_DIR="/tmp/x/etc"',
            'ENV_FILE="/tmp/x/etc/env"',
            'SERVICE_NAME="aws-helper"',
            'SERVICE_USER="awshelper"',
            'COMPOSE_BIN="docker compose"',
        ]
        + chunks
    )
    result = subprocess.run(
        ["bash", "-n"], input=script, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


# ---------- install.sh 关键行为 ----------


def test_supports_both_modes():
    text = INSTALL_SH.read_text()
    assert "install_systemd()" in text
    assert "install_docker()" in text


def test_systemd_uses_venv():
    """systemd 模式必须用虚拟环境，避免污染系统 Python。"""
    text = INSTALL_SH.read_text()
    assert "python3 -m venv" in text
    assert "$INSTALL_DIR/venv/bin/pip" in text
    assert "$INSTALL_DIR/venv/bin/python" in text


def test_systemd_unit_hardening():
    text = INSTALL_SH.read_text()
    for directive in (
        "User=$SERVICE_USER",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ReadWritePaths=$DATA_DIR",
        "Restart=on-failure",
        "WantedBy=multi-user.target",
    ):
        assert directive in text, f"systemd 单元缺少 {directive}"


def test_compose_availability_is_actually_probed():
    """只检查命令存在不够，必须验证能连上守护进程。"""
    text = INSTALL_SH.read_text()
    assert "compose_works()" in text
    assert "install_compose_plugin()" in text


def test_reinstall_does_not_print_stale_password():
    """已有密码时不能再打印新生成的值 —— 那个密码不会生效。"""
    text = INSTALL_SH.read_text()
    assert "db_has_password" in text
    assert "沿用原密码" in text


def test_port_conflict_is_fatal():
    """端口被别人占用必须终止安装。

    否则服务会起不来并反复重启，而摘要照样打印"部署完成 + 初始密码"，
    用户拿着"正确"的密码登不进去，非常难排查。
    """
    text = INSTALL_SH.read_text()
    assert "ensure_port_available" in text
    assert "请换端口" in text


def test_port_owner_check_inspects_listener():
    """判断端口是否属于本程序要看监听进程，不能只看服务存在。

    崩溃重启中的服务是 activating 状态，它并没有真的持有端口，
    只查 is-active 会把冲突误判为"自己占的"。
    """
    text = INSTALL_SH.read_text()
    assert "port_listener_pid" in text
    assert "is_our_process" in text
    assert "MainPID" in text


def test_healthcheck_failure_returns_nonzero():
    text = INSTALL_SH.read_text()
    idx = text.index("40 秒内未能确认服务就绪")
    assert "return 1" in text[idx : idx + 500]


def test_two_modes_can_coexist():
    """两种部署方式并存时不能互相覆盖。

    docker 用独立安装目录，管理命令按模式分文件（aws-helper-systemd /
    aws-helper-docker），aws-helper 是指向最近一次安装的软链。
    """
    text = INSTALL_SH.read_text()
    assert 'INSTALL_DIR="${INSTALL_DIR}-docker"' in text
    assert '${MANAGE_BIN}-${mode}' in text
    assert 'ln -sf "$target" "$MANAGE_BIN"' in text


def test_uninstall_preserves_other_mode():
    """卸载一种方式不能删掉另一种方式仍在用的东西。"""
    text = INSTALL_SH.read_text()
    assert "aws-helper-$other" in text
    assert "仍然存在，保留" in text


def test_manage_script_has_all_subcommands():
    text = INSTALL_SH.read_text()
    for cmd in (
        "start)",
        "stop)",
        "restart)",
        "status)",
        "logs)",
        "reset-password)",
        "logout-all)",
        "uninstall)",
    ):
        assert cmd in text, f"管理命令缺少 {cmd}"


def test_uninstall_asks_before_deleting_data():
    """卸载不能顺手删掉 AWS 凭据，必须单独确认。"""
    text = INSTALL_SH.read_text()
    assert "同时删除数据" in text


def test_warns_when_binding_public():
    text = INSTALL_SH.read_text()
    assert "HTTPS 反代" in text


# ---------- Dockerfile ----------


def test_dockerfile_runs_as_non_root():
    text = DOCKERFILE.read_text()
    assert re.search(r"^USER\s+awshelper", text, re.M), "容器必须非 root 运行"
    assert "useradd" in text


def test_dockerfile_has_healthcheck():
    text = DOCKERFILE.read_text()
    assert "HEALTHCHECK" in text
    assert "/healthz" in text


def test_dockerfile_declares_data_volume():
    text = DOCKERFILE.read_text()
    assert 'VOLUME ["/data"]' in text
    assert "AWS_HELPER_DATA=/data" in text


def test_dockerfile_installs_requirements():
    text = DOCKERFILE.read_text()
    assert "requirements.txt" in text
    assert "pip install" in text


def test_dockerfile_copies_app_after_deps():
    """依赖层要在代码层之前，改代码才能命中缓存。"""
    text = DOCKERFILE.read_text()
    assert text.index("requirements.txt") < text.index("COPY aws_helper")


# ---------- Postgres 集成 ----------


def test_requirements_include_postgres_driver():
    text = REQUIREMENTS.read_text().lower()
    assert "psycopg" in text
    assert "psycopg-pool" in text


def test_install_sets_up_postgres():
    """systemd 模式要自动装并初始化 Postgres，否则装完连不上库。"""
    text = INSTALL_SH.read_text()
    assert "install_postgres()" in text
    assert "setup_database()" in text
    assert "AWS_HELPER_DATABASE_URL=" in text


def test_database_setup_is_idempotent():
    """重装不能覆盖已有数据库，角色和库都要先查再建。"""
    text = INSTALL_SH.read_text()
    assert "FROM pg_roles WHERE rolname" in text
    assert "FROM pg_database WHERE datname" in text
    assert "保留原有数据" in text


def test_db_password_reused_on_reinstall():
    """数据库口令必须从已有 env 沿用 —— 重新生成会连不上已初始化的库。"""
    text = INSTALL_SH.read_text()
    assert "read_env_value AWS_HELPER_DB_PASSWORD" in text


def test_unit_depends_on_postgres():
    """服务必须在 Postgres 之后启动，否则首次建表失败。"""
    text = INSTALL_SH.read_text()
    assert "Requires=postgresql.service" in text
    assert "After=network-online.target postgresql.service" in text


def test_schema_check_runs_after_database_ready():
    """完整导入自检要排在建库之后。

    web.app 在导入时就会连数据库，放在建库之前必然失败。
    """
    text = INSTALL_SH.read_text()
    assert text.index("setup_database") < text.index("验证数据库连接并建表")


def test_uninstall_drops_database():
    """卸载删数据时要连数据库一起删，光删目录会残留全部业务数据。"""
    text = INSTALL_SH.read_text()
    assert "dropdb --if-exists" in text
    assert "DROP ROLE IF EXISTS" in text


def test_legacy_env_gets_postgres_keys():
    """从 SQLite 时代升级上来的 .env 缺 POSTGRES_*，compose 会拒绝启动。"""
    text = INSTALL_SH.read_text()
    assert "已补齐缺失的" in text
    assert "POSTGRES_PASSWORD" in text


def test_new_volume_syncs_initial_password():
    """数据库卷是新的时候，初始密码要同步进 .env。

    否则摘要打印本次生成的密码、容器却读到上一轮遗留的旧值，登录必然失败。
    """
    text = INSTALL_SH.read_text()
    idx = text.index("数据库卷是新的")
    assert "AWS_HELPER_PASSWORD=$password" in text[idx : idx + 600]


def test_compose_has_postgres_service():
    text = COMPOSE.read_text()
    assert "postgres:16-alpine" in text
    assert "aws-helper-db:/var/lib/postgresql/data" in text


def test_compose_waits_for_healthy_database():
    """必须等库 ready 再起面板，否则首次建表会失败。"""
    import yaml

    data = yaml.safe_load(COMPOSE.read_text())
    depends = data["services"]["aws-helper"]["depends_on"]
    assert depends["postgres"]["condition"] == "service_healthy"
    assert "healthcheck" in data["services"]["postgres"]


def test_compose_database_not_exposed():
    """数据库不该映射到主机端口，只允许 compose 网络内访问。"""
    data = __import__("yaml").safe_load(COMPOSE.read_text())
    assert "ports" not in data["services"]["postgres"]


def test_compose_requires_db_password():
    """POSTGRES_PASSWORD 必须显式配置，不能悄悄用空密码建库。"""
    text = COMPOSE.read_text()
    assert "POSTGRES_PASSWORD:?" in text


def test_compose_separates_data_volumes():
    """数据库和加密密钥分开放：密钥丢了数据也解不开，不该同卷。"""
    data = __import__("yaml").safe_load(COMPOSE.read_text())
    assert set(data["volumes"]) == {"aws-helper-db", "aws-helper-data"}


# ---------- docker-compose.yml ----------


def test_compose_binds_localhost_by_default():
    text = COMPOSE.read_text()
    assert "${AWS_HELPER_BIND:-127.0.0.1}" in text


def test_compose_persists_data():
    text = COMPOSE.read_text()
    assert "aws-helper-data:/data" in text
    assert "name: aws-helper-data" in text


def test_compose_has_healthcheck_and_restart():
    text = COMPOSE.read_text()
    assert "healthcheck:" in text
    assert "restart: unless-stopped" in text


def test_compose_security_and_logging():
    text = COMPOSE.read_text()
    assert "no-new-privileges:true" in text
    assert "max-size" in text


@pytest.mark.skipif(not shutil.which("python3"), reason="需要 python3")
def test_compose_is_valid_yaml():
    import json

    try:
        import yaml  # type: ignore
    except ImportError:
        pytest.skip("未安装 PyYAML")

    data = yaml.safe_load(COMPOSE.read_text())
    assert "aws-helper" in data["services"]
    assert json.dumps(data)


# ---------- requirements.txt ----------


def test_requirements_are_pinned():
    """依赖必须钉版本，否则不同时间部署装到不同版本。"""
    for line in REQUIREMENTS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        assert "==" in line, f"依赖未固定版本: {line}"


def test_requirements_cover_all_imports():
    """程序 import 的第三方包必须都在 requirements 里。"""
    text = REQUIREMENTS.read_text().lower()
    for package in (
        "fastapi",
        "uvicorn",
        "boto3",
        "jinja2",
        "python-multipart",
        "itsdangerous",
        "cryptography",
        "pysocks",
    ):
        assert package in text, f"requirements.txt 缺少 {package}"


def test_dockerignore_excludes_junk():
    path = ROOT / ".dockerignore"
    assert path.is_file()
    text = path.read_text()
    for pattern in ("__pycache__", "tests/", ".git"):
        assert pattern in text


def test_compose_exposes_report_port():
    """实例上报端口必须映射出来，否则 agent 模式的脚本连不到面板。"""
    import yaml

    d = yaml.safe_load(COMPOSE.read_text())
    ports = d["services"]["aws-helper"]["ports"]
    assert any("8766" in p for p in ports), f"缺上报端口映射: {ports}"


def test_compose_report_port_binds_all_interfaces():
    """面板端口默认绑本机，但上报端口必须对外 —— 实例在公网上。"""
    import yaml

    d = yaml.safe_load(COMPOSE.read_text())
    report = next(p for p in d["services"]["aws-helper"]["ports"] if "8766" in p)
    assert "0.0.0.0" in report, f"上报端口必须默认绑 0.0.0.0: {report}"


def test_installer_writes_report_config():
    text = INSTALL_SH.read_text()
    assert "AWS_HELPER_REPORT_PORT=" in text
    assert "AWS_HELPER_REPORT_URL=" in text
