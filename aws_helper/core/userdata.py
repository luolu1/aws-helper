"""开机脚本（EC2 UserData / cloud-init）渲染。"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

SHEBANGS = ("#!/bin/bash", "#!/bin/sh", "#cloud-config")

# 只放开必要项，不整体覆盖 sshd_config。用 drop-in 文件，
# 保留发行版默认配置，避免删掉 Subsystem sftp 等条目。
_ROOT_LOGIN_BLOCK = """\
# --- aws-helper: 开启 root 密码登录 ---
echo 'root:{password}' | chpasswd
install -d -m 755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/60-aws-helper.conf <<'AWSHELPER_EOF'
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
ClientAliveInterval 120
AWSHELPER_EOF
# 部分 AMI 的主配置里硬编码了 PasswordAuthentication no 且不含 Include，
# 这种情况下 drop-in 不生效，需要就地改写。
if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\\.d/' /etc/ssh/sshd_config; then
  sed -i -E 's/^[[:space:]]*#?[[:space:]]*(PasswordAuthentication|PermitRootLogin)[[:space:]].*//I' \\
    /etc/ssh/sshd_config
  printf '\\nInclude /etc/ssh/sshd_config.d/*.conf\\n' >> /etc/ssh/sshd_config
fi
# 云镜像常在此目录放 PasswordAuthentication no，需要一并清掉
if [ -d /etc/ssh/sshd_config.d ]; then
  for f in /etc/ssh/sshd_config.d/*.conf; do
    case "$f" in
      */60-aws-helper.conf) continue ;;
    esac
    [ -f "$f" ] && sed -i -E \\
      's/^[[:space:]]*(PasswordAuthentication|PermitRootLogin)[[:space:]].*//I' "$f"
  done
fi
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
"""


@dataclass
class ScriptOptions:
    """开机脚本的组装选项。"""

    custom_script: str = ""
    root_password: str | None = None
    hostname: str | None = None
    packages: list[str] = field(default_factory=list)
    run_as_root: bool = True


class ScriptError(ValueError):
    """脚本内容不合法。"""


def validate(custom_script: str) -> None:
    """自定义脚本不应自带 shebang，因为渲染时会补上。"""
    head = custom_script.lstrip()
    for shebang in SHEBANGS:
        if head.startswith(shebang):
            raise ScriptError(
                f"自定义脚本不要以 {shebang} 开头，渲染时会自动添加。"
                "直接写需要执行的命令即可。"
            )


def render(opts: ScriptOptions) -> str:
    """渲染完整 UserData 文本。

    结构固定为：shebang → set -e → hostname → 包安装 → root 登录 → 用户脚本。
    用户脚本永远在最后，前面的固定动作失败不影响它执行（用 `|| true` 兜住）。
    """
    validate(opts.custom_script)

    lines = ["#!/bin/bash", "set -o pipefail", "export DEBIAN_FRONTEND=noninteractive", ""]

    if opts.hostname:
        safe = _sanitize_hostname(opts.hostname)
        lines += [
            f"hostnamectl set-hostname {safe} 2>/dev/null || hostname {safe} || true",
            f"grep -q '{safe}' /etc/hosts || echo '127.0.1.1 {safe}' >> /etc/hosts",
            "",
        ]

    if opts.packages:
        pkgs = " ".join(_sanitize_package(p) for p in opts.packages if p.strip())
        if pkgs:
            lines += [
                "if command -v apt-get >/dev/null 2>&1; then",
                "  apt-get update -y || true",
                f"  apt-get install -y {pkgs} || true",
                "elif command -v dnf >/dev/null 2>&1; then",
                f"  dnf install -y {pkgs} || true",
                "elif command -v yum >/dev/null 2>&1; then",
                f"  yum install -y {pkgs} || true",
                "fi",
                "",
            ]

    if opts.root_password:
        lines.append(_ROOT_LOGIN_BLOCK.format(password=_escape_sq(opts.root_password)))
        lines.append("")

    if opts.custom_script.strip():
        lines += ["# --- 用户自定义脚本 ---", opts.custom_script.rstrip(), ""]

    return "\n".join(lines)


def render_b64(opts: ScriptOptions) -> str:
    """渲染并 base64 编码。EC2 RunInstances 的 UserData 需要 base64。

    boto3 会对 UserData 自动做 base64，所以传给 boto3 时用 render()；
    此函数用于需要手动编码的场合（如导出、日志、直接调 HTTP API）。
    """
    return base64.b64encode(render(opts).encode("utf-8")).decode("ascii")


def _escape_sq(value: str) -> str:
    """转义单引号，防止 chpasswd 那行的引号被提前闭合。"""
    return value.replace("'", "'\"'\"'")


def _sanitize_hostname(name: str) -> str:
    allowed = [c if (c.isalnum() or c in "-.") else "-" for c in name]
    result = "".join(allowed).strip("-.") or "aws-helper"
    return result[:63]


def _sanitize_package(name: str) -> str:
    """校验软件包名。非法字符直接报错，不做静默改写。

    静默改写会把 "; rm -rf /" 变成 "rm-rf" 并照样执行 install，
    既掩盖了注入意图，也可能装错包。
    """
    cleaned = name.strip()
    if not cleaned or any(not (c.isalnum() or c in "-_.+") for c in cleaned):
        raise ScriptError(
            f"非法软件包名: {name!r}（只允许字母、数字和 - _ . + ）"
        )
    return cleaned
