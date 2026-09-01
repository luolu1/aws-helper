"""重置实例登录密码。

走 Systems Manager（SSM）的 SendCommand —— 这是唯一不需要先能登进去的办法：

- SSH 改密码：前提是已经能 SSH，密码忘了正好用不上
- EC2 Instance Connect：只支持部分 AMI，且推的是临时公钥不是密码
- 改 user-data 重启：cloud-init 默认只在首次启动跑，还要先停机

SSM 的硬前提是**实例挂了带 AmazonSSMManagedInstanceCore 的实例配置文件**，
且 SSM Agent 在跑（Amazon Linux 2/2023、Ubuntu 官方 AMI 预装）。开机时没挂
实例配置文件的机器用不了 —— 这种情况必须给出可操作的说明，而不是让用户
对着一个超时错误发呆。
"""

from __future__ import annotations

import time
from typing import Any

from . import aws

# SSM 命令下发后要轮询结果。Agent 拿到指令、执行、回传通常几秒，
# 但机器负载高或 Agent 刚启动时会慢，给 60 秒。
_POLL_TIMEOUT = 60
_POLL_INTERVAL = 2

# SendCommand 之后 GetCommandInvocation 可能短暂报 InvocationDoesNotExist，
# 指令还没派发到实例上。这不是失败，重试即可。
_INVOCATION_GRACE = 10


class PasswordResetError(RuntimeError):
    """重置密码失败。"""


def _ssm(creds: aws.Credentials, region: str) -> Any:
    return aws.client("ssm", creds, region)


def ssm_status(creds: aws.Credentials, region: str, instance_id: str) -> dict[str, Any]:
    """查实例在 SSM 里的注册状态。

    先查这个再下发命令 —— 没注册的话 SendCommand 会直接抛
    InvalidInstanceId，报错里不会说清"要挂实例配置文件"。
    """
    try:
        resp = _ssm(creds, region).describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
    except Exception as exc:
        return {"registered": False, "reason": f"查询 SSM 状态失败: {exc}"}

    items = resp.get("InstanceInformationList") or []
    if not items:
        return {
            "registered": False,
            "reason": (
                "实例没有注册到 Systems Manager。需要满足两个条件：\n"
                "1. 实例挂了带 AmazonSSMManagedInstanceCore 策略的 IAM 实例配置文件\n"
                "   （开机时没挂的话，可以在控制台「操作 → 安全 → 修改 IAM 角色」补上，\n"
                "   附加后等 1-2 分钟 Agent 会自动注册，不用重启）\n"
                "2. 实例能访问 SSM 端点（公网或 VPC 端点）"
            ),
        }

    info = items[0]
    ping = info.get("PingStatus", "")
    return {
        "registered": ping == "Online",
        "ping_status": ping,
        "platform": info.get("PlatformType", ""),
        "platform_name": info.get("PlatformName", ""),
        "agent_version": info.get("AgentVersion", ""),
        "reason": "" if ping == "Online" else f"SSM Agent 状态为 {ping}，不是 Online",
    }


def _wait_command(
    client: Any, command_id: str, instance_id: str, progress: Any = None
) -> dict[str, Any]:
    deadline = time.time() + _POLL_TIMEOUT
    grace_until = time.time() + _INVOCATION_GRACE
    last: dict[str, Any] = {}

    while time.time() < deadline:
        try:
            last = client.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id
            )
        except Exception as exc:
            # 指令还没派发下去时会报 InvocationDoesNotExist，宽限期内当"还没开始"
            if "InvocationDoesNotExist" in str(exc) and time.time() < grace_until:
                time.sleep(_POLL_INTERVAL)
                continue
            raise PasswordResetError(f"查询命令结果失败: {exc}") from exc

        status = last.get("Status", "")
        if progress:
            progress(f"命令状态 {status}")
        if status in ("Success", "Failed", "Cancelled", "TimedOut"):
            return last
        time.sleep(_POLL_INTERVAL)

    raise PasswordResetError(
        f"等待命令结果超时（{_POLL_TIMEOUT}s），最后状态 {last.get('Status', '未知')}"
    )


def _linux_script(user: str, password: str) -> str:
    """改密码并确保能用密码登录 SSH。

    只改密码往往还是登不进去：官方云镜像默认 PasswordAuthentication no，
    而且 Ubuntu 22.04+ 起用 /etc/ssh/sshd_config.d/ 下的片段覆盖主配置，
    只改主配置会被片段盖掉。所以显式写一个高优先级片段。
    """
    return f"""set -e
# 用 chpasswd 从 stdin 读，避免密码出现在进程列表里（ps 能看到命令行参数）
printf '%s' {_sh_quote(f"{user}:{password}")} | chpasswd

if [ "{user}" = "root" ]; then
    # root 账号可能是锁定状态（云镜像默认），解锁否则密码认证仍然失败
    passwd -u root 2>/dev/null || true
fi

sshd_dir=/etc/ssh/sshd_config.d
if [ -d "$sshd_dir" ]; then
    # Ubuntu 22.04+ 用 Include 片段，编号越小越优先
    printf 'PasswordAuthentication yes\\nPermitRootLogin yes\\n' \\
        > "$sshd_dir/00-aws-helper-password.conf"
else
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
fi

# 校验配置再重启，配置写坏了重启 sshd 会把自己关在门外
sshd -t
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service ssh restart
echo "密码已重置，SSH 密码登录已开启"
"""


def _windows_script(user: str, password: str) -> str:
    return f"""$ErrorActionPreference = 'Stop'
$pw = ConvertTo-SecureString {_ps_quote(password)} -AsPlainText -Force
Set-LocalUser -Name {_ps_quote(user)} -Password $pw
Write-Output "密码已重置"
"""


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def reset_password(
    creds: aws.Credentials,
    region: str,
    instance_id: str,
    password: str,
    user: str = "root",
    is_windows: bool = False,
    progress: Any = None,
) -> dict[str, Any]:
    """通过 SSM 重置实例登录密码。

    返回执行结果。密码本身不会写进返回值和日志 —— SSM 的命令历史在
    AWS 控制台可见，所以脚本里也用 stdin 传密码而不是命令行参数。
    """
    if not password:
        raise PasswordResetError("请提供新密码")
    if not instance_id:
        raise PasswordResetError("请提供实例 ID")

    if progress:
        progress("检查 SSM 注册状态")
    status = ssm_status(creds, region, instance_id)
    if not status["registered"]:
        raise PasswordResetError(status["reason"])

    document = "AWS-RunPowerShellScript" if is_windows else "AWS-RunShellScript"
    script = (
        _windows_script(user, password)
        if is_windows
        else _linux_script(user, password)
    )

    client = _ssm(creds, region)
    if progress:
        progress("下发重置命令")
    try:
        sent = client.send_command(
            InstanceIds=[instance_id],
            DocumentName=document,
            Parameters={"commands": [script]},
            Comment="aws-helper reset password",
            TimeoutSeconds=120,
        )
    except Exception as exc:
        raise PasswordResetError(f"下发命令失败: {exc}") from exc

    command_id = sent["Command"]["CommandId"]
    result = _wait_command(client, command_id, instance_id, progress)

    if result.get("Status") != "Success":
        detail = (result.get("StandardErrorContent") or "").strip()[:400]
        raise PasswordResetError(
            f"命令执行失败（{result.get('Status')}）: {detail or '无错误输出'}"
        )

    return {
        "instance_id": instance_id,
        "user": user,
        "command_id": command_id,
        "status": result.get("Status"),
        "output": (result.get("StandardOutputContent") or "").strip()[:400],
    }
