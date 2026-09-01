"""重置实例登录密码（SSM）。

面板拿不到实例里面的东西，唯一不需要"先能登进去"的路径是 Systems Manager。
这些测试盯的是它的前提条件与失败模式 —— 没挂实例配置文件的机器占多数，
那种情况必须给可操作的说明，而不是一个超时。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aws_helper.core import aws, respw

CREDS = aws.Credentials("a", "b", "us-east-1")
IID = "i-0abc0000000000001"


def _online(**over):
    item = {
        "InstanceId": IID,
        "PingStatus": "Online",
        "PlatformType": "Linux",
        "PlatformName": "Ubuntu",
        "AgentVersion": "3.3.1",
    }
    item.update(over)
    return {"InstanceInformationList": [item]}


# ---------- 注册状态 ----------


def test_unregistered_instance_explains_how_to_fix():
    """没注册到 SSM 时必须说清怎么补，这是最常见的情况。

    开机时没挂实例配置文件的机器根本用不了 SSM，用户看到的不该是
    InvalidInstanceId 或者一个超时。
    """
    with patch.object(respw, "_ssm") as factory:
        factory.return_value.describe_instance_information.return_value = {
            "InstanceInformationList": []
        }
        status = respw.ssm_status(CREDS, "us-east-1", IID)

    assert status["registered"] is False
    assert "AmazonSSMManagedInstanceCore" in status["reason"]
    assert "修改 IAM 角色" in status["reason"]
    assert "不用重启" in status["reason"]


def test_offline_agent_is_not_registered():
    """Agent 掉线（PingStatus 不是 Online）等于不可用。"""
    with patch.object(respw, "_ssm") as factory:
        factory.return_value.describe_instance_information.return_value = _online(
            PingStatus="ConnectionLost"
        )
        status = respw.ssm_status(CREDS, "us-east-1", IID)

    assert status["registered"] is False
    assert "ConnectionLost" in status["reason"]


def test_online_instance_reports_platform():
    with patch.object(respw, "_ssm") as factory:
        factory.return_value.describe_instance_information.return_value = _online()
        status = respw.ssm_status(CREDS, "us-east-1", IID)

    assert status["registered"] is True
    assert status["platform"] == "Linux"
    assert status["agent_version"] == "3.3.1"


def test_ssm_query_failure_does_not_raise():
    """查状态失败不该抛异常 —— 页面只是想知道能不能用。"""
    with patch.object(respw, "_ssm") as factory:
        factory.return_value.describe_instance_information.side_effect = RuntimeError(
            "AccessDenied"
        )
        status = respw.ssm_status(CREDS, "us-east-1", IID)

    assert status["registered"] is False
    assert "AccessDenied" in status["reason"]


def test_reset_refuses_unregistered_before_sending():
    """没注册就不该下发命令，白等 60 秒轮询。"""
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = {"InstanceInformationList": []}
        with pytest.raises(respw.PasswordResetError, match="AmazonSSMManagedInstanceCore"):
            respw.reset_password(CREDS, "us-east-1", IID, "Str0ng!Pass1")
        assert client.send_command.call_count == 0, "未注册时不该下发命令"


# ---------- 脚本内容 ----------


def test_linux_script_opens_password_auth():
    """只改密码是不够的。

    官方云镜像默认 PasswordAuthentication no，改完密码仍然登不进去 ——
    这是"重置密码"这个功能最容易做成半成品的地方。
    """
    script = respw._linux_script("root", "Str0ng!Pass1")
    assert "chpasswd" in script
    assert "PasswordAuthentication yes" in script


def test_linux_script_writes_sshd_config_d_fragment():
    """Ubuntu 22.04+ 用 sshd_config.d 片段覆盖主配置。

    只改 /etc/ssh/sshd_config 会被 Include 进来的片段盖掉，
    改了等于没改。
    """
    script = respw._linux_script("root", "Str0ng!Pass1")
    assert "/etc/ssh/sshd_config.d" in script
    assert "00-aws-helper-password.conf" in script


def test_linux_script_validates_config_before_restart():
    """重启 sshd 前必须 sshd -t。

    配置写坏了直接重启会把自己彻底关在门外 —— 而这台机器的密码
    正是刚才要重置的那个，没有别的进入手段。
    """
    script = respw._linux_script("root", "Str0ng!Pass1")
    assert "sshd -t" in script
    restart_at = min(
        script.index("systemctl restart sshd"), script.index("service ssh restart")
    )
    assert script.index("sshd -t") < restart_at


def test_linux_script_unlocks_root():
    """云镜像的 root 账号默认是锁定的，不解锁密码认证照样失败。"""
    script = respw._linux_script("root", "Str0ng!Pass1")
    assert "passwd -u root" in script


def test_linux_script_does_not_unlock_non_root():
    script = respw._linux_script("ubuntu", "Str0ng!Pass1")
    assert 'if [ "ubuntu" = "root" ]' in script


def test_password_not_passed_as_argv():
    """密码不能出现在命令行参数里 —— 同机任何用户 ps 一下就能看到。"""
    script = respw._linux_script("root", "SuperSecret1!")
    assert "printf" in script and "| chpasswd" in script
    assert "chpasswd SuperSecret1!" not in script
    assert "echo SuperSecret1!" not in script


def test_shell_quoting_survives_single_quote():
    """密码里带单引号不能把脚本引号结构破坏掉。"""
    script = respw._linux_script("root", "pa'ss")
    assert "'root:pa'\\''ss'" in script


def test_powershell_quoting_doubles_single_quote():
    script = respw._windows_script("Administrator", "pa'ss")
    assert "'pa''ss'" in script


def test_windows_uses_powershell_document():
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online(
            PlatformType="Windows"
        )
        client.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
        client.get_command_invocation.return_value = {
            "Status": "Success",
            "StandardOutputContent": "done",
        }
        respw.reset_password(
            CREDS, "us-east-1", IID, "Str0ng!Pass1", "Administrator", is_windows=True
        )
        kwargs = client.send_command.call_args.kwargs

    assert kwargs["DocumentName"] == "AWS-RunPowerShellScript"
    assert "Set-LocalUser" in kwargs["Parameters"]["commands"][0]


def test_linux_uses_shell_document():
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online()
        client.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
        client.get_command_invocation.return_value = {"Status": "Success"}
        respw.reset_password(CREDS, "us-east-1", IID, "Str0ng!Pass1")
        kwargs = client.send_command.call_args.kwargs

    assert kwargs["DocumentName"] == "AWS-RunShellScript"


# ---------- 执行与轮询 ----------


def test_successful_reset_returns_command_id():
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online()
        client.send_command.return_value = {"Command": {"CommandId": "cmd-42"}}
        client.get_command_invocation.return_value = {
            "Status": "Success",
            "StandardOutputContent": "密码已重置\n",
        }
        out = respw.reset_password(CREDS, "us-east-1", IID, "Str0ng!Pass1")

    assert out["command_id"] == "cmd-42"
    assert out["status"] == "Success"
    assert "密码已重置" in out["output"]


def test_result_never_contains_password():
    """返回值里不能带密码 —— 它会进任务记录和页面。"""
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online()
        client.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
        client.get_command_invocation.return_value = {"Status": "Success"}
        out = respw.reset_password(CREDS, "us-east-1", IID, "TopSecret9!")

    assert "TopSecret9!" not in str(out)


def test_polls_until_terminal_status(monkeypatch):
    """命令是异步的，要轮询到终态。"""
    monkeypatch.setattr(respw, "_POLL_INTERVAL", 0)
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online()
        client.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
        client.get_command_invocation.side_effect = [
            {"Status": "Pending"},
            {"Status": "InProgress"},
            {"Status": "Success"},
        ]
        out = respw.reset_password(CREDS, "us-east-1", IID, "Str0ng!Pass1")

    assert out["status"] == "Success"
    assert client.get_command_invocation.call_count == 3


def test_tolerates_invocation_not_yet_existing(monkeypatch):
    """SendCommand 之后指令还没派发时会报 InvocationDoesNotExist。

    这不是失败，宽限期内重试即可 —— 不容忍的话每次重置都随机失败。
    """
    monkeypatch.setattr(respw, "_POLL_INTERVAL", 0)
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online()
        client.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
        client.get_command_invocation.side_effect = [
            RuntimeError("InvocationDoesNotExist"),
            {"Status": "Success"},
        ]
        out = respw.reset_password(CREDS, "us-east-1", IID, "Str0ng!Pass1")

    assert out["status"] == "Success"


def test_failed_command_surfaces_stderr():
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online()
        client.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
        client.get_command_invocation.return_value = {
            "Status": "Failed",
            "StandardErrorContent": "chpasswd: user 'nope' does not exist",
        }
        with pytest.raises(respw.PasswordResetError, match="does not exist"):
            respw.reset_password(CREDS, "us-east-1", IID, "Str0ng!Pass1", "nope")


def test_timeout_reports_last_status(monkeypatch):
    monkeypatch.setattr(respw, "_POLL_INTERVAL", 0)
    monkeypatch.setattr(respw, "_POLL_TIMEOUT", 0.05)
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online()
        client.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
        client.get_command_invocation.return_value = {"Status": "InProgress"}
        with pytest.raises(respw.PasswordResetError, match="超时"):
            respw.reset_password(CREDS, "us-east-1", IID, "Str0ng!Pass1")


def test_empty_password_rejected():
    with pytest.raises(respw.PasswordResetError, match="请提供新密码"):
        respw.reset_password(CREDS, "us-east-1", IID, "")


def test_empty_instance_rejected():
    with pytest.raises(respw.PasswordResetError, match="实例 ID"):
        respw.reset_password(CREDS, "us-east-1", "", "Str0ng!Pass1")


def test_send_command_failure_is_wrapped():
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online()
        client.send_command.side_effect = RuntimeError("ThrottlingException")
        with pytest.raises(respw.PasswordResetError, match="ThrottlingException"):
            respw.reset_password(CREDS, "us-east-1", IID, "Str0ng!Pass1")


def test_progress_is_reported(monkeypatch):
    monkeypatch.setattr(respw, "_POLL_INTERVAL", 0)
    seen: list[str] = []
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online()
        client.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
        client.get_command_invocation.return_value = {"Status": "Success"}
        respw.reset_password(
            CREDS, "us-east-1", IID, "Str0ng!Pass1", progress=seen.append
        )

    assert any("SSM" in s for s in seen)
    assert any("下发" in s for s in seen)
