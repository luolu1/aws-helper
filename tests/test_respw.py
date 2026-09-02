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


# ---------- SSH 公钥校验 ----------

# 真实 ed25519 公钥。硬编码而不是每次 ssh-keygen：测试不该依赖外部二进制，
# 而这串必须是 OpenSSH 真正产出的格式，校验函数会解析 base64 内部的类型名。
REAL_ED25519 = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIMxGgW4kZ8HLmGpQnbnFhc6TThRRW3TnkS1EYQ8jSJZG"
    " me@laptop"
)


def test_accepts_real_openssh_public_key():
    out = respw.validate_public_key(REAL_ED25519)
    assert out.startswith("ssh-ed25519 AAAAC3")
    assert out.endswith("me@laptop")


def test_public_key_newlines_are_flattened():
    """从文件里复制常带换行，写进 authorized_keys 会拆成两条无效行。"""
    out = respw.validate_public_key("ssh-ed25519\n" + REAL_ED25519.split(" ", 1)[1])
    assert "\n" not in out


def test_private_key_paste_is_caught():
    """最常见的误操作是粘了私钥，报错必须点明。"""
    with pytest.raises(respw.PasswordResetError, match="私钥"):
        respw.validate_public_key(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabcd\n-----END OPENSSH PRIVATE KEY-----"
        )


def test_unknown_key_type_rejected():
    with pytest.raises(respw.PasswordResetError, match="不支持的公钥类型"):
        respw.validate_public_key("ssh-foo AAAAC3NzaC1lZDI1NTE5")


def test_body_must_be_base64():
    with pytest.raises(respw.PasswordResetError, match="base64"):
        respw.validate_public_key("ssh-ed25519 not-base64!!!!")


def test_type_prefix_must_match_body():
    """把两把不同的键拼起来是能过 base64 的，但登录时静默失败。"""
    body = REAL_ED25519.split(" ")[1]
    with pytest.raises(respw.PasswordResetError, match="不符"):
        respw.validate_public_key(f"ssh-rsa {body}")


def test_empty_public_key_rejected():
    with pytest.raises(respw.PasswordResetError, match="请粘贴"):
        respw.validate_public_key("   ")


# ---------- 写入 authorized_keys ----------


def test_pubkey_script_sets_strict_modes_permissions():
    """sshd 的 StrictModes 默认开启，权限过宽会静默拒绝该公钥。"""
    script = respw._linux_script("root", public_key=REAL_ED25519)
    assert "install -d -m 700" in script
    assert "chmod 600" in script
    assert 'chown "$target_user"' in script


def test_pubkey_script_appends_not_overwrites():
    """覆盖会踢掉 AWS 密钥对注入的那把公钥，用户原私钥就登不进了。"""
    script = respw._linux_script("root", public_key=REAL_ED25519)
    assert ">> \"$home/.ssh/authorized_keys\"" in script
    assert "grep -qxF" in script


def test_pubkey_script_resolves_home_from_passwd():
    """不能假设 /home/<user>：root 是 /root，某些镜像的默认用户也不在 /home。"""
    script = respw._linux_script("ubuntu", public_key=REAL_ED25519)
    assert "getent passwd" in script
    assert "/home/ubuntu" not in script


def test_pubkey_only_script_has_no_chpasswd():
    script = respw._linux_script("root", public_key=REAL_ED25519)
    assert "chpasswd" not in script
    assert "PubkeyAuthentication yes" in script


def test_password_only_script_has_no_authorized_keys():
    script = respw._linux_script("root", password="Str0ng!Pass1")
    assert "authorized_keys" not in script
    assert "chpasswd" in script


def test_both_credentials_in_one_script():
    script = respw._linux_script("root", password="Str0ng!Pass1", public_key=REAL_ED25519)
    assert "chpasswd" in script
    assert "authorized_keys" in script
    # sshd 只重启一次，两段配置都写完之后
    assert script.count("systemctl restart sshd") == 1


def test_pubkey_fragment_sorts_after_password_fragment():
    """两个片段都写 PermitRootLogin，OpenSSH 是首个生效，文件名顺序决定结果。

    密码片段（00-aws-helper-password.conf）必须排在公钥片段
    （00-aws-helper-pubkey.conf）之前，否则 prohibit-password 会先生效，
    密码登录被静默挡掉 —— 用户设了密码却登不进去。实测 sshd -T 确认过。
    """
    script = respw._linux_script("root", password="Str0ng!Pass1", public_key=REAL_ED25519)
    assert "00-aws-helper-password.conf" in script
    assert "00-aws-helper-pubkey.conf" in script
    assert "00-aws-helper-password.conf" < "00-aws-helper-pubkey.conf"


def test_script_needs_at_least_one_credential():
    with pytest.raises(respw.PasswordResetError, match="至少"):
        respw._linux_script("root")


def test_reset_accepts_public_key_only():
    with patch.object(respw, "_ssm") as factory:
        client = factory.return_value
        client.describe_instance_information.return_value = _online()
        client.send_command.return_value = {"Command": {"CommandId": "cmd-9"}}
        client.get_command_invocation.return_value = {"Status": "Success"}
        out = respw.reset_password(
            CREDS, "us-east-1", IID, public_key=REAL_ED25519
        )
        script = client.send_command.call_args.kwargs["Parameters"]["commands"][0]

    assert out["set_public_key"] is True
    assert out["set_password"] is False
    assert "authorized_keys" in script


def test_reset_rejects_neither_credential():
    with pytest.raises(respw.PasswordResetError, match="密码或 SSH 公钥"):
        respw.reset_password(CREDS, "us-east-1", IID)


def test_windows_rejects_public_key():
    """EC2Launch 不读 authorized_keys，静默不生效比直接报错更难查。"""
    with pytest.raises(respw.PasswordResetError, match="Windows"):
        respw.reset_password(
            CREDS, "us-east-1", IID, public_key=REAL_ED25519, is_windows=True
        )


def test_bad_public_key_rejected_before_any_aws_call():
    """校验要在 SSM 之前，否则白跑一次注册状态查询。"""
    with patch.object(respw, "_ssm") as factory:
        with pytest.raises(respw.PasswordResetError):
            respw.reset_password(CREDS, "us-east-1", IID, public_key="ssh-ed25519 zzz!")
        factory.assert_not_called()
