"""开机脚本渲染的单元测试。"""

from __future__ import annotations

import base64

import pytest

from aws_helper.core.userdata import ScriptError, ScriptOptions, render, render_b64, validate


def test_render_adds_shebang():
    text = render(ScriptOptions(custom_script="echo hello"))
    assert text.startswith("#!/bin/bash")
    assert "echo hello" in text


def test_user_script_is_last():
    """用户脚本必须在所有固定动作之后执行。"""
    text = render(
        ScriptOptions(
            custom_script="MARKER_USER_SCRIPT",
            root_password="pw",
            hostname="node1",
            packages=["curl"],
        )
    )
    idx_user = text.index("MARKER_USER_SCRIPT")
    assert idx_user > text.index("hostnamectl")
    assert idx_user > text.index("chpasswd")
    assert idx_user > text.index("curl")


def test_rejects_shebang_in_custom_script():
    with pytest.raises(ScriptError, match="不要以"):
        render(ScriptOptions(custom_script="#!/bin/bash\necho hi"))
    with pytest.raises(ScriptError):
        validate("  #!/bin/sh\nls")
    with pytest.raises(ScriptError):
        validate("#cloud-config\nruncmd: []")


def test_no_root_password_means_no_ssh_change():
    text = render(ScriptOptions(custom_script="echo hi"))
    assert "chpasswd" not in text
    assert "PermitRootLogin" not in text


def test_root_password_enables_login():
    text = render(ScriptOptions(root_password="S3cret"))
    assert "echo 'root:S3cret' | chpasswd" in text
    assert "PermitRootLogin yes" in text
    assert "PasswordAuthentication yes" in text
    # 不应整体删除 sshd_config —— azpanel 的做法会连 sftp 配置一起丢
    assert "rm -rf /etc/ssh/sshd_config" not in text


def test_password_with_quote_is_escaped():
    """密码含单引号时，实际交给 shell 的值必须还原成原始密码。

    用真实 bash 执行渲染出的那一行来验证，而不是数引号个数。
    """
    import subprocess

    text = render(ScriptOptions(root_password="pa'ss"))
    line = [l for l in text.splitlines() if "chpasswd" in l][0]
    echo_only = line.replace("| chpasswd", "")
    out = subprocess.run(
        ["bash", "-c", echo_only], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "root:pa'ss"


def test_hostname_sanitized():
    text = render(ScriptOptions(hostname="my host;rm -rf /"))
    assert ";rm" not in text
    assert "rm -rf /" not in text
    assert "my-host-rm--rf" in text


def test_hostname_length_capped():
    text = render(ScriptOptions(hostname="a" * 200))
    line = [l for l in text.splitlines() if "set-hostname" in l][0]
    name = line.split("set-hostname ")[1].split()[0]
    assert len(name) <= 63


def test_packages_multi_distro():
    text = render(ScriptOptions(packages=["curl", "vim"]))
    assert "apt-get install -y curl vim" in text
    assert "dnf install -y curl vim" in text
    assert "yum install -y curl vim" in text


def test_illegal_package_rejected():
    with pytest.raises(ScriptError, match="非法软件包名"):
        render(ScriptOptions(packages=["; rm -rf /"]))


def test_empty_options_still_valid_script():
    text = render(ScriptOptions())
    assert text.startswith("#!/bin/bash")
    assert len(text.strip().splitlines()) >= 2


def test_render_b64_roundtrip():
    opts = ScriptOptions(custom_script="echo b64")
    assert base64.b64decode(render_b64(opts)).decode() == render(opts)
