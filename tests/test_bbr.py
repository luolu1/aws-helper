"""BBR 脚本与开机勾选的测试。"""

from __future__ import annotations

import subprocess

import pytest

from aws_helper.core import bbr


def _run(script: str, sysctl_path: str) -> subprocess.CompletedProcess[str]:
    """把脚本里的 sysctl 目标改到临时路径后真的执行一遍。"""
    body = script.replace(bbr.SYSCTL_PATH, sysctl_path)
    return subprocess.run(
        ["bash", "-c", body], capture_output=True, text=True, timeout=30
    )


def test_script_is_valid_bash():
    out = subprocess.run(
        ["bash", "-n"], input=bbr.render(), capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr


def test_script_does_not_replace_kernel():
    """网上的 BBR 一键脚本大多在换内核。换内核要重启、可能起不来，
    不该在开机脚本里悄悄干 —— 面板用的镜像内核都在 5.10 以上，
    BBR 早就编译进去了。
    """
    body = bbr.render()
    for forbidden in ("apt-get install -y linux-image", "grub", "reboot", "dpkg -i"):
        assert forbidden not in body, forbidden


def test_script_sets_both_qdisc_and_algorithm():
    """只设 congestion_control 不设 qdisc 时 BBR 效果打折 ——
    BBR 依赖发包时机（pacing），pfifo_fast 没有这个能力。
    """
    body = bbr.render()
    assert "net.core.default_qdisc = fq" in body
    assert "net.ipv4.tcp_congestion_control = bbr" in body


def test_script_exits_cleanly_when_kernel_lacks_bbr(tmp_path):
    """内核不支持时要跳过并说明，不能让整段开机脚本失败。"""
    conf = tmp_path / "bbr.conf"
    body = bbr.render().replace(bbr.SYSCTL_PATH, str(conf))
    # 让探测拿不到 bbr：把 sysctl 换成一个只回 cubic 的假命令
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "sysctl").write_text(
        "#!/bin/bash\n"
        'if [ "$1" = "net.ipv4.tcp_available_congestion_control" ]; then\n'
        '  echo "net.ipv4.tcp_available_congestion_control = reno cubic"; exit 0\n'
        "fi\n"
        'if [ "$1" = "-n" ]; then echo cubic; exit 0; fi\n'
        "exit 0\n"
    )
    (stub / "sysctl").chmod(0o755)
    (stub / "modprobe").write_text("#!/bin/bash\nexit 1\n")
    (stub / "modprobe").chmod(0o755)

    out = subprocess.run(
        ["bash", "-c", body],
        capture_output=True,
        text=True,
        env={"PATH": f"{stub}:/usr/bin:/bin"},
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    assert "不支持 BBR" in out.stderr
    assert not conf.exists(), "内核不支持时不该写配置文件"


def test_script_reports_failure_when_not_applied(tmp_path):
    """写进配置文件不等于内核接受了它，必须回读校验。"""
    conf = tmp_path / "bbr.conf"
    body = bbr.render().replace(bbr.SYSCTL_PATH, str(conf))
    stub = tmp_path / "bin"
    stub.mkdir()
    # 声称支持 bbr，但设置后回读仍是 cubic —— 模拟设置没生效
    (stub / "sysctl").write_text(
        "#!/bin/bash\n"
        'if [ "$1" = "net.ipv4.tcp_available_congestion_control" ]; then\n'
        '  echo "net.ipv4.tcp_available_congestion_control = reno cubic bbr"; exit 0\n'
        "fi\n"
        'if [ "$1" = "-n" ]; then echo cubic; exit 0; fi\n'
        "exit 0\n"
    )
    (stub / "sysctl").chmod(0o755)
    (stub / "modprobe").write_text("#!/bin/bash\nexit 0\n")
    (stub / "modprobe").chmod(0o755)

    out = subprocess.run(
        ["bash", "-c", body],
        capture_output=True,
        text=True,
        env={"PATH": f"{stub}:/usr/bin:/bin"},
        timeout=30,
    )
    assert "开启失败" in out.stderr
    assert "cubic" in out.stderr


def test_script_confirms_success_by_reading_back(tmp_path):
    """成功路径也要回读确认，不能写完就报成功。"""
    conf = tmp_path / "bbr.conf"
    body = bbr.render().replace(bbr.SYSCTL_PATH, str(conf))
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "sysctl").write_text(
        "#!/bin/bash\n"
        'if [ "$1" = "net.ipv4.tcp_available_congestion_control" ]; then\n'
        '  echo "net.ipv4.tcp_available_congestion_control = reno cubic bbr"; exit 0\n'
        "fi\n"
        'if [ "$1" = "-n" ] && [ "$2" = "net.ipv4.tcp_congestion_control" ]; then\n'
        "  echo bbr; exit 0\n"
        "fi\n"
        'if [ "$1" = "-n" ]; then echo fq; exit 0; fi\n'
        "exit 0\n"
    )
    (stub / "sysctl").chmod(0o755)
    (stub / "modprobe").write_text("#!/bin/bash\nexit 0\n")
    (stub / "modprobe").chmod(0o755)

    out = subprocess.run(
        ["bash", "-c", body],
        capture_output=True,
        text=True,
        env={"PATH": f"{stub}:/usr/bin:/bin"},
        timeout=30,
    )
    assert "BBR 已开启" in out.stdout
    assert conf.read_text().count("bbr") == 1


def test_script_is_idempotent(tmp_path):
    """开机脚本可能被重复执行（重装、重跑），配置不能越堆越多。"""
    conf = tmp_path / "bbr.conf"
    body = bbr.render().replace(bbr.SYSCTL_PATH, str(conf))
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "sysctl").write_text(
        "#!/bin/bash\n"
        'if [ "$1" = "net.ipv4.tcp_available_congestion_control" ]; then\n'
        '  echo "net.ipv4.tcp_available_congestion_control = bbr"; exit 0\n'
        "fi\n"
        'if [ "$1" = "-n" ]; then echo bbr; exit 0; fi\n'
        "exit 0\n"
    )
    (stub / "sysctl").chmod(0o755)
    (stub / "modprobe").write_text("#!/bin/bash\nexit 0\n")
    (stub / "modprobe").chmod(0o755)
    env = {"PATH": f"{stub}:/usr/bin:/bin"}

    for _ in range(3):
        subprocess.run(["bash", "-c", body], capture_output=True, env=env, timeout=30)

    assert conf.read_text().strip().count("\n") == 1, conf.read_text()


def test_unsupported_bbr_does_not_stop_following_user_script(tmp_path):
    """BBR 段被内联在用户脚本前，不能用 exit 0 结束整个 user-data。"""
    from aws_helper.core.userdata import ScriptOptions, render

    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "sysctl").write_text(
        "#!/bin/bash\n"
        'if [ "$1" = "net.ipv4.tcp_available_congestion_control" ]; then\n'
        '  echo "net.ipv4.tcp_available_congestion_control = reno cubic"; exit 0\n'
        "fi\n"
        "exit 0\n"
    )
    (stub / "sysctl").chmod(0o755)
    (stub / "modprobe").write_text("#!/bin/bash\nexit 1\n")
    (stub / "modprobe").chmod(0o755)

    out = subprocess.run(
        ["bash", "-c", render(ScriptOptions(
            custom_script="echo USER_SCRIPT_RAN", deploy_blocks=[bbr.render()]
        ))],
        capture_output=True,
        text=True,
        env={"PATH": f"{stub}:/usr/bin:/bin"},
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    assert "当前内核不支持 BBR" in out.stderr
    assert "USER_SCRIPT_RAN" in out.stdout
