"""重装系统（换根卷）。

这是个不可逆的破坏性操作，所以测试重点在两头：
- 前置校验要挡住会做坏事的组合（架构不匹配、instance-store 根卷、已终止实例）
- 失败状态要说清后果，尤其 failed-detached —— 实例会没有可启动的根卷

ReplaceRootVolume 系列 API moto 没实现，所以这些用 stub；
preflight 里的 DescribeInstances / DescribeImages 走真实 moto 调用。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
import pytest

from aws_helper.core import aws, reinstall

CREDS = aws.Credentials("testing", "testing", "us-east-1")
IID = "i-0abc0000000000001"


def _instance(**over):
    info = {
        "InstanceId": IID,
        "State": {"Name": "running"},
        "Architecture": "x86_64",
        "RootDeviceType": "ebs",
        "RootDeviceName": "/dev/sda1",
        "ImageId": "ami-original",
        "PrivateIpAddress": "10.0.0.5",
        "PublicIpAddress": "1.2.3.4",
        "BlockDeviceMappings": [{"DeviceName": "/dev/sda1"}],
    }
    info.update(over)
    return {"Reservations": [{"Instances": [info]}]}


def _stub_session(instance=None, images=None):
    session = MagicMock()
    session.describe_instances.return_value = instance or _instance()
    session.describe_images.return_value = {"Images": images or []}
    return session


# ---------- 前置校验 ----------


def test_terminated_instance_rejected():
    session = _stub_session(_instance(State={"Name": "terminated"}))
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.preflight(CREDS, "us-east-1", IID)
    assert out["ok"] is False
    assert any("已终止" in p for p in out["problems"])


def test_instance_store_root_rejected():
    """instance-store 的根卷是临时盘，没有卷可以替换。"""
    session = _stub_session(_instance(RootDeviceType="instance-store"))
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.preflight(CREDS, "us-east-1", IID)
    assert out["ok"] is False
    assert any("instance-store" in p for p in out["problems"])


def test_arch_mismatch_rejected():
    """架构不匹配必须挡住。

    x86 实例铺 ARM 镜像时 AWS 会接受请求，但换完实例起不来，
    且没有明显报错 —— 用户只看到一台连不上的机器。
    """
    session = _stub_session(images=[{"ImageId": "ami-arm", "Architecture": "arm64"}])
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.preflight(CREDS, "us-east-1", IID, image_id="ami-arm")

    assert out["ok"] is False
    problem = "；".join(out["problems"])
    assert "arm64" in problem and "x86_64" in problem
    assert "起不来" in problem


def test_matching_arch_accepted():
    session = _stub_session(images=[{"ImageId": "ami-x86", "Architecture": "x86_64"}])
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.preflight(CREDS, "us-east-1", IID, image_id="ami-x86")
    assert out["ok"] is True
    assert out["target_image_id"] == "ami-x86"


def test_missing_image_rejected():
    session = _stub_session(images=[])
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.preflight(CREDS, "us-east-1", IID, image_id="ami-nope")
    assert out["ok"] is False
    assert any("不存在" in p for p in out["problems"])


def test_no_image_means_reflash_original():
    """不指定镜像 = 用原 AMI 重铺，这是"恢复出厂"。"""
    session = _stub_session()
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.preflight(CREDS, "us-east-1", IID)
    assert out["ok"] is True
    assert out["target_image_id"] == ""
    assert out["current_image_id"] == "ami-original"


def test_extra_volumes_listed():
    """数据卷会原样保留，页面要能列出来，否则用户不敢点。"""
    session = _stub_session(
        _instance(
            BlockDeviceMappings=[
                {"DeviceName": "/dev/sda1"},
                {"DeviceName": "/dev/sdf"},
                {"DeviceName": "/dev/sdg"},
            ]
        )
    )
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.preflight(CREDS, "us-east-1", IID)
    assert out["extra_volumes"] == ["/dev/sdf", "/dev/sdg"]


def test_root_volume_not_counted_as_extra():
    session = _stub_session(_instance(BlockDeviceMappings=[{"DeviceName": "/dev/sda1"}]))
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.preflight(CREDS, "us-east-1", IID)
    assert out["extra_volumes"] == []


def test_unknown_instance_raises():
    session = MagicMock()
    session.describe_instances.return_value = {"Reservations": []}
    with patch.object(reinstall.aws, "ec2", return_value=session):
        with pytest.raises(reinstall.ReinstallError, match="找不到实例"):
            reinstall.preflight(CREDS, "us-east-1", IID)


# ---------- 真实 EC2 调用（moto） ----------


def test_preflight_against_real_ec2(mock_ec2):
    """preflight 的 DescribeInstances/DescribeImages 走真实调用。"""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    started = ec2.run_instances(
        ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro"
    )
    iid = started["Instances"][0]["InstanceId"]

    out = reinstall.preflight(CREDS, "us-east-1", iid)
    assert out["ok"] is True
    assert out["root_device_type"] == "ebs"
    assert out["architecture"] in ("x86_64", "arm64", "i386")
    assert out["private_ip"]


def test_arch_mismatch_against_real_images(mock_ec2):
    """用 moto 的真实镜像清单验架构校验，不是自己编的假数据。"""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    images = ec2.describe_images(Owners=["amazon"])["Images"]
    x86 = next(i for i in images if i.get("Architecture") == "x86_64")
    arm = next((i for i in images if i.get("Architecture") == "arm64"), None)
    if arm is None:
        pytest.skip("moto 镜像里没有 arm64")

    started = ec2.run_instances(
        ImageId=x86["ImageId"], MinCount=1, MaxCount=1, InstanceType="t3.micro"
    )
    iid = started["Instances"][0]["InstanceId"]

    out = reinstall.preflight(CREDS, "us-east-1", iid, image_id=arm["ImageId"])
    assert out["ok"] is False
    assert any("不匹配" in p for p in out["problems"])


# ---------- 下发与轮询 ----------


def _reinstall_session(states, task_id="rrvt-1", **instance_over):
    session = _stub_session(_instance(**instance_over) if instance_over else None)
    session.create_replace_root_volume_task.return_value = {
        "ReplaceRootVolumeTask": {"ReplaceRootVolumeTaskId": task_id, "TaskState": "pending"}
    }
    session.describe_replace_root_volume_tasks.side_effect = [
        {"ReplaceRootVolumeTasks": [{"ReplaceRootVolumeTaskId": task_id, "TaskState": s,
                                     "ImageId": "ami-new"}]}
        for s in states
    ]
    return session


def test_successful_reinstall_returns_summary(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["pending", "in-progress", "succeeded"])
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.reinstall(CREDS, "us-east-1", IID)

    assert out["state"] == "succeeded"
    assert out["task_id"] == "rrvt-1"
    assert out["private_ip"] == "10.0.0.5"
    assert out["public_ip"] == "1.2.3.4"


def test_omits_image_id_when_reflashing(monkeypatch):
    """恢复出厂时不能传 ImageId —— 传了就变成指定镜像了。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"])
    with patch.object(reinstall.aws, "ec2", return_value=session):
        reinstall.reinstall(CREDS, "us-east-1", IID)
        kwargs = session.create_replace_root_volume_task.call_args.kwargs

    assert "ImageId" not in kwargs
    assert kwargs["InstanceId"] == IID


def test_passes_image_id_when_switching(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"])
    session.describe_images.return_value = {
        "Images": [{"ImageId": "ami-x86", "Architecture": "x86_64"}]
    }
    with patch.object(reinstall.aws, "ec2", return_value=session):
        reinstall.reinstall(CREDS, "us-east-1", IID, image_id="ami-x86")
        kwargs = session.create_replace_root_volume_task.call_args.kwargs

    assert kwargs["ImageId"] == "ami-x86"


def test_delete_old_volume_flag_forwarded(monkeypatch):
    """旧卷不删会一直按 EBS 容量计费，这个开关必须真的传下去。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    for flag in (True, False):
        session = _reinstall_session(["succeeded"])
        with patch.object(reinstall.aws, "ec2", return_value=session):
            reinstall.reinstall(CREDS, "us-east-1", IID, delete_old_volume=flag)
            kwargs = session.create_replace_root_volume_task.call_args.kwargs
        assert kwargs["DeleteReplacedRootVolume"] is flag


def test_preflight_failure_blocks_send(monkeypatch):
    """校验不过就不该下发任务。"""
    session = _stub_session(_instance(State={"Name": "terminated"}))
    with patch.object(reinstall.aws, "ec2", return_value=session):
        with pytest.raises(reinstall.ReinstallError, match="已终止"):
            reinstall.reinstall(CREDS, "us-east-1", IID)
        assert session.create_replace_root_volume_task.call_count == 0


def test_failed_detached_explains_consequence(monkeypatch):
    """failed-detached 是最危险的状态：实例现在没有根卷。

    只报"失败"会让用户以为没事发生，实际上机器已经起不来了。
    """
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["in-progress", "failed-detached"])
    with patch.object(reinstall.aws, "ec2", return_value=session):
        with pytest.raises(reinstall.ReinstallError) as err:
            reinstall.reinstall(CREDS, "us-east-1", IID)

    message = str(err.value)
    assert "failed-detached" in message
    assert "没有可启动的根卷" in message
    assert "快照恢复" in message


def test_plain_failure_reported(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["failed"])
    with patch.object(reinstall.aws, "ec2", return_value=session):
        with pytest.raises(reinstall.ReinstallError, match="重装失败（failed）"):
            reinstall.reinstall(CREDS, "us-east-1", IID)


def test_timeout_mentions_task_still_running(monkeypatch):
    """超时不等于失败 —— 任务还在后台跑，别让用户以为要重来。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    monkeypatch.setattr(reinstall, "_TASK_TIMEOUT", 0.05)
    session = _stub_session()
    session.create_replace_root_volume_task.return_value = {
        "ReplaceRootVolumeTask": {"ReplaceRootVolumeTaskId": "rrvt-9"}
    }
    session.describe_replace_root_volume_tasks.return_value = {
        "ReplaceRootVolumeTasks": [{"TaskState": "in-progress"}]
    }
    with patch.object(reinstall.aws, "ec2", return_value=session):
        with pytest.raises(reinstall.ReinstallError) as err:
            reinstall.reinstall(CREDS, "us-east-1", IID)

    assert "仍在后台跑" in str(err.value)
    assert "rrvt-9" in str(err.value)


def test_missing_task_id_is_error(monkeypatch):
    session = _stub_session()
    session.create_replace_root_volume_task.return_value = {"ReplaceRootVolumeTask": {}}
    with patch.object(reinstall.aws, "ec2", return_value=session):
        with pytest.raises(reinstall.ReinstallError, match="没有返回重装任务 ID"):
            reinstall.reinstall(CREDS, "us-east-1", IID)


def test_progress_reports_states(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    seen: list[str] = []
    session = _reinstall_session(["in-progress", "succeeded"])
    with patch.object(reinstall.aws, "ec2", return_value=session):
        reinstall.reinstall(CREDS, "us-east-1", IID, progress=seen.append)

    joined = " ".join(seen)
    assert "检查重装前提" in joined
    assert "in-progress" in joined
    assert "重启" in joined, "要提醒用户实例会重启"


def test_elapsed_recorded(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"])
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.reinstall(CREDS, "us-east-1", IID)
    assert isinstance(out["elapsed_sec"], int)


def test_preflight_page_reads_body_not_api_helper():
    """预检失败时页面必须显示具体原因。

    api() 把 ok:false 当异常抛，而预检的 ok:false 是正常结果（"不能重装，
    原因如下"）。走 api() 的话用户只看到一句"检查失败 HTTP 200" ——
    真机上就是这样，架构不匹配的具体原因被吞掉了。
    """
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    block = html[html.index("async function riPreflight"):]
    block = block[: block.index("async function doReinstall")]

    assert "await fetch(`/api/instances/reinstall-preflight" in block, "应直接 fetch"
    assert "await api(`/api/instances/reinstall-preflight" not in block, (
        "不能走 api()，它会把 ok:false 的具体原因吞成 HTTP 200"
    )
    assert "d.problems" in block, "要把 problems 显示出来"


# ---------- 重装后的连接信息 ----------


def test_result_includes_ssh_command(monkeypatch):
    """重装完必须给出 SSH 命令。

    只回一句"重装完成"用户还得自己去查新系统的默认用户是什么 ——
    这正是用户报的问题："重装后的 ssh 信息没有"。
    """
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"], KeyName="mykey")
    session.describe_images.return_value = {
        "Images": [
            {
                "ImageId": "ami-x86",
                "Architecture": "x86_64",
                "Name": "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-1",
            }
        ]
    }
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.reinstall(CREDS, "us-east-1", IID, image_id="ami-x86")

    assert out["ssh_user"] == "ubuntu"
    assert out["key_name"] == "mykey"
    assert out["ssh_command"] == "ssh -i mykey.pem ubuntu@1.2.3.4"


def test_ssh_user_from_builtin_image_key(monkeypatch):
    """选内置镜像时用它声明的用户，不靠猜。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"], KeyName="k1")
    session.describe_images.return_value = {
        "Images": [{"ImageId": "ami-deb", "Architecture": "x86_64", "Name": "whatever"}]
    }
    with patch.object(reinstall.aws, "ec2", return_value=session), patch.object(
        reinstall.aws, "resolve_ami", return_value="ami-deb"
    ):
        out = reinstall.reinstall(CREDS, "us-east-1", IID, image_key="debian-12")

    assert out["ssh_user"] == "admin", "Debian 的默认用户是 admin 不是 ubuntu"


def test_reflash_resolves_ssh_user_from_current_image(monkeypatch):
    """恢复出厂时没有 image_key，要去查实例当前镜像的名字来推断用户。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"], KeyName="k1")
    session.describe_images.return_value = {
        "Images": [
            {
                "ImageId": "ami-original",
                "Architecture": "x86_64",
                "Name": "al2023-ami-2026.0.20260101-kernel-6.1-x86_64",
            }
        ]
    }
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.reinstall(CREDS, "us-east-1", IID)

    assert out["ssh_user"] == "ec2-user"


def test_unknown_image_leaves_ssh_user_blank(monkeypatch):
    """认不出来就留空，别给一个错的用户名让用户白试。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"], KeyName="k1")
    session.describe_images.return_value = {
        "Images": [
            {"ImageId": "ami-x", "Architecture": "x86_64", "Name": "my-custom-golden-image"}
        ]
    }
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.reinstall(CREDS, "us-east-1", IID)

    assert out["ssh_user"] == ""
    assert "<登录用户>" in out["ssh_command"], "用户名未知时要留占位符提示"


def test_windows_gets_rdp_instead_of_ssh(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"], KeyName="k1")
    session.describe_images.return_value = {
        "Images": [
            {
                "ImageId": "ami-win",
                "Architecture": "x86_64",
                "Name": "Windows_Server-2025-English-Full-Base",
                "Platform": "windows",
            }
        ]
    }
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.reinstall(CREDS, "us-east-1", IID, image_id="ami-win")

    assert out["os_family"] == "windows"
    assert out["ssh_command"].startswith("RDP 1.2.3.4:3389")
    assert out["known_hosts_hint"] == "", "Windows 没有 known_hosts 的问题"


def test_no_public_ip_says_so(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"], PublicIpAddress=None, KeyName="k1")
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.reinstall(CREDS, "us-east-1", IID)

    assert "无公网 IP" in out["ssh_command"]
    assert out["known_hosts_hint"] == ""


def test_known_hosts_hint_provided(monkeypatch):
    """主机密钥随根卷重建，旧 known_hosts 记录会让连接被拒。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"], KeyName="k1")
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.reinstall(CREDS, "us-east-1", IID)

    assert out["known_hosts_hint"] == "ssh-keygen -R 1.2.3.4"


def test_key_name_preserved_across_reinstall(monkeypatch):
    """换根卷不动实例的 KeyName，原私钥仍然可用 —— 页面要这么告诉用户。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"], KeyName="prod-key")
    with patch.object(reinstall.aws, "ec2", return_value=session):
        out = reinstall.reinstall(CREDS, "us-east-1", IID)

    assert out["key_name"] == "prod-key"
    assert "prod-key.pem" in out["ssh_command"]


@pytest.mark.parametrize(
    "image_name,expected",
    [
        ("ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-1", "ubuntu"),
        ("debian-12-amd64-20260101-1234", "admin"),
        ("al2023-ami-2026.0.20260101-kernel-6.1-x86_64", "ec2-user"),
        ("amzn2-ami-hvm-2.0.20260101-x86_64-gp2", "ec2-user"),
        ("RHEL-9.4_HVM-20260101-x86_64-0-Hourly2-GP3", "ec2-user"),
        ("Fedora-Cloud-Base-40-1.14.x86_64", "fedora"),
        ("CentOS-Stream-ec2-9-20260101.0.x86_64", "centos"),
        ("Rocky-9-EC2-Base-9.4-20260101.0.x86_64", "rocky"),
        ("suse-sles-15-sp6-v20260101-hvm-ssd-x86_64", "ec2-user"),
        ("my-own-golden-image-v3", ""),
    ],
)
def test_ssh_user_guessing(image_name, expected):
    assert reinstall._guess_ssh_user(image_name, "") == expected


def test_windows_platform_overrides_name_guess():
    """Platform=windows 优先于名字匹配。"""
    assert reinstall._guess_ssh_user("some-ubuntu-flavored-name", "windows") == "Administrator"


def test_page_renders_ssh_command_after_reinstall():
    """页面必须把 SSH 命令渲染出来，而不只是显示镜像 id 和耗时。"""
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    assert "function showReinstallResult" in html
    block = html[html.index("function showReinstallResult"):]
    block = block[: block.index("let PW_TARGET")]

    for field in ("ssh_command", "ssh_user", "key_name", "known_hosts_hint"):
        assert f"d.{field}" in block, f"结果面板没有用到 {field}"
    assert "原私钥继续可用" in block


# ---------- 重装后设置凭据 ----------

REAL_ED25519 = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIMxGgW4kZ8HLmGpQnbnFhc6TThRRW3TnkS1EYQ8jSJZG"
    " me@laptop"
)


def _online_ssm():
    client = MagicMock()
    client.describe_instance_information.return_value = {
        "InstanceInformationList": [
            {"InstanceId": IID, "PingStatus": "Online", "PlatformType": "Linux"}
        ]
    }
    client.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    client.get_command_invocation.return_value = {"Status": "Success"}
    return client


def test_no_credentials_means_no_ssm_call(monkeypatch):
    """不改凭据时一次 SSM 都不该调 —— 大多数实例没挂实例配置文件。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"])
    with patch.object(reinstall.aws, "ec2", return_value=session), \
            patch("aws_helper.core.respw._ssm") as factory:
        out = reinstall.reinstall(CREDS, "us-east-1", IID)
        factory.assert_not_called()

    assert out["creds_applied"] is False
    assert out["set_password"] is False


def test_password_applied_after_reinstall(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    monkeypatch.setattr("aws_helper.core.respw._POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"])
    ssm = _online_ssm()
    with patch.object(reinstall.aws, "ec2", return_value=session), \
            patch("aws_helper.core.respw._ssm", return_value=ssm):
        out = reinstall.reinstall(
            CREDS, "us-east-1", IID, new_password="Str0ng!Pass1"
        )
        script = ssm.send_command.call_args.kwargs["Parameters"]["commands"][0]

    assert out["creds_applied"] is True
    assert out["set_password"] is True
    assert out["login_user"] == "root"
    assert "chpasswd" in script


def test_public_key_applied_after_reinstall(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    monkeypatch.setattr("aws_helper.core.respw._POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"])
    ssm = _online_ssm()
    with patch.object(reinstall.aws, "ec2", return_value=session), \
            patch("aws_helper.core.respw._ssm", return_value=ssm):
        out = reinstall.reinstall(
            CREDS, "us-east-1", IID, new_public_key=REAL_ED25519
        )
        script = ssm.send_command.call_args.kwargs["Parameters"]["commands"][0]

    assert out["set_public_key"] is True
    assert "authorized_keys" in script


def test_credentials_applied_only_after_success(monkeypatch):
    """重装失败就不该去设凭据 —— 那台机器可能根本没有根卷。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["failed"])
    with patch.object(reinstall.aws, "ec2", return_value=session), \
            patch("aws_helper.core.respw._ssm") as factory:
        with pytest.raises(reinstall.ReinstallError):
            reinstall.reinstall(CREDS, "us-east-1", IID, new_password="Str0ng!Pass1")
        factory.assert_not_called()


def test_agent_never_returns_does_not_fail_reinstall(monkeypatch):
    """根卷已经换好了，Agent 没回来只是凭据没设上，不能算重装失败。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    monkeypatch.setattr(reinstall, "_AGENT_WAIT", 0)
    monkeypatch.setattr(reinstall, "_AGENT_POLL", 0)
    session = _reinstall_session(["succeeded"])
    offline = MagicMock()
    offline.describe_instance_information.return_value = {"InstanceInformationList": []}
    with patch.object(reinstall.aws, "ec2", return_value=session), \
            patch("aws_helper.core.respw._ssm", return_value=offline):
        out = reinstall.reinstall(CREDS, "us-east-1", IID, new_password="Str0ng!Pass1")

    assert out["state"] == "succeeded"
    assert out["creds_applied"] is False
    assert "重置密码" in out["creds_note"]


def test_credential_failure_surfaces_reason(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    monkeypatch.setattr("aws_helper.core.respw._POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"])
    ssm = _online_ssm()
    ssm.get_command_invocation.return_value = {
        "Status": "Failed",
        "StandardErrorContent": "sshd -t 校验失败",
    }
    with patch.object(reinstall.aws, "ec2", return_value=session), \
            patch("aws_helper.core.respw._ssm", return_value=ssm):
        out = reinstall.reinstall(CREDS, "us-east-1", IID, new_password="Str0ng!Pass1")

    assert out["state"] == "succeeded"
    assert out["creds_applied"] is False
    assert "sshd -t" in out["creds_note"]


def test_password_never_in_result(monkeypatch):
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    monkeypatch.setattr("aws_helper.core.respw._POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"])
    with patch.object(reinstall.aws, "ec2", return_value=session), \
            patch("aws_helper.core.respw._ssm", return_value=_online_ssm()):
        out = reinstall.reinstall(
            CREDS, "us-east-1", IID, new_password="TopSecret9!"
        )

    assert "TopSecret9!" not in str(out)


def test_ssh_command_reflects_password_login(monkeypatch):
    """设了密码就不用再提示 -i 私钥，否则用户以为还得找密钥文件。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    monkeypatch.setattr("aws_helper.core.respw._POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"])
    with patch.object(reinstall.aws, "ec2", return_value=session), \
            patch("aws_helper.core.respw._ssm", return_value=_online_ssm()):
        out = reinstall.reinstall(
            CREDS, "us-east-1", IID, new_password="Str0ng!Pass1"
        )

    assert out["ssh_command"] == "ssh root@1.2.3.4"
    assert ".pem" not in out["ssh_command"]


def test_invalid_public_key_rejected_before_reinstall(monkeypatch):
    """公钥不合法要在换根卷之前就挡住 —— 卷换完了再报错已经不可逆。"""
    monkeypatch.setattr(reinstall, "_POLL_INTERVAL", 0)
    session = _reinstall_session(["succeeded"])
    with patch.object(reinstall.aws, "ec2", return_value=session), \
            patch("aws_helper.core.respw._ssm", return_value=_online_ssm()):
        with pytest.raises(Exception):
            reinstall.reinstall(
                CREDS, "us-east-1", IID, new_public_key="ssh-ed25519 bogus!!"
            )
