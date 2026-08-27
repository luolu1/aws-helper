"""镜像 AMI 解析：SSM 公共参数优先，名称匹配兜底。"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from aws_helper.core import aws


@pytest.fixture
def moto_image(mock_ec2, creds):
    session = aws.ec2(creds)
    return session, session.describe_images(Owners=["099720109477"])["Images"][0]


# ---------- 镜像清单本身 ----------


def test_all_images_have_patterns():
    for key, spec in aws.IMAGES.items():
        assert spec.name_patterns, f"{key} 没有名称匹配兜底"
        assert spec.owner, f"{key} 没有 owner"
        assert spec.label, f"{key} 没有展示名"


def test_ubuntu_uses_canonical_ssm_parameter():
    """Ubuntu 必须走 Canonical 官方 SSM 参数，路径格式按官方文档。"""
    spec = aws.IMAGES["ubuntu-24.04"]
    assert spec.ssm_parameter == (
        "/aws/service/canonical/ubuntu/server/24.04/stable/current"
        "/amd64/hvm/ebs-gp3/ami-id"
    )
    assert spec.owner == "099720109477"


def test_arm_images_declare_arm64():
    for key in ("ubuntu-24.04-arm", "ubuntu-22.04-arm", "debian-12-arm", "al2023-arm"):
        assert aws.IMAGES[key].arch == "arm64", key


def test_noble_patterns_cover_gp3_naming():
    """24.04 起 Canonical 从 hvm-ssd 改成 hvm-ssd-gp3，两种都要覆盖。

    原来只有一个 hvm-ssd* 通配，在部分区域匹配不到导致开机失败。
    """
    patterns = aws.IMAGES["ubuntu-24.04"].name_patterns
    assert any("hvm-ssd-gp3" in p for p in patterns)
    assert any("hvm-ssd/" in p for p in patterns)
    assert len(patterns) >= 2


def test_ssh_users_match_distro():
    assert aws.IMAGES["ubuntu-24.04"].ssh_user == "ubuntu"
    assert aws.IMAGES["debian-12"].ssh_user == "admin"
    assert aws.IMAGES["al2023"].ssh_user == "ec2-user"


# ---------- 解析顺序 ----------


def test_ssm_result_takes_precedence(moto_image, creds):
    session, _ = moto_image
    with patch.object(aws, "_resolve_via_ssm", return_value="ami-fromssm0001") as m:
        assert (
            aws.resolve_ami(session, "ubuntu-24.04", creds, "us-east-1")
            == "ami-fromssm0001"
        )
    assert m.called


def test_falls_back_to_name_match_when_ssm_fails(moto_image, creds, monkeypatch):
    """SSM 不可用（IAM 缺权限、区域无参数）时必须仍能开机。"""
    session, img = moto_image
    monkeypatch.setitem(
        aws.IMAGES,
        "ubuntu-24.04",
        aws.ImageSpec(
            label="probe",
            owner=img["OwnerId"],
            ssm_parameter="/nonexistent/param",
            name_patterns=(img["Name"],),
        ),
    )
    with patch.object(aws, "_resolve_via_ssm", return_value=None):
        assert (
            aws.resolve_ami(session, "ubuntu-24.04", creds, "us-east-1")
            == img["ImageId"]
        )


def test_tries_patterns_in_order(moto_image, creds, monkeypatch):
    """第一个 pattern 匹配不到要继续试下一个，而不是直接报错。"""
    session, img = moto_image
    monkeypatch.setitem(
        aws.IMAGES,
        "ubuntu-24.04",
        aws.ImageSpec(
            label="probe",
            owner=img["OwnerId"],
            name_patterns=("绝对匹配不到-*", "也匹配不到-*", img["Name"]),
        ),
    )
    assert aws.resolve_ami(session, "ubuntu-24.04", creds) == img["ImageId"]


def test_works_without_credentials(moto_image, monkeypatch):
    """不传 creds 时跳过 SSM，靠名称匹配工作。"""
    session, img = moto_image
    monkeypatch.setitem(
        aws.IMAGES,
        "ubuntu-24.04",
        aws.ImageSpec(
            label="probe", owner=img["OwnerId"], name_patterns=(img["Name"],)
        ),
    )
    assert aws.resolve_ami(session, "ubuntu-24.04") == img["ImageId"]


def test_ssm_failure_is_swallowed(mock_ec2, creds):
    """SSM 报错不能冒泡出来打断开机流程。"""
    assert aws._resolve_via_ssm(creds, "us-east-1", "/definitely/not/exist") is None


def test_ssm_rejects_non_ami_value(mock_ec2, creds):
    fake = {"Parameter": {"Value": "not-an-ami"}}
    with patch.object(aws, "client") as m:
        m.return_value.get_parameter.return_value = fake
        assert aws._resolve_via_ssm(creds, "us-east-1", "/some/param") is None


# ---------- 报错质量 ----------


def test_error_lists_tried_patterns(moto_image, creds, monkeypatch):
    """报错要说清试过什么、以及怎么绕过 —— 光说"找不到"没法排查。"""
    session, _ = moto_image
    monkeypatch.setitem(
        aws.IMAGES,
        "ubuntu-24.04",
        aws.ImageSpec(
            label="Ubuntu 24.04 LTS",
            owner="099720109477",
            ssm_parameter="/fake/param",
            name_patterns=("pattern-a-*", "pattern-b-*"),
        ),
    )
    with patch.object(aws, "_resolve_via_ssm", return_value=None):
        with pytest.raises(LookupError) as excinfo:
            aws.resolve_ami(session, "ubuntu-24.04", creds, "us-east-1")

    message = str(excinfo.value)
    assert "Ubuntu 24.04 LTS" in message
    assert "pattern-a-*" in message
    assert "pattern-b-*" in message
    assert "指定 AMI ID" in message


def test_unknown_image_key_rejected(moto_image, creds):
    session, _ = moto_image
    with pytest.raises(LookupError, match="未知镜像"):
        aws.resolve_ami(session, "windows-11", creds)


# ---------- 与开机流程集成 ----------


def test_launch_passes_credentials_for_ssm(mock_ec2, creds, ubuntu_ami):
    """launch 必须把 creds 传给 resolve_ami，否则 SSM 分支永远走不到。"""
    from aws_helper.core import launch

    with patch.object(aws, "resolve_ami", wraps=aws.resolve_ami) as spy:
        launch.launch(creds, launch.LaunchRequest(name="ssm-arg", region="us-east-1"))

    assert spy.called
    args = spy.call_args[0]
    assert len(args) >= 3, "resolve_ami 没收到 creds"
    assert isinstance(args[2], aws.Credentials)


def test_explicit_image_id_skips_resolution(mock_ec2, creds, ubuntu_ami):
    from aws_helper.core import launch

    with patch.object(aws, "resolve_ami") as spy:
        results = launch.launch(
            creds,
            launch.LaunchRequest(
                name="explicit-ami", region="us-east-1", image_id=ubuntu_ami
            ),
        )
    assert not spy.called
    assert results[0].image_id == ubuntu_ami
