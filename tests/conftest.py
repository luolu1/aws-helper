"""pytest 公共 fixture：moto 模拟 EC2，隔离数据目录。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    """每个测试用独立数据目录和假凭据，避免读到真实 ~/.aws。"""
    monkeypatch.setenv("AWS_HELPER_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_HELPER_ENDPOINT_URL", raising=False)
    yield


@pytest.fixture
def creds():
    from aws_helper.core.aws import Credentials

    return Credentials("testing", "testing", "us-east-1")


@pytest.fixture
def mock_ec2():
    """启用 moto 的 EC2 模拟。"""
    from moto import mock_aws

    with mock_aws():
        yield


@pytest.fixture
def ubuntu_ami(mock_ec2, creds, monkeypatch):
    """moto 自带的 AMI 名字和真实 AWS 不同，这里改写查找规则指向 moto 的镜像。

    moto 预置了若干 AMI，取第一个可用的，并把 IMAGES 里的 pattern 换成它的名字。
    """
    from aws_helper.core import aws

    session = aws.ec2(creds)
    images = session.describe_images()["Images"]
    assert images, "moto 应预置 AMI"
    img = images[0]

    spec = aws.ImageSpec(
        label="moto-test-image",
        owner=img["OwnerId"],
        name_patterns=(img["Name"],),
        ssh_user="ubuntu",
    )
    monkeypatch.setitem(aws.IMAGES, "ubuntu-24.04", spec)
    return img["ImageId"]


@pytest.fixture
def store(tmp_path):
    from aws_helper.store import Store

    s = Store(tmp_path / "store")
    yield s
    s.close()
