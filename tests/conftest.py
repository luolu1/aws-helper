"""pytest 公共 fixture：moto 模拟 EC2，每个测试独立的数据目录与数据库 schema。

数据库用真实 Postgres（不是模拟），靠每个测试独占一个 schema 做隔离 ——
比起 mock 掉 SQL，这样能验证真实的约束、upsert 语义和级联删除。
连接串取 AWS_HELPER_TEST_DATABASE_URL，缺失时跳过需要库的测试。
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_DSN_ENV = "AWS_HELPER_TEST_DATABASE_URL"
DEFAULT_TEST_DSN = "postgresql://postgres:test@127.0.0.1:15432/awshelper"


def database_dsn() -> str:
    return os.environ.get(TEST_DSN_ENV, DEFAULT_TEST_DSN)


def _database_reachable() -> bool:
    try:
        import psycopg

        with psycopg.connect(database_dsn(), connect_timeout=5):
            return True
    except Exception:
        return False


_DB_OK = _database_reachable()

requires_db = pytest.mark.skipif(
    not _DB_OK,
    reason=f"需要可用的 Postgres（设置 {TEST_DSN_ENV}）",
)


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch, request):
    """每个测试用独立数据目录、独立 schema 和假凭据。"""
    monkeypatch.setenv("AWS_HELPER_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_HELPER_ENDPOINT_URL", raising=False)

    monkeypatch.setenv("AWS_HELPER_DATABASE_URL", database_dsn())
    schema = "t_" + uuid.uuid4().hex[:16]
    monkeypatch.setenv("AWS_HELPER_DB_SCHEMA", schema)
    yield

    if not _DB_OK:
        return
    try:
        import psycopg

        with psycopg.connect(database_dsn(), autocommit=True) as conn:
            conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
    except Exception:
        pass


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

    if not _DB_OK:
        pytest.skip(f"需要可用的 Postgres（设置 {TEST_DSN_ENV}）")
    s = Store(tmp_path / "store")
    yield s
    s.close()
