"""镜像目录级联选择与 Windows 开机适配。"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from aws_helper.core import aws, launch

from .test_web import build_app, login


# ---------- 分类元数据 ----------


def test_os_families_and_architectures():
    assert set(aws.OS_FAMILIES) == {"linux", "windows"}
    assert set(aws.ARCHITECTURES) == {"x86_64", "arm64"}
    assert aws.ARCHITECTURES["arm64"] == "64 位（ARM）"
    assert aws.ARCHITECTURES["x86_64"] == "64 位（x86）"


def test_every_image_declares_os_and_arch():
    for key, spec in aws.IMAGES.items():
        assert spec.os_family in aws.OS_FAMILIES, key
        assert spec.arch in aws.ARCHITECTURES, key


def test_windows_images_present():
    wins = aws.images_by_os_arch("windows", "x86_64")
    assert wins, "应有 Windows 镜像"
    assert all(s.is_windows for s in wins.values())
    assert all(s.ssh_user == "Administrator" for s in wins.values())


def test_windows_uses_official_ssm_namespace():
    """Windows AMI 在 describe_images 里不可靠（实测 ap-east-1 返回 0 条），
    必须走 AWS 官方 ami-windows-latest 参数空间。"""
    for spec in aws.images_by_os_arch("windows", "x86_64").values():
        assert spec.ssm_parameter
        assert spec.ssm_parameter.startswith("/aws/service/ami-windows-latest/")


def test_no_windows_arm64_images():
    """AWS 没有公开发布 ARM64 的 Windows Server 基础镜像，不能凭空列出来。"""
    assert aws.images_by_os_arch("windows", "arm64") == {}


def test_linux_images_split_by_arch():
    x86 = aws.images_by_os_arch("linux", "x86_64")
    arm = aws.images_by_os_arch("linux", "arm64")
    assert x86 and arm
    assert not set(x86) & set(arm)
    assert all(s.arch == "x86_64" for s in x86.values())
    assert all(s.arch == "arm64" for s in arm.values())


def test_canonical_ssm_paths_follow_official_format():
    """路径格式按 Canonical 官方文档：
    /aws/service/canonical/ubuntu/server/RELEASE/stable/current/ARCH/hvm/VOL/ami-id
    """
    spec = aws.IMAGES["ubuntu-24.04"]
    parts = spec.ssm_parameter.strip("/").split("/")
    assert parts[:5] == ["aws", "service", "canonical", "ubuntu", "server"]
    assert parts[5] == "24.04"
    assert parts[-1] == "ami-id"
    assert "amd64" in parts
    assert aws.IMAGES["ubuntu-24.04-arm"].ssm_parameter.count("arm64") == 1


# ---------- 规格实时拉取 ----------


def test_list_instance_types_filters_by_arch(mock_ec2, creds):
    types = aws.list_instance_types(creds, "us-east-1", "x86_64", use_cache=False)
    assert types
    for t in types:
        assert {"name", "vcpu", "memory_gib", "label"} <= set(t)
        assert t["vcpu"] >= 1


def test_arm_and_x86_type_lists_differ(mock_ec2, creds):
    x86 = {t["name"] for t in aws.list_instance_types(creds, "us-east-1", "x86_64", False)}
    arm = {t["name"] for t in aws.list_instance_types(creds, "us-east-1", "arm64", False)}
    assert x86
    assert not (x86 & arm) or len(x86 ^ arm) > 0


def test_types_sorted_by_memory(mock_ec2, creds):
    types = aws.list_instance_types(creds, "us-east-1", "x86_64", use_cache=False)
    mems = [t["memory_gib"] for t in types]
    assert mems == sorted(mems)


def test_type_list_is_cached(mock_ec2, creds):
    """DescribeInstanceTypes 要翻多页拉数百条，每次开页都拉太慢。"""
    aws._TYPE_CACHE.clear()
    first = aws.list_instance_types(creds, "us-east-1", "x86_64")
    with patch.object(aws, "ec2") as spy:
        second = aws.list_instance_types(creds, "us-east-1", "x86_64")
    assert not spy.called
    assert first == second
    aws._TYPE_CACHE.clear()


def test_unknown_arch_rejected(mock_ec2, creds):
    with pytest.raises(ValueError, match="未知架构"):
        aws.list_instance_types(creds, "us-east-1", "mips")


def test_fallback_list_available():
    for arch in ("x86_64", "arm64"):
        items = aws.fallback_instance_types(arch)
        assert items
        assert all(i["name"] for i in items)


def test_fallback_arm_types_are_actually_arm():
    names = [i["name"] for i in aws.fallback_instance_types("arm64")]
    assert all(
        n.startswith(("t4g", "c6g", "c7g", "m6g", "m7g", "r6g", "c8g")) for n in names
    ), names


# ---------- /api/catalog ----------


@pytest.fixture
def panel(mock_ec2, ubuntu_ami, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "catalog")
    client = TestClient(app_module.app)
    login(client)
    account_id = app_module.store.add_account("t", "testing", "testing", "us-east-1")
    return client, account_id, app_module


def test_catalog_linux_x86(panel):
    c, aid, _ = panel
    d = c.get(f"/api/catalog?account_id={aid}&region=us-east-1").json()
    assert d["ok"]
    assert d["os_family"] == "linux"
    assert d["arch"] == "x86_64"
    assert d["images"]
    assert d["instance_types"]
    assert d["is_windows"] is False


def test_catalog_windows_marks_flag(panel):
    c, aid, _ = panel
    d = c.get(
        f"/api/catalog?account_id={aid}&region=us-east-1&os_family=windows"
    ).json()
    assert d["is_windows"] is True
    assert any("Windows" in i["label"] for i in d["images"])


def test_catalog_arm_returns_arm_images(panel):
    c, aid, _ = panel
    d = c.get(f"/api/catalog?account_id={aid}&region=us-east-1&arch=arm64").json()
    assert d["images"]
    assert all("ARM" in i["label"] or "arm" in i["key"] for i in d["images"])


def test_catalog_windows_arm_is_empty(panel):
    c, aid, _ = panel
    d = c.get(
        f"/api/catalog?account_id={aid}&region=us-east-1"
        "&os_family=windows&arch=arm64"
    ).json()
    assert d["images"] == []


def test_empty_image_key_gets_actionable_error(mock_ec2, creds, ubuntu_ami):
    """镜像下拉为空（如 Windows+ARM64）时提交，报错要说明白怎么办。

    原来只说"未知镜像: "，用户看不出是组合没镜像还是自己填错了。
    """
    with pytest.raises(launch.LaunchError, match="没有选择镜像") as excinfo:
        launch.launch(
            creds, launch.LaunchRequest(name="no-img", region="us-east-1", image_key="")
        )
    message = str(excinfo.value)
    assert "指定 AMI ID" in message
    assert "ARM64 的 Windows" in message


def test_empty_image_key_ok_with_explicit_ami(mock_ec2, creds, ubuntu_ami):
    """手动填了 AMI ID 时，镜像下拉为空不该阻断开机。"""
    results = launch.launch(
        creds,
        launch.LaunchRequest(
            name="explicit-only", region="us-east-1", image_key="", image_id=ubuntu_ami
        ),
    )
    assert results[0].image_id == ubuntu_ami


def test_catalog_rejects_bad_params(panel):
    c, aid, _ = panel
    assert c.get(
        f"/api/catalog?account_id={aid}&region=us-east-1&os_family=plan9"
    ).status_code == 400
    assert c.get(
        f"/api/catalog?account_id={aid}&region=us-east-1&arch=sparc"
    ).status_code == 400


def test_catalog_requires_login(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "cat-anon")
    c = TestClient(app_module.app)
    assert c.get("/api/catalog?account_id=1&region=us-east-1").status_code == 401


def test_catalog_degrades_when_api_fails(panel):
    """DescribeInstanceTypes 不可用（IAM 缺权限）时必须降级而不是整页报错。"""
    c, aid, _ = panel
    aws._TYPE_CACHE.clear()
    with patch.object(aws, "list_instance_types", side_effect=RuntimeError("denied")):
        d = c.get(f"/api/catalog?account_id={aid}&region=us-east-1").json()
    assert d["ok"]
    assert d["degraded"] is True
    assert d["instance_types"]


def test_launch_page_renders_cascade(panel):
    c, _, _ = panel
    html = c.get("/launch").text
    assert "① 系统类别" in html
    assert "② 架构" in html
    assert "③ 镜像" in html
    assert "④ 规格" in html
    assert "loadCatalog" in html


# ---------- Windows 开机适配 ----------


@pytest.fixture
def win_image(mock_ec2, creds, monkeypatch):
    session = aws.ec2(creds)
    img = session.describe_images()["Images"][0]
    monkeypatch.setitem(
        aws.IMAGES,
        "windows-2022",
        aws.ImageSpec(
            label="Windows Server 2022",
            owner=img["OwnerId"],
            name_patterns=(img["Name"],),
            os_family="windows",
            ssh_user="Administrator",
        ),
    )
    return img["ImageId"]


def test_windows_launch_sends_no_userdata(win_image, creds):
    """Windows 的 cloud-init 是 EC2Launch，不吃 bash 脚本。

    传一段 Linux UserData 上去不会报错，只会静默不执行 —— 比直接拒绝更难排查。
    """
    from botocore.exceptions import ClientError

    results = launch.launch(
        creds, launch.LaunchRequest(name="win-node", region="us-east-1",
                                    image_key="windows-2022")
    )
    session = aws.ec2(creds)
    try:
        attr = session.describe_instance_attribute(
            InstanceId=results[0].instance_id, Attribute="userData"
        )
        assert not attr.get("UserData", {}).get("Value")
    except ClientError:
        pass


def test_windows_reports_os_family(win_image, creds):
    results = launch.launch(
        creds, launch.LaunchRequest(name="win-os", region="us-east-1",
                                    image_key="windows-2022")
    )
    assert results[0].os_family == "windows"
    assert results[0].ssh_user == "Administrator"


def test_windows_rejects_root_password(win_image, creds):
    with pytest.raises(launch.LaunchError, match="不支持设置 root 密码"):
        launch.launch(
            creds,
            launch.LaunchRequest(
                name="win-pw", region="us-east-1",
                image_key="windows-2022", root_password="Pw123456",
            ),
        )


def test_windows_rejects_linux_script(win_image, creds):
    with pytest.raises(launch.LaunchError, match="不支持 Linux 开机脚本"):
        launch.launch(
            creds,
            launch.LaunchRequest(
                name="win-script", region="us-east-1",
                image_key="windows-2022", script="apt-get update",
            ),
        )


def test_windows_rejects_packages(win_image, creds):
    with pytest.raises(launch.LaunchError, match="不支持 Linux 开机脚本"):
        launch.launch(
            creds,
            launch.LaunchRequest(
                name="win-pkg", region="us-east-1",
                image_key="windows-2022", packages=["curl"],
            ),
        )


def test_windows_rejection_creates_nothing(win_image, creds):
    """参数校验必须在创建任何 AWS 资源之前完成。"""
    before = len(launch.list_instances(creds, "us-east-1"))
    with pytest.raises(launch.LaunchError):
        launch.launch(
            creds,
            launch.LaunchRequest(
                name="win-clean", region="us-east-1",
                image_key="windows-2022", root_password="x",
            ),
        )
    assert len(launch.list_instances(creds, "us-east-1")) == before


def test_linux_launch_still_injects_userdata(mock_ec2, creds, ubuntu_ami):
    import base64

    results = launch.launch(
        creds,
        launch.LaunchRequest(
            name="linux-still", region="us-east-1", script="echo STILL_WORKS"
        ),
    )
    session = aws.ec2(creds)
    attr = session.describe_instance_attribute(
        InstanceId=results[0].instance_id, Attribute="userData"
    )
    decoded = base64.b64decode(attr["UserData"]["Value"]).decode()
    assert "echo STILL_WORKS" in decoded
    assert results[0].os_family == "linux"
