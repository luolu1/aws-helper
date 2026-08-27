"""终止实例的资源清理与账号探测。"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from aws_helper.core import aws, ipchange, launch

from .test_web import build_app, login


@pytest.fixture
def live(mock_ec2, creds, ubuntu_ami):
    """开一台带 EIP 的实例，构造出所有会残留的资源。"""
    result = launch.launch(
        creds, launch.LaunchRequest(name="cl", region="us-east-1", disk_size=20)
    )[0]
    ipchange.change_ip(creds, "us-east-1", result.instance_id, "eip")
    return result


# ---------- 资源采集 ----------


def test_collect_finds_all_related(live, creds):
    """终止前必须先采集：终止后 AWS 会逐步解除关联，届时查不到了。"""
    session = aws.ec2(creds)
    found = launch.collect_related_resources(session, [live.instance_id])

    assert found["volumes"], "应采集到根卷"
    assert found["addresses"], "应采集到弹性 IP"
    assert live.security_group_id in found["security_groups"]
    assert live.key_name in found["key_pairs"]
    assert found["network_interfaces"]


def test_collect_handles_no_eip(mock_ec2, creds, ubuntu_ami):
    result = launch.launch(
        creds, launch.LaunchRequest(name="noeip", region="us-east-1")
    )[0]
    found = launch.collect_related_resources(aws.ec2(creds), [result.instance_id])
    assert found["addresses"] == []
    assert found["volumes"]


# ---------- 清理效果 ----------


def test_terminate_releases_elastic_ip(live, creds):
    """弹性 IP 是唯一持续产生真实费用的项，必须释放。"""
    res = launch.power(creds, "us-east-1", "terminate", [live.instance_id])
    assert res["cleaned"]["addresses"], res
    assert ipchange.list_addresses(creds, "us-east-1") == []


def test_terminate_deletes_security_group(live, creds):
    launch.power(creds, "us-east-1", "terminate", [live.instance_id])
    session = aws.ec2(creds)
    groups = [
        g["GroupId"]
        for g in session.describe_security_groups()["SecurityGroups"]
        if g["GroupName"] != "default"
    ]
    assert live.security_group_id not in groups


def test_terminate_deletes_our_key_pair(live, creds):
    launch.power(creds, "us-east-1", "terminate", [live.instance_id])
    names = [
        k["KeyName"] for k in aws.ec2(creds).describe_key_pairs()["KeyPairs"]
    ]
    assert live.key_name not in names


def test_terminate_keeps_user_key_pair(mock_ec2, creds, ubuntu_ami):
    """用户自己的密钥对不能删 —— 可能还在给别的实例用。"""
    session = aws.ec2(creds)
    session.create_key_pair(KeyName="my-own-key")
    result = launch.launch(
        creds,
        launch.LaunchRequest(name="ok", region="us-east-1", key_name="my-own-key"),
    )[0]

    launch.power(creds, "us-east-1", "terminate", [result.instance_id])
    names = [k["KeyName"] for k in session.describe_key_pairs()["KeyPairs"]]
    assert "my-own-key" in names


def test_terminate_no_leftover_volumes(live, creds):
    launch.power(creds, "us-east-1", "terminate", [live.instance_id])
    vols = [
        v for v in aws.ec2(creds).describe_volumes()["Volumes"]
        if v.get("State") != "deleted"
    ]
    assert vols == []


def test_terminate_deletes_self_built_vpc(mock_ec2, creds, ubuntu_ami):
    """IPv6 双栈会自建 VPC，终止时要连带删掉，否则堆积占配额。"""
    result = launch.launch(
        creds,
        launch.LaunchRequest(name="v6cl", region="us-east-1", enable_ipv6=True),
    )[0]
    session = aws.ec2(creds)
    vpc_id = session.describe_security_groups(GroupIds=[result.security_group_id])[
        "SecurityGroups"
    ][0]["VpcId"]

    res = launch.power(creds, "us-east-1", "terminate", [result.instance_id])
    assert vpc_id in res["cleaned"]["vpcs"], res["failed"]
    remaining = [v["VpcId"] for v in session.describe_vpcs()["Vpcs"]]
    assert vpc_id not in remaining


def test_terminate_keeps_default_vpc(live, creds):
    """默认 VPC 绝对不能删。"""
    session = aws.ec2(creds)
    launch.power(creds, "us-east-1", "terminate", [live.instance_id])
    defaults = [
        v["VpcId"] for v in session.describe_vpcs()["Vpcs"] if v.get("IsDefault")
    ]
    assert defaults, "默认 VPC 被误删了"


def test_terminate_keeps_vpc_with_other_instances(mock_ec2, creds, ubuntu_ami):
    """VPC 里还有别的实例在跑时不能删 —— 会打断用户其他业务。"""
    a = launch.launch(
        creds, launch.LaunchRequest(name="keep-a", region="us-east-1", enable_ipv6=True)
    )[0]
    session = aws.ec2(creds)
    vpc_id = session.describe_security_groups(GroupIds=[a.security_group_id])[
        "SecurityGroups"
    ][0]["VpcId"]

    subnet = session.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["Subnets"][0]["SubnetId"]
    other = session.run_instances(
        ImageId=a.image_id, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=subnet,
    )["Instances"][0]["InstanceId"]

    launch.power(creds, "us-east-1", "terminate", [a.instance_id])
    assert vpc_id in [v["VpcId"] for v in session.describe_vpcs()["Vpcs"]]
    session.terminate_instances(InstanceIds=[other])


def test_cleanup_can_be_disabled(live, creds):
    """cleanup=False 时只终止，不动关联资源。"""
    res = launch.power(
        creds, "us-east-1", "terminate", [live.instance_id], cleanup=False
    )
    assert "cleaned" not in res
    assert ipchange.list_addresses(creds, "us-east-1")


def test_cleanup_reports_progress(live, creds):
    steps: list[str] = []
    launch.power(
        creds, "us-east-1", "terminate", [live.instance_id], progress=steps.append
    )
    joined = " ".join(steps)
    assert "采集关联资源" in joined
    assert "释放弹性 IP" in joined
    assert "终止" in joined


def test_partial_failure_does_not_abort(live, creds):
    """某一项删不掉要记进 failed 而不是中断整个清理。"""
    session = aws.ec2(creds)
    real_delete = session.delete_security_group

    with patch.object(aws, "ec2") as factory:
        proxy = type("P", (), {})()
        for name in dir(session):
            if not name.startswith("_"):
                setattr(proxy, name, getattr(session, name))

        def boom(**kwargs):
            raise _client_error("DependencyViolation")

        proxy.delete_security_group = boom
        factory.return_value = proxy
        res = launch.power(creds, "us-east-1", "terminate", [live.instance_id])

    assert res["ok"]
    assert res["cleaned"]["addresses"], "EIP 仍应被释放"
    assert any("安全组" in f for f in res["failed"])
    assert real_delete


def _client_error(code: str):
    from botocore.exceptions import ClientError

    return ClientError(
        {"Error": {"Code": code, "Message": code}}, "DeleteSecurityGroup"
    )


# ---------- 账号探测 ----------


def test_probe_reports_checks(mock_ec2, creds):
    result = aws.probe_account(creds, "us-east-1")
    names = [c["name"] for c in result["checks"]]
    assert "凭据与网络" in names
    assert "开机权限" in names
    assert "region" in result
    assert "usage" in result


def test_probe_counts_usage(mock_ec2, creds, ubuntu_ami):
    launch.launch(creds, launch.LaunchRequest(name="u1", region="us-east-1"))
    result = aws.probe_account(creds, "us-east-1")
    usage = result["usage"]
    assert usage["running_instances"] >= 1
    assert usage["volumes"] >= 1


def test_probe_counts_idle_addresses(mock_ec2, creds):
    """空闲弹性 IP 在计费，探测要单独数出来。"""
    aws.ec2(creds).allocate_address(Domain="vpc")
    usage = aws.probe_account(creds, "us-east-1")["usage"]
    assert usage["addresses"] >= 1
    assert usage["idle_addresses"] >= 1


def test_probe_flags_root_credentials(mock_ec2, creds):
    """root 凭据风险高，探测要提示换 IAM 用户。"""
    with patch.object(aws, "client") as factory:
        factory.return_value.get_caller_identity.return_value = {
            "Account": "111122223333",
            "Arn": "arn:aws:iam::111122223333:root",
        }
        result = aws.probe_account(creds, "us-east-1")
    identity = [c for c in result["checks"] if c["name"] == "账号身份"][0]
    assert identity["ok"] is False
    assert "root" in identity["detail"]


def test_probe_detects_blocked_account(mock_ec2, creds):
    """账号被 AWS 封禁时 DryRun 仍会通过，必须从真实错误里识别。"""
    session = aws.ec2(creds)

    class Blocked:
        def __getattr__(self, name):
            return getattr(session, name)

        def run_instances(self, **kwargs):
            from botocore.exceptions import ClientError

            raise ClientError(
                {"Error": {"Code": "Blocked", "Message": "This account is blocked"}},
                "RunInstances",
            )

    with patch.object(aws, "ec2", return_value=Blocked()):
        result = aws.probe_account(creds, "us-east-1")

    check = [c for c in result["checks"] if c["name"] == "开机权限"][0]
    assert check["ok"] is False
    assert "封禁" in check["detail"]
    assert result["healthy"] is False


def test_probe_survives_missing_quota_permission(mock_ec2, creds):
    """缺 servicequotas 权限不能让整个探测失败，只标这一项未通过。"""
    real_client = aws.client

    def selective(service, *args, **kwargs):
        if service == "service-quotas":
            raise RuntimeError("AccessDeniedException")
        return real_client(service, *args, **kwargs)

    with patch.object(aws, "client", side_effect=selective):
        result = aws.probe_account(creds, "us-east-1")

    assert result["checks"]
    quota_check = [c for c in result["checks"] if c["name"] == "vCPU 配额"][0]
    assert quota_check["ok"] is False
    # 其他检查项不受影响
    assert any(c["ok"] for c in result["checks"])
    assert "usage" in result


# ---------- Web 端点 ----------


@pytest.fixture
def panel(mock_ec2, ubuntu_ami, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "cleanup")
    client = TestClient(app_module.app)
    login(client)
    account_id = app_module.store.add_account("t", "testing", "testing", "us-east-1")
    return client, account_id, app_module


def test_probe_endpoint(panel):
    c, aid, _ = panel
    d = c.get(f"/api/probe-account?account_id={aid}&region=us-east-1").json()
    assert d["ok"]
    assert d["checks"]
    assert "usage" in d


def test_probe_endpoint_requires_login(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "pa")
    c = TestClient(app_module.app)
    assert c.get("/api/probe-account?account_id=1&region=us-east-1").status_code == 401


def test_terminate_endpoint_returns_task(panel, creds):
    """终止走后台任务：清理要等实例真终止，HTTP 同步会超时。"""
    c, aid, app_module = panel
    inst = launch.launch(
        creds, launch.LaunchRequest(name="ep", region="us-east-1")
    )[0]

    resp = c.post(
        "/api/instances/power",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "action": "terminate",
            "instance_ids": [inst.instance_id],
        },
    )
    assert resp.status_code == 200
    task_id = resp.json()["task_id"]

    deadline = time.time() + 60
    while time.time() < deadline:
        task = c.get(f"/api/tasks/{task_id}").json()["task"]
        if task["status"] != "running":
            break
        time.sleep(0.4)
    assert task["status"] == "done", task
    assert task["result"]["cleaned"]["instances"] == [inst.instance_id]


def test_non_terminate_actions_stay_synchronous(panel, creds):
    c, aid, _ = panel
    inst = launch.launch(
        creds, launch.LaunchRequest(name="sy", region="us-east-1")
    )[0]
    resp = c.post(
        "/api/instances/power",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "action": "stop",
            "instance_ids": [inst.instance_id],
        },
    )
    assert resp.status_code == 200
    assert "task_id" not in resp.json()


def test_accounts_page_shows_quota_columns(panel):
    """账号列表要直接看到状态和 vCPU 配额，不用点进详情。"""
    c, _, _ = panel
    html = c.get("/accounts").text

    assert "vCPU 配额 / 已用" in html
    assert ">状态<" in html
    assert 'class="probe-status"' in html
    assert 'class="probe-quota' in html


def test_accounts_page_has_per_row_and_bulk_probe(panel):
    c, aid, _ = panel
    html = c.get("/accounts").text

    assert f"probeAccount({aid}," in html, "每行要有独立的检测按钮"
    assert "probeAll()" in html
    assert "检测全部账号" in html


def test_account_rows_carry_probe_metadata(panel):
    """行上要带 account/region，批量检测才知道逐个查什么。"""
    c, aid, _ = panel
    html = c.get("/accounts").text
    assert f'data-account="{aid}"' in html
    assert 'data-region="us-east-1"' in html
