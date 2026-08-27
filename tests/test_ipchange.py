"""换 IP 的集成测试（moto 模拟 EC2）。"""

from __future__ import annotations

import pytest

from aws_helper.core import aws, ipchange, launch


@pytest.fixture
def instance(mock_ec2, creds, ubuntu_ami):
    results = launch.launch(creds, launch.LaunchRequest(name="ip-test", region="us-east-1"))
    return results[0]


def test_change_ip_via_eip(creds, instance):
    old = instance.public_ip
    result = ipchange.change_ip(creds, "us-east-1", instance.instance_id, strategy="eip")

    assert result.new_ip != old
    assert result.old_ip == old
    assert result.strategy == "eip"
    assert result.allocation_id

    session = aws.ec2(creds)
    live = session.describe_instances(InstanceIds=[instance.instance_id])
    actual = live["Reservations"][0]["Instances"][0]["PublicIpAddress"]
    assert actual == result.new_ip


def test_second_eip_change_releases_the_first(creds, instance):
    """连续换两次，第一次分配的 EIP 必须被释放，否则会一直计费。"""
    first = ipchange.change_ip(creds, "us-east-1", instance.instance_id, strategy="eip")
    second = ipchange.change_ip(creds, "us-east-1", instance.instance_id, strategy="eip")

    assert second.new_ip != first.new_ip
    assert first.new_ip in second.released

    remaining = {a["public_ip"] for a in ipchange.list_addresses(creds, "us-east-1")}
    assert first.new_ip not in remaining
    assert second.new_ip in remaining


def test_no_idle_eip_left_after_change(creds, instance):
    ipchange.change_ip(creds, "us-east-1", instance.instance_id, strategy="eip")
    idle = [a for a in ipchange.list_addresses(creds, "us-east-1") if a["idle"]]
    assert idle == []


def test_change_ip_via_restart(creds, instance):
    old = instance.public_ip
    result = ipchange.change_ip(
        creds, "us-east-1", instance.instance_id, strategy="dynamic"
    )
    assert result.strategy == "dynamic"
    assert result.new_ip != old

    session = aws.ec2(creds)
    live = session.describe_instances(InstanceIds=[instance.instance_id])
    inst = live["Reservations"][0]["Instances"][0]
    assert inst["State"]["Name"] == "running"
    assert inst["PublicIpAddress"] == result.new_ip


def test_dynamic_refuses_when_eip_attached(creds, instance):
    """绑了 EIP 的实例重启不会换 IP，必须明确报错而不是假装成功。"""
    ipchange.change_ip(creds, "us-east-1", instance.instance_id, strategy="eip")
    with pytest.raises(ipchange.IpChangeError, match="绑定了弹性 IP"):
        ipchange.change_ip(creds, "us-east-1", instance.instance_id, strategy="dynamic")


def test_unknown_strategy_rejected(creds, instance):
    with pytest.raises(ipchange.IpChangeError, match="未知策略"):
        ipchange.change_ip(creds, "us-east-1", instance.instance_id, strategy="magic")


def test_dynamic_refuses_when_secondary_nic_present(creds, instance):
    """有辅助网卡时 stop/start 不会换 IP（AWS 官方文档明确的例外）。

    必须提前拦住，否则会白白停机一次，IP 还是原来那个。
    """
    session = aws.ec2(creds)
    inst = session.describe_instances(InstanceIds=[instance.instance_id])[
        "Reservations"
    ][0]["Instances"][0]
    subnet_id = inst["NetworkInterfaces"][0]["SubnetId"]

    extra = session.create_network_interface(SubnetId=subnet_id)
    session.attach_network_interface(
        NetworkInterfaceId=extra["NetworkInterface"]["NetworkInterfaceId"],
        InstanceId=instance.instance_id,
        DeviceIndex=1,
    )

    with pytest.raises(ipchange.IpChangeError, match="辅助网卡"):
        ipchange.change_ip(
            creds, "us-east-1", instance.instance_id, strategy="dynamic"
        )


def test_instance_state_unchanged_after_blocked_dynamic(creds, instance):
    """被拦下时实例不该被停机 —— 拦截必须发生在任何 stop 之前。"""
    session = aws.ec2(creds)
    ipchange.change_ip(creds, "us-east-1", instance.instance_id, "eip")

    with pytest.raises(ipchange.IpChangeError):
        ipchange.change_ip(
            creds, "us-east-1", instance.instance_id, strategy="dynamic"
        )

    live = session.describe_instances(InstanceIds=[instance.instance_id])
    assert live["Reservations"][0]["Instances"][0]["State"]["Name"] == "running"


def test_deny_cidr_forces_retry_then_fails(creds, instance):
    """所有 IP 都被 deny 段覆盖时，应耗尽重试次数并报错，且不留下空闲 EIP。"""
    rule = ipchange.IpRule(deny_cidrs=["0.0.0.0/0"], max_attempts=3)
    with pytest.raises(ipchange.IpChangeError, match="不满足规则"):
        ipchange.change_ip(
            creds, "us-east-1", instance.instance_id, strategy="eip", rule=rule
        )
    idle = [a for a in ipchange.list_addresses(creds, "us-east-1") if a["idle"]]
    assert idle == []


def test_allow_cidr_accepts_matching_ip(creds, instance):
    rule = ipchange.IpRule(allow_cidrs=["0.0.0.0/0"], max_attempts=1)
    result = ipchange.change_ip(
        creds, "us-east-1", instance.instance_id, strategy="eip", rule=rule
    )
    assert result.new_ip != instance.public_ip


def test_ip_rule_matching_logic():
    rule = ipchange.IpRule(allow_cidrs=["13.112.0.0/14"], deny_cidrs=["13.112.5.0/24"])
    assert rule.matches("13.112.1.1")
    assert not rule.matches("13.112.5.9")
    assert not rule.matches("52.1.1.1")
    assert not rule.matches("not-an-ip")


def test_deny_takes_precedence_over_allow():
    rule = ipchange.IpRule(allow_cidrs=["10.0.0.0/8"], deny_cidrs=["10.1.0.0/16"])
    assert rule.matches("10.2.0.1")
    assert not rule.matches("10.1.0.1")


def test_empty_rule_accepts_any_valid_ip():
    rule = ipchange.IpRule()
    assert rule.matches("1.2.3.4")
    assert not rule.matches("garbage")


def test_invalid_max_attempts(creds, instance):
    with pytest.raises(ipchange.IpChangeError, match="max_attempts"):
        ipchange.change_ip(
            creds,
            "us-east-1",
            instance.instance_id,
            rule=ipchange.IpRule(max_attempts=0),
        )


def test_release_idle_frees_unattached(creds, mock_ec2):
    session = aws.ec2(creds)
    a1 = session.allocate_address(Domain="vpc")
    a2 = session.allocate_address(Domain="vpc")

    freed = ipchange.release_idle(creds, "us-east-1")
    assert set(freed) == {a1["PublicIp"], a2["PublicIp"]}
    assert ipchange.list_addresses(creds, "us-east-1") == []


def test_orphaned_eip_detected_after_terminate(creds, instance):
    """实例终止后，仍挂在它名下的 EIP 必须被识别为在计费的孤儿。

    describe_addresses 对已终止实例仍会返回 InstanceId，
    只看 InstanceId 是否为空会把这类地址误判为"已绑定"而漏掉。

    这里用 cleanup=False 直接终止 —— 默认的连带清理会主动释放 EIP，
    那样就没有孤儿可测了。这条测的是"清理没跑或跑失败"后的兜底识别能力。
    """
    result = ipchange.change_ip(creds, "us-east-1", instance.instance_id, "eip")
    launch.power(
        creds, "us-east-1", "terminate", [instance.instance_id], cleanup=False
    )

    addrs = ipchange.list_addresses(creds, "us-east-1")
    target = [a for a in addrs if a["public_ip"] == result.new_ip][0]
    assert target["orphaned"] is True

    freed = ipchange.release_idle(creds, "us-east-1")
    assert result.new_ip in freed
    assert ipchange.list_addresses(creds, "us-east-1") == []


def test_attached_eip_is_not_orphaned(creds, instance):
    result = ipchange.change_ip(creds, "us-east-1", instance.instance_id, "eip")
    addrs = ipchange.list_addresses(creds, "us-east-1")
    target = [a for a in addrs if a["public_ip"] == result.new_ip][0]
    assert target["idle"] is False
    assert target["orphaned"] is False

    assert ipchange.release_idle(creds, "us-east-1") == []


def test_change_ip_missing_instance(creds, mock_ec2):
    with pytest.raises(ipchange.IpChangeError, match="找不到实例|InvalidInstanceID"):
        ipchange.change_ip(creds, "us-east-1", "i-00000000000000000")
