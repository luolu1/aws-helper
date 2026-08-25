"""一键开机的集成测试（moto 模拟 EC2）。"""

from __future__ import annotations

import base64

import pytest

from aws_helper.core import aws, launch


def test_launch_minimal(mock_ec2, creds, ubuntu_ami):
    """只给名字就能开出机器，且拿到公网 IP 和私钥。"""
    steps: list[str] = []
    results = launch.launch(
        creds,
        launch.LaunchRequest(name="node-a", region="us-east-1"),
        progress=steps.append,
    )

    assert len(results) == 1
    r = results[0]
    assert r.instance_id.startswith("i-")
    assert r.state == "running"
    assert r.public_ip
    assert r.private_ip
    assert r.private_key and "PRIVATE KEY" in r.private_key
    assert r.image_id == ubuntu_ami
    assert steps and "完成" in steps[-1]


def test_launch_injects_userdata(mock_ec2, creds, ubuntu_ami):
    """开机脚本必须真的落到 EC2 的 UserData 属性上。"""
    results = launch.launch(
        creds,
        launch.LaunchRequest(
            name="node-script",
            region="us-east-1",
            script="echo MARKER_FROM_TEST > /tmp/marker",
            root_password="pw123",
            packages=["curl"],
        ),
    )
    session = aws.ec2(creds)
    attr = session.describe_instance_attribute(
        InstanceId=results[0].instance_id, Attribute="userData"
    )
    decoded = base64.b64decode(attr["UserData"]["Value"]).decode()

    assert decoded.startswith("#!/bin/bash")
    assert "echo MARKER_FROM_TEST > /tmp/marker" in decoded
    assert "chpasswd" in decoded
    assert "apt-get install -y curl" in decoded
    assert decoded.index("MARKER_FROM_TEST") > decoded.index("chpasswd")


def test_launch_without_password_has_no_root_block(mock_ec2, creds, ubuntu_ami):
    results = launch.launch(
        creds, launch.LaunchRequest(name="node-nopw", region="us-east-1", script="ls")
    )
    session = aws.ec2(creds)
    attr = session.describe_instance_attribute(
        InstanceId=results[0].instance_id, Attribute="userData"
    )
    decoded = base64.b64decode(attr["UserData"]["Value"]).decode()
    assert "chpasswd" not in decoded


def test_security_group_opens_only_requested_ports(mock_ec2, creds, ubuntu_ami):
    results = launch.launch(
        creds,
        launch.LaunchRequest(
            name="node-sg", region="us-east-1", open_ports=[22, 443]
        ),
    )
    session = aws.ec2(creds)
    sg = session.describe_security_groups(GroupIds=[results[0].security_group_id])
    perms = sg["SecurityGroups"][0]["IpPermissions"]

    ports = sorted(p["FromPort"] for p in perms)
    assert ports == [22, 443]
    assert all(p["IpProtocol"] == "tcp" for p in perms)


def test_allow_all_ports_is_opt_in(mock_ec2, creds, ubuntu_ami):
    results = launch.launch(
        creds,
        launch.LaunchRequest(
            name="node-open", region="us-east-1", allow_all_ports=True
        ),
    )
    session = aws.ec2(creds)
    sg = session.describe_security_groups(GroupIds=[results[0].security_group_id])
    perms = sg["SecurityGroups"][0]["IpPermissions"]
    assert any(p["IpProtocol"] == "-1" for p in perms)


def test_launch_multiple_gets_distinct_names(mock_ec2, creds, ubuntu_ami):
    results = launch.launch(
        creds, launch.LaunchRequest(name="batch", region="us-east-1", count=3)
    )
    assert len(results) == 3
    assert {r.name for r in results} == {"batch-1", "batch-2", "batch-3"}
    assert len({r.instance_id for r in results}) == 3
    assert len({r.security_group_id for r in results}) == 1


def test_disk_size_applied(mock_ec2, creds, ubuntu_ami):
    results = launch.launch(
        creds,
        launch.LaunchRequest(name="node-disk", region="us-east-1", disk_size=32),
    )
    session = aws.ec2(creds)
    inst = session.describe_instances(InstanceIds=[results[0].instance_id])
    mapping = inst["Reservations"][0]["Instances"][0]["BlockDeviceMappings"]
    vol_id = mapping[0]["Ebs"]["VolumeId"]
    vol = session.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]
    assert vol["Size"] == 32


def test_rejects_bad_disk_size(mock_ec2, creds, ubuntu_ami):
    with pytest.raises(launch.LaunchError, match="至少 8 GB"):
        launch.launch(
            creds, launch.LaunchRequest(name="x", region="us-east-1", disk_size=4)
        )


def test_rejects_zero_count(mock_ec2, creds, ubuntu_ami):
    with pytest.raises(launch.LaunchError, match=">= 1"):
        launch.launch(creds, launch.LaunchRequest(name="x", region="us-east-1", count=0))


def test_rejects_unknown_image(mock_ec2, creds):
    with pytest.raises(launch.LaunchError, match="未知镜像"):
        launch.launch(
            creds, launch.LaunchRequest(name="x", region="us-east-1", image_key="no-such")
        )


def test_script_with_shebang_rejected_before_api_call(mock_ec2, creds, ubuntu_ami):
    """脚本非法时必须在调用 RunInstances 之前就失败，不能开出一台废机器。"""
    from aws_helper.core.userdata import ScriptError

    before = len(launch.list_instances(creds, "us-east-1"))
    with pytest.raises(ScriptError):
        launch.launch(
            creds,
            launch.LaunchRequest(
                name="bad", region="us-east-1", script="#!/bin/bash\necho hi"
            ),
        )
    assert len(launch.list_instances(creds, "us-east-1")) == before


def test_list_instances_reports_fields(mock_ec2, creds, ubuntu_ami):
    launch.launch(creds, launch.LaunchRequest(name="listed", region="us-east-1"))
    items = launch.list_instances(creds, "us-east-1")
    assert len(items) == 1
    item = items[0]
    assert item["name"] == "listed"
    assert item["state"] == "running"
    assert item["public_ip"]
    assert item["region"] == "us-east-1"


def test_power_actions(mock_ec2, creds, ubuntu_ami):
    results = launch.launch(creds, launch.LaunchRequest(name="pw", region="us-east-1"))
    iid = results[0].instance_id

    launch.power(creds, "us-east-1", "stop", [iid])
    assert _state(creds, iid) == "stopped"

    launch.power(creds, "us-east-1", "start", [iid])
    assert _state(creds, iid) == "running"

    launch.power(creds, "us-east-1", "terminate", [iid])
    assert _state(creds, iid) in ("shutting-down", "terminated")


def test_power_rejects_unknown_action(mock_ec2, creds):
    with pytest.raises(launch.LaunchError, match="不支持的操作"):
        launch.power(creds, "us-east-1", "explode", ["i-123"])


def test_power_rejects_empty_selection(mock_ec2, creds):
    with pytest.raises(launch.LaunchError, match="至少选择一台"):
        launch.power(creds, "us-east-1", "stop", [])


def test_ipv6_network_creates_dual_stack(mock_ec2, creds, ubuntu_ami):
    """开启 IPv6 时应自建 VPC，并配好 v4/v6 双默认路由。"""
    results = launch.launch(
        creds,
        launch.LaunchRequest(name="node-v6", region="us-east-1", enable_ipv6=True),
    )
    assert results[0].ipv6, "开启 IPv6 后必须返回实际地址"
    session = aws.ec2(creds)
    sg = session.describe_security_groups(GroupIds=[results[0].security_group_id])
    vpc_id = sg["SecurityGroups"][0]["VpcId"]

    vpc = session.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert vpc.get("Ipv6CidrBlockAssociationSet")

    rtb = session.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["RouteTables"][0]
    dests = {
        r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock")
        for r in rtb["Routes"]
    }
    assert "0.0.0.0/0" in dests
    assert "::/0" in dests


def test_reuses_existing_key_pair(mock_ec2, creds, ubuntu_ami):
    session = aws.ec2(creds)
    session.create_key_pair(KeyName="my-existing-key")

    results = launch.launch(
        creds,
        launch.LaunchRequest(
            name="node-key", region="us-east-1", key_name="my-existing-key"
        ),
    )
    assert results[0].key_name == "my-existing-key"
    assert results[0].private_key is None


def _state(creds, instance_id: str) -> str:
    session = aws.ec2(creds)
    resp = session.describe_instances(InstanceIds=[instance_id])
    return resp["Reservations"][0]["Instances"][0]["State"]["Name"]
