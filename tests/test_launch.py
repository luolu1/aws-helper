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


def test_default_security_group_opens_everything(mock_ec2, creds, ubuntu_ami):
    """默认放通全部端口和协议。"""
    results = launch.launch(
        creds, launch.LaunchRequest(name="node-default-sg", region="us-east-1")
    )
    session = aws.ec2(creds)
    sg = session.describe_security_groups(GroupIds=[results[0].security_group_id])
    perms = sg["SecurityGroups"][0]["IpPermissions"]

    assert len(perms) == 1
    assert perms[0]["IpProtocol"] == "-1"
    assert perms[0]["IpRanges"] == [{"CidrIp": "0.0.0.0/0"}]


def test_security_group_opens_only_requested_ports(mock_ec2, creds, ubuntu_ami):
    """显式关掉全放通后，只开指定端口。"""
    results = launch.launch(
        creds,
        launch.LaunchRequest(
            name="node-sg",
            region="us-east-1",
            allow_all_ports=False,
            open_ports=[22, 443],
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


# ---------- CPU 积分模式（unlimited 会产生超额账单） ----------


def test_burstable_family_detection():
    """只看族前缀。非 T 机型传 CreditSpecification 会被 AWS 拒绝。"""
    for t in ("t2.micro", "t3.micro", "t3a.small", "t4g.nano", "T3.LARGE"):
        assert launch.is_burstable(t), t
    for t in ("c5.large", "m6i.large", "c6g.medium", "r5.xlarge", ""):
        assert not launch.is_burstable(t), t


def test_t_instance_launches_as_standard(mock_ec2, creds, ubuntu_ami):
    """T 实例必须显式设成 standard。

    AWS 对 T3/T3a/T4g 的默认值是 unlimited —— 积分耗尽后按超额积分继续计费，
    跑满 CPU 就产生计划外账单。standard 只降速，不多收钱。

    注意：这里断言的是**发出的请求参数**，不是 moto 的返回值。moto 对所有
    机型都返回 standard，把修复整段删掉它照样"通过" —— 那种断言证明不了
    任何事。真实 AWS 的默认值是 unlimited。
    """
    results = launch.launch(
        creds,
        launch.LaunchRequest(
            name="t-node", region="us-east-1", instance_type="t3.micro"
        ),
    )
    assert results[0].instance_id.startswith("i-")

    from unittest.mock import MagicMock

    session = MagicMock()
    session.run_instances.return_value = {"Instances": [{"InstanceId": "i-1"}]}
    session.describe_images.return_value = {"Images": [{"RootDeviceName": "/dev/sda1"}]}
    launch._run_instances(
        session,
        launch.LaunchRequest(name="t", region="us-east-1", instance_type="t3.micro"),
        "ami-1",
        "k",
        "sg-1",
        None,
        "",
    )
    sent = session.run_instances.call_args.kwargs
    assert sent["CreditSpecification"] == {"CpuCredits": "standard"}


def test_credit_spec_omitted_for_non_burstable():
    """非突发机型不能传这个参数，传了 AWS 直接报错。"""
    from unittest.mock import MagicMock

    for itype, expect in (
        ("t3.micro", {"CpuCredits": "standard"}),
        ("t2.small", {"CpuCredits": "standard"}),
        ("t4g.nano", {"CpuCredits": "standard"}),
        ("c5.large", None),
        ("m6i.large", None),
    ):
        session = MagicMock()
        session.run_instances.return_value = {"Instances": [{"InstanceId": "i-1"}]}
        session.describe_images.return_value = {
            "Images": [{"RootDeviceName": "/dev/sda1"}]
        }
        req = launch.LaunchRequest(
            name="n", region="us-east-1", instance_type=itype
        )
        launch._run_instances(session, req, "ami-1", "k", "sg-1", None, "")
        got = session.run_instances.call_args.kwargs.get("CreditSpecification")
        assert got == expect, f"{itype}: {got}"


def test_list_reports_credit_mode(creds):
    """列表要带上积分模式。用 stub 而不是 moto —— moto 对所有机型都回
    standard，无法验证真正读到了 API 返回的值。
    """
    from unittest.mock import MagicMock, patch

    session = MagicMock()
    session.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-9",
                        "InstanceType": "t3.micro",
                        "State": {"Name": "running"},
                    }
                ]
            }
        ]
    }
    session.describe_instance_credit_specifications.return_value = {
        "InstanceCreditSpecifications": [
            {"InstanceId": "i-9", "CpuCredits": "unlimited"}
        ]
    }
    with patch.object(launch.aws, "ec2", return_value=session):
        items = launch.list_instances(creds, "us-east-1")

    assert items[0]["burstable"] is True
    assert items[0]["cpu_credits"] == "unlimited", "要如实反映 AWS 返回的模式"
    sent = session.describe_instance_credit_specifications.call_args.kwargs
    assert sent["InstanceIds"] == ["i-9"]


def test_non_burstable_marked_and_not_queried(mock_ec2, creds, ubuntu_ami):
    """非 T 机型不查积分模式 —— 省一次 API，而且传进去会报错。"""
    from unittest.mock import MagicMock, patch

    session = MagicMock()
    session.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-1",
                        "InstanceType": "c5.large",
                        "State": {"Name": "running"},
                    }
                ]
            }
        ]
    }
    with patch.object(launch.aws, "ec2", return_value=session):
        items = launch.list_instances(creds, "us-east-1")

    assert session.describe_instance_credit_specifications.call_count == 0
    assert items[0]["burstable"] is False
    assert items[0]["cpu_credits"] == ""


def test_credit_query_failure_does_not_break_list(creds):
    """缺 ec2:DescribeInstanceCreditSpecifications 权限时那一列留空，
    但整个实例列表必须照常返回 —— 不能因为一个附加字段拉不到就全挂。
    """
    from unittest.mock import MagicMock, patch

    from botocore.exceptions import ClientError

    session = MagicMock()
    session.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-2",
                        "InstanceType": "t3.micro",
                        "State": {"Name": "running"},
                    }
                ]
            }
        ]
    }
    session.describe_instance_credit_specifications.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "no perm"}},
        "DescribeInstanceCreditSpecifications",
    )
    with patch.object(launch.aws, "ec2", return_value=session):
        items = launch.list_instances(creds, "us-east-1")

    assert len(items) == 1
    assert items[0]["burstable"] is True
    assert items[0]["cpu_credits"] == ""


def test_set_credit_mode_rejects_bad_value(creds):
    with pytest.raises(launch.LaunchError, match="standard 或 unlimited"):
        launch.set_credit_mode(creds, "us-east-1", ["i-1"], "cheap")


def test_set_credit_mode_rejects_empty_ids(creds):
    with pytest.raises(launch.LaunchError, match="请选择实例"):
        launch.set_credit_mode(creds, "us-east-1", [], "standard")


def test_set_credit_mode_sends_standard(creds):
    """moto 没实现 ModifyInstanceCreditSpecification，所以断言发出的参数。"""
    from unittest.mock import MagicMock, patch

    session = MagicMock()
    session.modify_instance_credit_specification.return_value = {
        "SuccessfulInstanceCreditSpecifications": [{"InstanceId": "i-1"}],
        "UnsuccessfulInstanceCreditSpecifications": [],
    }
    with patch.object(launch.aws, "ec2", return_value=session):
        out = launch.set_credit_mode(creds, "us-east-1", ["i-1", "i-2"], "standard")

    sent = session.modify_instance_credit_specification.call_args.kwargs
    assert sent["InstanceCreditSpecifications"] == [
        {"InstanceId": "i-1", "CpuCredits": "standard"},
        {"InstanceId": "i-2", "CpuCredits": "standard"},
    ]
    assert out["mode"] == "standard"
    assert out["succeeded"] == ["i-1"]


def test_set_credit_mode_reports_partial_failure(creds):
    """部分失败要带上原因，不能笼统说「失败」。"""
    from unittest.mock import MagicMock, patch

    session = MagicMock()
    session.modify_instance_credit_specification.return_value = {
        "SuccessfulInstanceCreditSpecifications": [{"InstanceId": "i-1"}],
        "UnsuccessfulInstanceCreditSpecifications": [
            {
                "InstanceId": "i-2",
                "Error": {
                    "Code": "InvalidInstanceType",
                    "Message": "not a burstable instance",
                },
            }
        ],
    }
    with patch.object(launch.aws, "ec2", return_value=session):
        out = launch.set_credit_mode(creds, "us-east-1", ["i-1", "i-2"], "standard")

    assert out["succeeded"] == ["i-1"]
    assert len(out["failed"]) == 1
    assert "not a burstable instance" in out["failed"][0]
