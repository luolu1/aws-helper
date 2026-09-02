"""一键开机：解析镜像 → 密钥对 → 安全组 → RunInstances → 等公网 IP。"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from botocore.exceptions import ClientError

from . import aws
from .userdata import ScriptOptions, render

ProgressFn = Callable[[str], None]

# 突发性能机型族。这些机型的 CPU 积分模式默认值不统一：AWS 对 T2 默认
# standard，对 T3/T3a/T4g 默认 unlimited，而 unlimited 会在积分耗尽后
# 继续按超额积分计费。判断只看族前缀，因为非突发机型传 CreditSpecification
# 会被 AWS 直接拒绝。
_BURSTABLE_FAMILIES = ("t2", "t3", "t3a", "t4g")


def is_burstable(instance_type: str) -> bool:
    family = instance_type.split(".", 1)[0].lower()
    return family in _BURSTABLE_FAMILIES


def _noop(_: str) -> None:
    return None


@dataclass
class LaunchRequest:
    """一次开机请求的全部参数。"""

    name: str
    region: str
    instance_type: str = "t3.micro"
    image_key: str = "ubuntu-24.04"
    # 直接指定 AMI ID 时跳过 image_key 的名称查找，用于自定义/私有镜像
    image_id: str | None = None
    disk_size: int = 16
    disk_type: str = "gp3"
    count: int = 1
    # 默认放通全部端口（allow_all_ports=True）。取消勾选后才按 open_ports 逐个开。
    open_ports: list[int] = field(default_factory=lambda: [22])
    open_cidr: str = "0.0.0.0/0"
    allow_all_ports: bool = True
    assign_public_ip: bool = True
    enable_ipv6: bool = False
    # 开机脚本
    script: str = ""
    root_password: str | None = None
    packages: list[str] = field(default_factory=list)
    set_hostname: bool = True
    # 密钥对：留空则新建并返回私钥
    key_name: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class LaunchResult:
    """单台实例的开机结果。"""

    instance_id: str
    name: str
    region: str
    public_ip: str | None
    private_ip: str | None
    ipv6: str | None
    image_id: str
    instance_type: str
    key_name: str
    private_key: str | None
    security_group_id: str
    ssh_user: str
    state: str
    os_family: str = "linux"


class LaunchError(RuntimeError):
    """开机失败。"""


def launch(
    creds: aws.Credentials,
    req: LaunchRequest,
    progress: ProgressFn = _noop,
) -> list[LaunchResult]:
    """执行开机。count > 1 时返回多条结果，共用同一个安全组和密钥对。"""
    if req.count < 1:
        raise LaunchError("创建数量必须 >= 1")
    if req.disk_size < 8:
        raise LaunchError("磁盘容量至少 8 GB")

    spec = aws.IMAGES.get(req.image_key)
    if spec is None and not req.image_id:
        if not req.image_key:
            raise LaunchError(
                "没有选择镜像。该系统类别与架构的组合下没有可用镜像"
                "（例如 AWS 未发布 ARM64 的 Windows Server），"
                "请换个组合，或在「指定 AMI ID」里手动填一个"
            )
        raise LaunchError(f"未知镜像: {req.image_key}")
    ssh_user = spec.ssh_user if spec else "ubuntu"
    is_windows = bool(spec and spec.is_windows)

    # 参数校验全部前置：任何 AWS 资源都还没创建，失败时无需清理
    if is_windows:
        # Windows 的 cloud-init 是 EC2Launch，不吃 bash 脚本；
        # 静默注入一段无效脚本比直接报错更难排查。
        if req.root_password:
            raise LaunchError(
                "Windows 镜像不支持设置 root 密码。"
                "管理员密码由 AWS 生成，开机后用密钥对在控制台解密获取。"
            )
        if req.script.strip() or req.packages:
            raise LaunchError(
                "Windows 镜像不支持 Linux 开机脚本和 apt/yum 预装包。"
                "如需自动化请自行在「指定 AMI ID」配合 PowerShell 方案。"
            )
        progress("Windows 镜像：跳过 Linux 开机脚本")
        user_data = ""
    else:
        progress("正在渲染开机脚本")
        user_data = render(
            ScriptOptions(
                custom_script=req.script,
                root_password=req.root_password,
                hostname=req.name if req.set_hostname else None,
                packages=req.packages,
            )
        )

    session = aws.ec2(creds, req.region)

    if req.image_id:
        progress(f"使用指定的 AMI {req.image_id}")
        image_id = req.image_id
    else:
        progress("正在解析镜像 AMI")
        image_id = aws.resolve_ami(session, req.image_key, creds, req.region)

    progress("正在准备密钥对")
    key_name, private_key = _ensure_key_pair(session, req)

    progress("正在准备安全组")
    sg_id, vpc_id, subnet_id = _ensure_network(session, req, progress)

    progress(f"正在创建 {req.count} 台实例")
    instance_ids = _run_instances(
        session, req, image_id, key_name, sg_id, subnet_id, user_data
    )

    progress("正在等待实例进入 running")
    _wait_running(session, instance_ids, progress)

    results: list[LaunchResult] = []
    for idx, iid in enumerate(instance_ids):
        info = _describe(session, iid)
        ipv6 = _instance_ipv6(info)
        if req.enable_ipv6 and not ipv6:
            progress(f"正在为 {iid} 补分配 IPv6 地址")
            ipv6 = _assign_ipv6(session, info)
        results.append(
            LaunchResult(
                instance_id=iid,
                name=_instance_name(req, idx),
                region=req.region,
                public_ip=info.get("PublicIpAddress"),
                private_ip=info.get("PrivateIpAddress"),
                ipv6=ipv6,
                image_id=image_id,
                instance_type=req.instance_type,
                key_name=key_name,
                private_key=private_key,
                security_group_id=sg_id,
                ssh_user=ssh_user,
                state=info.get("State", {}).get("Name", "unknown"),
                os_family="windows" if is_windows else "linux",
            )
        )
    progress("开机完成")
    return results


def _instance_name(req: LaunchRequest, idx: int) -> str:
    return req.name if req.count == 1 else f"{req.name}-{idx + 1}"


def _instance_ipv6(info: dict[str, Any]) -> str | None:
    for nic in info.get("NetworkInterfaces") or []:
        for addr in nic.get("Ipv6Addresses") or []:
            if addr.get("Ipv6Address"):
                return addr["Ipv6Address"]
    return None


def _assign_ipv6(session: Any, info: dict[str, Any]) -> str | None:
    """RunInstances 的 Ipv6AddressCount 未生效时，事后补分配一个地址。

    子网已带 /64 段且开了 AssignIpv6AddressOnCreation，仍可能拿不到地址，
    此时显式调 AssignIpv6Addresses 补上，失败不影响实例可用性。
    """
    nics = info.get("NetworkInterfaces") or []
    if not nics:
        return None
    try:
        resp = session.assign_ipv6_addresses(
            NetworkInterfaceId=nics[0]["NetworkInterfaceId"], Ipv6AddressCount=1
        )
        assigned = resp.get("AssignedIpv6Addresses") or []
        return assigned[0] if assigned else None
    except ClientError:
        return None


def _ensure_key_pair(session: Any, req: LaunchRequest) -> tuple[str, str | None]:
    """复用已有密钥对，或新建一个并返回私钥内容。

    新建时必须把 KeyMaterial 交回调用方保存 —— AWS 只在创建时返回一次。
    """
    if req.key_name:
        try:
            session.describe_key_pairs(KeyNames=[req.key_name])
            return req.key_name, None
        except ClientError as exc:
            if _code(exc) != "InvalidKeyPair.NotFound":
                raise
            # 指定的密钥不存在，按该名字新建

    name = req.key_name or f"awshelper-{req.name}-{int(time.time())}"
    resp = session.create_key_pair(KeyName=name, KeyType="rsa")
    return name, resp.get("KeyMaterial")


def _ensure_network(
    session: Any, req: LaunchRequest, progress: ProgressFn
) -> tuple[str, str, str | None]:
    """返回 (security_group_id, vpc_id, subnet_id)。

    默认复用默认 VPC。开启 IPv6 时新建带 IPv6 CIDR 的 VPC 全套网络。
    """
    if req.enable_ipv6:
        return _create_ipv6_network(session, req, progress)

    vpc_id = _default_vpc(session)
    subnet_id = _default_subnet(session, vpc_id)
    sg_id = _create_security_group(session, req, vpc_id)
    return sg_id, vpc_id, subnet_id


def _default_vpc(session: Any) -> str:
    resp = session.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["true"]}]
    )
    vpcs = resp.get("Vpcs", [])
    if vpcs:
        return vpcs[0]["VpcId"]
    # 没有默认 VPC 时退回任意可用 VPC
    resp = session.describe_vpcs()
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        raise LaunchError("该区域没有可用 VPC，请先在控制台创建，或勾选 IPv6 让工具自建")
    return vpcs[0]["VpcId"]


def _default_subnet(session: Any, vpc_id: str) -> str | None:
    resp = session.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )
    subnets = resp.get("Subnets", [])
    if not subnets:
        return None
    # 优先选自动分配公网 IP 的子网
    for sn in subnets:
        if sn.get("MapPublicIpOnLaunch"):
            return sn["SubnetId"]
    return subnets[0]["SubnetId"]


def _create_security_group(session: Any, req: LaunchRequest, vpc_id: str) -> str:
    name = f"awshelper-{req.name}-{int(time.time())}"
    resp = session.create_security_group(
        GroupName=name,
        Description=f"aws-helper for {req.name}",
        VpcId=vpc_id,
    )
    sg_id = resp["GroupId"]

    if req.allow_all_ports:
        perms: list[dict[str, Any]] = [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": req.open_cidr}],
            }
        ]
        if req.enable_ipv6:
            perms[0]["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]
    else:
        ports = sorted({int(p) for p in req.open_ports}) or [22]
        perms = []
        for port in ports:
            if not 1 <= port <= 65535:
                raise LaunchError(f"端口越界: {port}")
            rule: dict[str, Any] = {
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": req.open_cidr}],
            }
            if req.enable_ipv6:
                rule["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]
            perms.append(rule)

    session.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=perms)
    return sg_id


def _create_ipv6_network(
    session: Any, req: LaunchRequest, progress: ProgressFn
) -> tuple[str, str, str]:
    """建一套带 IPv6 的完整网络：VPC → 子网 → IGW → 路由表。"""
    progress("正在创建 VPC（含 IPv6 段）")
    vpc = session.create_vpc(
        CidrBlock="172.31.0.0/16", AmazonProvidedIpv6CidrBlock=True
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    session.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    ipv6_cidr = _wait_vpc_ipv6(session, vpc_id)
    # /56 切出一个 /64 给子网
    subnet_v6 = _first_v64(ipv6_cidr)

    progress("正在创建子网")
    subnet = session.create_subnet(
        VpcId=vpc_id,
        CidrBlock="172.31.0.0/20",
        Ipv6CidrBlock=subnet_v6,
    )
    subnet_id = subnet["Subnet"]["SubnetId"]
    session.modify_subnet_attribute(
        SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True}
    )
    session.modify_subnet_attribute(
        SubnetId=subnet_id, AssignIpv6AddressOnCreation={"Value": True}
    )

    progress("正在创建互联网网关与路由")
    igw = session.create_internet_gateway()
    igw_id = igw["InternetGateway"]["InternetGatewayId"]
    session.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb = session.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )
    rtb_id = rtb["RouteTables"][0]["RouteTableId"]
    session.create_route(
        RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id
    )
    session.create_route(
        RouteTableId=rtb_id, DestinationIpv6CidrBlock="::/0", GatewayId=igw_id
    )
    session.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)

    sg_id = _create_security_group(session, req, vpc_id)
    return sg_id, vpc_id, subnet_id


def _wait_vpc_ipv6(session: Any, vpc_id: str, timeout: int = 60) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = session.describe_vpcs(VpcIds=[vpc_id])
        assoc = resp["Vpcs"][0].get("Ipv6CidrBlockAssociationSet") or []
        for item in assoc:
            cidr = item.get("Ipv6CidrBlock")
            if cidr:
                return cidr
        time.sleep(2)
    raise LaunchError("等待 VPC 分配 IPv6 段超时")


def _first_v64(ipv6_cidr: str) -> str:
    """从 /56 段切出第一个 /64。"""
    import ipaddress

    net = ipaddress.IPv6Network(ipv6_cidr, strict=False)
    if net.prefixlen >= 64:
        return str(net)
    return str(next(net.subnets(new_prefix=64)))


def _run_instances(
    session: Any,
    req: LaunchRequest,
    image_id: str,
    key_name: str,
    sg_id: str,
    subnet_id: str | None,
    user_data: str,
) -> list[str]:
    params: dict[str, Any] = {
        "ImageId": image_id,
        "InstanceType": req.instance_type,
        "KeyName": key_name,
        "MinCount": req.count,
        "MaxCount": req.count,
        "BlockDeviceMappings": [
            {
                "DeviceName": _root_device(session, image_id),
                "Ebs": {
                    "VolumeSize": req.disk_size,
                    "VolumeType": req.disk_type,
                    "DeleteOnTermination": True,
                },
            }
        ],
    }

    # T 系列强制 standard。AWS 对 T3/T3a/T4g 的默认值是 unlimited，
    # 那会在 CPU 积分耗尽后继续按超额积分计费 —— 突发流量或跑满 CPU 就产生
    # 计划外账单。standard 模式积分用完只降速，绝不多收钱。
    # 只对 T 系列传：非突发机型传这个参数 AWS 会直接报错。
    if is_burstable(req.instance_type):
        params["CreditSpecification"] = {"CpuCredits": "standard"}

    # 空 UserData 就别传（Windows 路径），传空串等于给 cloud-init 一份空脚本
    if user_data:
        params["UserData"] = user_data

    tags = [{"Key": "Name", "Value": req.name}, {"Key": "ManagedBy", "Value": "aws-helper"}]
    tags += [{"Key": k, "Value": v} for k, v in req.tags.items()]
    params["TagSpecifications"] = [{"ResourceType": "instance", "Tags": tags}]

    # 网络接口和顶层 SecurityGroupIds/SubnetId 互斥，只能用一种
    if subnet_id:
        nic: dict[str, Any] = {
            "DeviceIndex": 0,
            "SubnetId": subnet_id,
            "Groups": [sg_id],
            "AssociatePublicIpAddress": req.assign_public_ip,
            "DeleteOnTermination": True,
        }
        if req.enable_ipv6:
            nic["Ipv6AddressCount"] = 1
        params["NetworkInterfaces"] = [nic]
    else:
        params["SecurityGroupIds"] = [sg_id]

    resp = session.run_instances(**params)
    ids = [i["InstanceId"] for i in resp.get("Instances", [])]
    if not ids:
        raise LaunchError("RunInstances 未返回实例 ID")

    # count > 1 时逐台改名，便于区分
    if req.count > 1:
        for idx, iid in enumerate(ids):
            session.create_tags(
                Resources=[iid],
                Tags=[{"Key": "Name", "Value": _instance_name(req, idx)}],
            )
    return ids


def _root_device(session: Any, image_id: str) -> str:
    """读镜像的根设备名。Debian/Ubuntu 多为 /dev/xvda，AL2023 为 /dev/xvda。"""
    try:
        resp = session.describe_images(ImageIds=[image_id])
        images = resp.get("Images", [])
        if images:
            name = images[0].get("RootDeviceName")
            if name:
                return name
    except ClientError:
        pass
    return "/dev/xvda"


def _wait_running(
    session: Any, instance_ids: list[str], progress: ProgressFn, timeout: int = 300
) -> None:
    deadline = time.time() + timeout
    pending = set(instance_ids)
    while pending and time.time() < deadline:
        resp = session.describe_instances(InstanceIds=list(pending))
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                state = inst.get("State", {}).get("Name")
                if state == "running":
                    pending.discard(inst["InstanceId"])
                elif state in ("terminated", "shutting-down"):
                    raise LaunchError(
                        f"实例 {inst['InstanceId']} 进入 {state}，开机失败"
                    )
        if pending:
            progress(f"等待 {len(pending)} 台实例启动")
            time.sleep(3)
    if pending:
        raise LaunchError(f"等待实例 running 超时: {', '.join(sorted(pending))}")


def _describe(session: Any, instance_id: str) -> dict[str, Any]:
    resp = session.describe_instances(InstanceIds=[instance_id])
    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            if inst["InstanceId"] == instance_id:
                return inst
    raise LaunchError(f"找不到实例 {instance_id}")


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _credit_modes(session: Any, instance_ids: list[str]) -> dict[str, str]:
    """查每台 T 实例的 CPU 积分模式。

    单独一次调用而不是从 describe_instances 里读 —— DescribeInstances 的返回
    里根本没有这个字段。只查突发机型：非 T 机型传进去会报 InvalidInstanceID。
    查不到不算失败，那一列显示为空好过整个列表拉不出来。
    """
    if not instance_ids:
        return {}
    try:
        resp = session.describe_instance_credit_specifications(
            InstanceIds=instance_ids
        )
    except ClientError:
        return {}
    return {
        item["InstanceId"]: item.get("CpuCredits", "")
        for item in resp.get("InstanceCreditSpecifications", [])
    }


def set_credit_mode(
    creds: aws.Credentials, region: str, instance_ids: list[str], mode: str
) -> dict[str, Any]:
    """改 CPU 积分模式。unlimited 会按超额积分计费，standard 只降速。"""
    if mode not in ("standard", "unlimited"):
        raise LaunchError("积分模式只能是 standard 或 unlimited")
    if not instance_ids:
        raise LaunchError("请选择实例")

    session = aws.ec2(creds, region)
    try:
        resp = session.modify_instance_credit_specification(
            InstanceCreditSpecifications=[
                {"InstanceId": i, "CpuCredits": mode} for i in instance_ids
            ]
        )
    except ClientError as exc:
        raise LaunchError(f"修改积分模式失败: {exc}") from exc

    return {
        "mode": mode,
        "succeeded": [
            x["InstanceId"] for x in resp.get("SuccessfulInstanceCreditSpecifications", [])
        ],
        "failed": [
            f"{x['InstanceId']}: {(x.get('Error') or {}).get('Message', '未知错误')}"
            for x in resp.get("UnsuccessfulInstanceCreditSpecifications", [])
        ],
    }


def list_instances(creds: aws.Credentials, region: str) -> list[dict[str, Any]]:
    """列出区域内所有非终止实例。"""
    session = aws.ec2(creds, region)
    resp = session.describe_instances(
        Filters=[
            {
                "Name": "instance-state-name",
                "Values": ["pending", "running", "stopping", "stopped"],
            }
        ]
    )
    burstable_ids = [
        inst["InstanceId"]
        for res in resp.get("Reservations", [])
        for inst in res.get("Instances", [])
        if is_burstable(inst.get("InstanceType", ""))
    ]
    credits = _credit_modes(session, burstable_ids)
    out: list[dict[str, Any]] = []
    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            name = ""
            for tag in inst.get("Tags") or []:
                if tag.get("Key") == "Name":
                    name = tag.get("Value", "")
            nics = inst.get("NetworkInterfaces") or []
            ipv6 = None
            if nics:
                v6 = nics[0].get("Ipv6Addresses") or []
                if v6:
                    ipv6 = v6[0].get("Ipv6Address")
            out.append(
                {
                    "instance_id": inst["InstanceId"],
                    "name": name,
                    "state": inst.get("State", {}).get("Name", ""),
                    "instance_type": inst.get("InstanceType", ""),
                    "public_ip": inst.get("PublicIpAddress"),
                    "private_ip": inst.get("PrivateIpAddress"),
                    "ipv6": ipv6,
                    "region": region,
                    "key_name": inst.get("KeyName", ""),
                    # Windows 实例的 Platform 才是 "windows"，Linux 上这个字段
                    # 直接不存在（不是空串）—— 重置密码要用它决定发 shell
                    # 还是 PowerShell 脚本。
                    "platform": inst.get("Platform") or "linux",
                    "burstable": is_burstable(inst.get("InstanceType", "")),
                    "cpu_credits": credits.get(inst["InstanceId"], ""),
                    "iam_profile": (inst.get("IamInstanceProfile") or {}).get("Arn", ""),
                    "launch_time": (
                        inst["LaunchTime"].isoformat()
                        if inst.get("LaunchTime")
                        else ""
                    ),
                }
            )
    # 同批开机的实例 launch_time 精确到秒是相同的，只按它排序时 AWS 返回顺序
    # 一变，列表顺序就变 —— 页面上行会莫名跳动，前端算的指纹也会误判「变了」。
    out.sort(key=lambda i: (i["launch_time"], i["instance_id"]), reverse=True)
    return out


def power(
    creds: aws.Credentials,
    region: str,
    action: str,
    instance_ids: list[str],
    cleanup: bool = True,
    progress: ProgressFn = _noop,
) -> dict[str, Any]:
    """电源操作：start / stop / reboot / terminate。

    terminate 且 cleanup=True 时，连带清理会继续计费或占配额的关联资源。
    """
    session = aws.ec2(creds, region)
    calls = {
        "start": session.start_instances,
        "stop": session.stop_instances,
        "reboot": session.reboot_instances,
        "terminate": session.terminate_instances,
    }
    fn = calls.get(action)
    if fn is None:
        raise LaunchError(f"不支持的操作: {action}")
    if not instance_ids:
        raise LaunchError("请至少选择一台实例")

    if action == "terminate" and cleanup:
        return terminate_and_cleanup(creds, region, instance_ids, progress)

    resp = fn(InstanceIds=instance_ids)
    return {"ok": True, "action": action, "count": len(instance_ids), "raw": _strip(resp)}


def collect_related_resources(
    session: Any, instance_ids: list[str]
) -> dict[str, Any]:
    """在终止之前把关联资源记下来。

    终止后 AWS 会逐步解除标签和关联，届时再查就找不到这些资源了，
    必须先采集。
    """
    found: dict[str, Any] = {
        "volumes": [],
        "addresses": [],
        "security_groups": [],
        "key_pairs": [],
        "network_interfaces": [],
        "vpcs": [],
    }

    resp = session.describe_instances(InstanceIds=instance_ids)
    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            for mapping in inst.get("BlockDeviceMappings") or []:
                ebs = mapping.get("Ebs") or {}
                if ebs.get("VolumeId"):
                    found["volumes"].append(ebs["VolumeId"])
            if inst.get("KeyName"):
                found["key_pairs"].append(inst["KeyName"])
            for nic in inst.get("NetworkInterfaces") or []:
                if nic.get("NetworkInterfaceId"):
                    found["network_interfaces"].append(nic["NetworkInterfaceId"])
                for group in nic.get("Groups") or []:
                    found["security_groups"].append(group["GroupId"])
                if nic.get("VpcId"):
                    found["vpcs"].append(nic["VpcId"])
            for group in inst.get("SecurityGroups") or []:
                found["security_groups"].append(group["GroupId"])
            if inst.get("VpcId"):
                found["vpcs"].append(inst["VpcId"])

    addrs = session.describe_addresses(
        Filters=[{"Name": "instance-id", "Values": instance_ids}]
    )
    for addr in addrs.get("Addresses", []):
        if addr.get("AllocationId"):
            found["addresses"].append(
                {
                    "allocation_id": addr["AllocationId"],
                    "public_ip": addr.get("PublicIp", ""),
                }
            )

    for key in ("volumes", "security_groups", "key_pairs", "network_interfaces", "vpcs"):
        found[key] = sorted(set(found[key]))
    return found


def terminate_and_cleanup(
    creds: aws.Credentials,
    region: str,
    instance_ids: list[str],
    progress: ProgressFn = _noop,
) -> dict[str, Any]:
    """终止实例并清理会残留计费的资源。

    按 AWS 官方文档，终止实例后这些仍然计费或占配额：
      - 弹性 IP：解绑但仍分配在账户下，未绑定按小时计费
      - EBS 卷：DeleteOnTermination=false 的卷会保留并持续计费
      - 安全组 / 密钥对 / 自建 VPC：不计费但占配额，堆积后无法创建新资源

    删除顺序有依赖：卷和网卡要等实例真的终止，安全组要等网卡释放，
    VPC 要等里面所有东西都清空。任何一步失败都记进 failed 而不中断，
    尽最大努力清理。
    """
    session = aws.ec2(creds, region)

    progress("正在采集关联资源")
    resources = collect_related_resources(session, instance_ids)

    cleaned: dict[str, list[str]] = {
        "instances": [],
        "addresses": [],
        "volumes": [],
        "security_groups": [],
        "key_pairs": [],
        "vpcs": [],
    }
    failed: list[str] = []

    # 先释放弹性 IP：这是唯一会持续产生真实费用的项，优先止损
    for addr in resources["addresses"]:
        try:
            session.release_address(AllocationId=addr["allocation_id"])
            cleaned["addresses"].append(addr["public_ip"] or addr["allocation_id"])
            progress(f"已释放弹性 IP {addr['public_ip']}")
        except ClientError as exc:
            failed.append(f"弹性 IP {addr['public_ip']}: {_code(exc) or exc}")

    progress(f"正在终止 {len(instance_ids)} 台实例")
    try:
        session.terminate_instances(InstanceIds=instance_ids)
        cleaned["instances"] = list(instance_ids)
    except ClientError as exc:
        raise LaunchError(f"终止实例失败: {exc}") from exc

    progress("正在等待实例完全终止")
    _wait_terminated(session, instance_ids, progress)

    for volume_id in resources["volumes"]:
        try:
            info = session.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
        except ClientError:
            continue  # 随实例一起删掉了
        if info.get("State") == "deleted":
            continue
        try:
            session.delete_volume(VolumeId=volume_id)
            cleaned["volumes"].append(volume_id)
            progress(f"已删除残留卷 {volume_id}")
        except ClientError as exc:
            failed.append(f"卷 {volume_id}: {_code(exc) or exc}")

    for group_id in resources["security_groups"]:
        try:
            info = session.describe_security_groups(GroupIds=[group_id])
        except ClientError:
            continue
        groups = info.get("SecurityGroups") or []
        if not groups or groups[0].get("GroupName") == "default":
            continue  # 默认安全组删不掉也不该删
        try:
            session.delete_security_group(GroupId=group_id)
            cleaned["security_groups"].append(group_id)
            progress(f"已删除安全组 {group_id}")
        except ClientError as exc:
            failed.append(f"安全组 {group_id}: {_code(exc) or exc}")

    # 只删本工具建的密钥对，用户自己的不动
    for key_name in resources["key_pairs"]:
        if not key_name.startswith("awshelper-"):
            continue
        try:
            session.delete_key_pair(KeyName=key_name)
            cleaned["key_pairs"].append(key_name)
            progress(f"已删除密钥对 {key_name}")
        except ClientError as exc:
            failed.append(f"密钥对 {key_name}: {_code(exc) or exc}")

    for vpc_id in resources["vpcs"]:
        if _delete_vpc_if_ours(session, vpc_id, progress, failed):
            cleaned["vpcs"].append(vpc_id)

    return {
        "ok": True,
        "action": "terminate",
        "count": len(instance_ids),
        "cleaned": cleaned,
        "failed": failed,
    }


def _wait_terminated(
    session: Any, instance_ids: list[str], progress: ProgressFn, timeout: int = 300
) -> None:
    deadline = time.time() + timeout
    pending = set(instance_ids)
    while pending and time.time() < deadline:
        try:
            resp = session.describe_instances(InstanceIds=list(pending))
        except ClientError:
            return
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") == "terminated":
                    pending.discard(inst["InstanceId"])
        if pending:
            progress(f"等待 {len(pending)} 台实例终止")
            time.sleep(3)


def _delete_vpc_if_ours(
    session: Any, vpc_id: str, progress: ProgressFn, failed: list[str]
) -> bool:
    """删除本工具为 IPv6 双栈自建的 VPC。

    默认 VPC 和还有别的实例在用的 VPC 一律不动 —— 误删会打断用户其他业务。
    """
    try:
        info = session.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    except ClientError:
        return False
    if info.get("IsDefault"):
        return False

    try:
        live = session.describe_instances(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                },
            ]
        )
        if any(r.get("Instances") for r in live.get("Reservations", [])):
            return False
    except ClientError:
        return False

    try:
        for nic in session.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("NetworkInterfaces", []):
            if nic.get("Status") == "available":
                session.delete_network_interface(
                    NetworkInterfaceId=nic["NetworkInterfaceId"]
                )

        for igw in session.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        ).get("InternetGateways", []):
            session.detach_internet_gateway(
                InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id
            )
            session.delete_internet_gateway(
                InternetGatewayId=igw["InternetGatewayId"]
            )

        # 路由表关联要先解除，否则子网删不掉；main 路由表随 VPC 一起走
        for table in session.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("RouteTables", []):
            is_main = any(a.get("Main") for a in table.get("Associations") or [])
            for assoc in table.get("Associations") or []:
                if not assoc.get("Main") and assoc.get("RouteTableAssociationId"):
                    session.disassociate_route_table(
                        AssociationId=assoc["RouteTableAssociationId"]
                    )
            if not is_main:
                session.delete_route_table(RouteTableId=table["RouteTableId"])

        for subnet in session.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("Subnets", []):
            session.delete_subnet(SubnetId=subnet["SubnetId"])

        for group in session.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("SecurityGroups", []):
            if group.get("GroupName") != "default":
                session.delete_security_group(GroupId=group["GroupId"])

        session.delete_vpc(VpcId=vpc_id)
        progress(f"已删除自建 VPC {vpc_id}")
        return True
    except ClientError as exc:
        failed.append(f"VPC {vpc_id}: {_code(exc) or exc}")
        return False


def _strip(resp: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in resp.items() if k != "ResponseMetadata"}
