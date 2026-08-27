"""一键开机：解析镜像 → 密钥对 → 安全组 → RunInstances → 等公网 IP。"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from botocore.exceptions import ClientError

from . import aws
from .userdata import ScriptOptions, render

ProgressFn = Callable[[str], None]


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
                    "launch_time": (
                        inst["LaunchTime"].isoformat()
                        if inst.get("LaunchTime")
                        else ""
                    ),
                }
            )
    out.sort(key=lambda i: i["launch_time"], reverse=True)
    return out


def power(
    creds: aws.Credentials, region: str, action: str, instance_ids: list[str]
) -> dict[str, Any]:
    """电源操作：start / stop / reboot / terminate。"""
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
    resp = fn(InstanceIds=instance_ids)
    return {"ok": True, "action": action, "count": len(instance_ids), "raw": _strip(resp)}


def _strip(resp: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in resp.items() if k != "ResponseMetadata"}
