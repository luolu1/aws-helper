"""Lightsail 轻量实例：套餐、蓝图、实例管理。

和 EC2 是完全不同的 API 和资源模型 —— 套餐（bundle）打包了 CPU/内存/磁盘/流量
并按月定价，镜像叫蓝图（blueprint），没有安全组而是实例级防火墙。
所以单独一个模块，不复用 EC2 的那套抽象。
"""

from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from . import aws

ProgressFn = Callable[[str], None]


def _noop(_: str) -> None:
    return None


class LightsailError(RuntimeError):
    """Lightsail 操作失败。"""


def client(creds: aws.Credentials, region: str) -> Any:
    return aws.client("lightsail", creds, region)


def available_regions(creds: aws.Credentials, region: str = "us-east-1") -> list[str]:
    """Lightsail 支持的区域比 EC2 少，要单独查。"""
    try:
        resp = client(creds, region).get_regions()
    except ClientError as exc:
        raise LightsailError(f"查询 Lightsail 区域失败: {exc}") from exc
    return [item["name"] for item in resp.get("regions", [])]


def list_bundles(creds: aws.Credentials, region: str) -> list[dict[str, Any]]:
    """列出套餐，按月价升序。

    Lightsail 套餐是打包定价（CPU+内存+磁盘+流量），和 EC2 按规格分开
    计费的模型完全不同，所以展示上要把流量额度一起给出来。
    """
    try:
        resp = client(creds, region).get_bundles()
    except ClientError as exc:
        raise LightsailError(f"查询套餐失败: {exc}") from exc

    out = []
    for item in resp.get("bundles", []):
        if not item.get("isActive", True):
            continue
        platform = "windows" if "_win_" in item["bundleId"] else "linux"
        out.append(
            {
                "bundle_id": item["bundleId"],
                "name": item.get("name", item["bundleId"]),
                "price": item.get("price", 0),
                "vcpu": item.get("cpuCount", 0),
                "ram_gb": item.get("ramSizeInGb", 0),
                "disk_gb": item.get("diskSizeInGb", 0),
                "transfer_gb": item.get("transferPerMonthInGb", 0),
                "platform": platform,
                "supports_ipv6_only": "_ipv6_" in item["bundleId"],
                "label": (
                    f"{item['bundleId']} — ${item.get('price', 0)}/月 · "
                    f"{item.get('cpuCount', 0)} vCPU / {item.get('ramSizeInGb', 0)} GB / "
                    f"{item.get('diskSizeInGb', 0)} GB SSD / {item.get('transferPerMonthInGb', 0)} GB 流量"
                ),
            }
        )
    out.sort(key=lambda b: (b["platform"] != "linux", b["price"]))
    return out


def list_blueprints(creds: aws.Credentials, region: str) -> dict[str, list[dict[str, Any]]]:
    """列出蓝图，分成纯系统和预装应用两类。"""
    try:
        resp = client(creds, region).get_blueprints()
    except ClientError as exc:
        raise LightsailError(f"查询蓝图失败: {exc}") from exc

    grouped: dict[str, list[dict[str, Any]]] = {"os": [], "app": []}
    for item in resp.get("blueprints", []):
        if not item.get("isActive", True):
            continue
        kind = item.get("type", "os")
        if kind not in grouped:
            continue
        version = item.get("version", "")
        grouped[kind].append(
            {
                "blueprint_id": item["blueprintId"],
                "name": item.get("name", item["blueprintId"]),
                "version": version,
                "platform": (item.get("platform") or "LINUX_UNIX").lower(),
                "label": f"{item.get('name', '')} {version}".strip()
                + f"（{item['blueprintId']}）",
            }
        )
    for items in grouped.values():
        items.sort(key=lambda b: b["blueprint_id"])
    return grouped


def list_instances(creds: aws.Credentials, region: str) -> list[dict[str, Any]]:
    try:
        resp = client(creds, region).get_instances()
    except ClientError as exc:
        raise LightsailError(f"查询实例失败: {exc}") from exc

    out = []
    for item in resp.get("instances", []):
        hardware = item.get("hardware") or {}
        networking = item.get("networking") or {}
        transfer = (networking.get("monthlyTransfer") or {}).get("gbPerMonthAllocated", 0)
        out.append(
            {
                "name": item["name"],
                "state": (item.get("state") or {}).get("name", "unknown"),
                "blueprint": item.get("blueprintName", ""),
                "bundle_id": item.get("bundleId", ""),
                "public_ip": item.get("publicIpAddress"),
                "private_ip": item.get("privateIpAddress"),
                "ipv6": (item.get("ipv6Addresses") or [None])[0],
                "is_static_ip": item.get("isStaticIp", False),
                "vcpu": hardware.get("cpuCount", 0),
                "ram_gb": hardware.get("ramSizeInGb", 0),
                "transfer_gb": transfer,
                "username": item.get("username", ""),
                "region": region,
                "created_at": (
                    item["createdAt"].isoformat() if item.get("createdAt") else ""
                ),
            }
        )
    out.sort(key=lambda i: i["created_at"], reverse=True)
    return out


def create_instance(
    creds: aws.Credentials,
    region: str,
    name: str,
    bundle_id: str,
    blueprint_id: str,
    availability_zone: str | None = None,
    user_data: str = "",
    key_pair_name: str | None = None,
    progress: ProgressFn = _noop,
) -> dict[str, Any]:
    """创建 Lightsail 实例并等到 running。"""
    if not name.strip():
        raise LightsailError("实例名称必填")
    if not bundle_id:
        raise LightsailError("请选择套餐")
    if not blueprint_id:
        raise LightsailError("请选择蓝图")

    session = client(creds, region)
    zone = availability_zone or f"{region}a"

    params: dict[str, Any] = {
        "instanceNames": [name],
        "availabilityZone": zone,
        "blueprintId": blueprint_id,
        "bundleId": bundle_id,
    }
    if user_data:
        params["userData"] = user_data
    if key_pair_name:
        params["keyPairName"] = key_pair_name

    progress(f"正在创建 Lightsail 实例 {name}（{bundle_id}）")
    try:
        session.create_instances(**params)
    except ClientError as exc:
        raise LightsailError(f"创建失败: {exc}") from exc

    progress("正在等待实例进入 running")
    info = _wait_running(session, name, progress)
    return {
        "name": name,
        "state": (info.get("state") or {}).get("name", "unknown"),
        "public_ip": info.get("publicIpAddress"),
        "username": info.get("username", ""),
        "bundle_id": bundle_id,
        "blueprint_id": blueprint_id,
        "region": region,
    }


def _wait_running(
    session: Any, name: str, progress: ProgressFn, timeout: int = 300
) -> dict[str, Any]:
    import time

    deadline = time.time() + timeout
    last: dict[str, Any] = {}
    while time.time() < deadline:
        try:
            last = session.get_instance(instanceName=name)["instance"]
        except ClientError:
            time.sleep(3)
            continue
        state = (last.get("state") or {}).get("name")
        if state == "running":
            return last
        progress(f"当前状态 {state}")
        time.sleep(4)
    return last


def power(
    creds: aws.Credentials, region: str, action: str, names: list[str]
) -> dict[str, Any]:
    """start / stop / reboot / delete。

    delete 会一并删掉实例挂着的静态 IP —— 未绑定的静态 IP 按月计费，
    和 EC2 的弹性 IP 一样是常见的隐性支出。
    """
    if not names:
        raise LightsailError("请至少选择一台实例")

    session = client(creds, region)
    calls = {
        "start": lambda n: session.start_instance(instanceName=n),
        "stop": lambda n: session.stop_instance(instanceName=n),
        "reboot": lambda n: session.reboot_instance(instanceName=n),
        "delete": lambda n: session.delete_instance(instanceName=n),
    }
    fn = calls.get(action)
    if fn is None:
        raise LightsailError(f"不支持的操作: {action}")

    done: list[str] = []
    failed: list[str] = []
    released: list[str] = []

    if action == "delete":
        released = _release_static_ips(session, names)

    for name in names:
        try:
            fn(name)
            done.append(name)
        except ClientError as exc:
            failed.append(f"{name}: {exc.response.get('Error', {}).get('Code', exc)}")

    result = {"ok": True, "action": action, "done": done, "failed": failed}
    if action == "delete":
        result["released_static_ips"] = released
    return result


def _release_static_ips(session: Any, names: list[str]) -> list[str]:
    """删除挂在这些实例上的静态 IP。未绑定的静态 IP 会一直计费。"""
    released: list[str] = []
    try:
        resp = session.get_static_ips()
    except ClientError:
        return released

    targets = set(names)
    for item in resp.get("staticIps", []):
        if item.get("attachedTo") not in targets:
            continue
        try:
            if item.get("isAttached"):
                session.detach_static_ip(staticIpName=item["name"])
            session.release_static_ip(staticIpName=item["name"])
            released.append(item.get("ipAddress") or item["name"])
        except ClientError:
            continue
    return released


def list_static_ips(creds: aws.Credentials, region: str) -> list[dict[str, Any]]:
    """静态 IP 清单。未附加的在计费，要标出来。"""
    try:
        resp = client(creds, region).get_static_ips()
    except ClientError as exc:
        raise LightsailError(f"查询静态 IP 失败: {exc}") from exc
    return [
        {
            "name": item["name"],
            "ip": item.get("ipAddress", ""),
            "attached_to": item.get("attachedTo") or None,
            "idle": not item.get("isAttached", False),
        }
        for item in resp.get("staticIps", [])
    ]
