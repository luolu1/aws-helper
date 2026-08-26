"""换 IP：两种策略。

- eip：分配新弹性 IP → 绑定 → 释放旧 EIP。不需要停机，IP 立刻生效。
- dynamic：stop → start，让 AWS 重新分配动态公网 IP。需要停机约 30-60 秒，
  且实例必须没有绑定 EIP（绑了 EIP 重启不会换 IP）。

两种策略都会校验新 IP 与旧 IP 不同，并支持 IP 段白名单/黑名单重试。
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from botocore.exceptions import ClientError

from . import aws

ProgressFn = Callable[[str], None]


def _noop(_: str) -> None:
    return None


class IpChangeError(RuntimeError):
    """换 IP 失败。"""


@dataclass
class IpRule:
    """换出来的 IP 需要满足的条件。"""

    # 允许的 CIDR 段，非空时新 IP 必须落在其中之一
    allow_cidrs: list[str] = field(default_factory=list)
    # 禁止的 CIDR 段，新 IP 落在其中则视为不合格
    deny_cidrs: list[str] = field(default_factory=list)
    # 不合格时最多重试几轮
    max_attempts: int = 1

    def matches(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cidr in self.deny_cidrs:
            if _in_cidr(addr, cidr):
                return False
        if self.allow_cidrs:
            return any(_in_cidr(addr, c) for c in self.allow_cidrs)
        return True


def _in_cidr(addr: Any, cidr: str) -> bool:
    try:
        return addr in ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return False


@dataclass
class IpChangeResult:
    instance_id: str
    old_ip: str | None
    new_ip: str
    strategy: str
    attempts: int
    allocation_id: str | None = None
    released: list[str] = field(default_factory=list)


def change_ip(
    creds: aws.Credentials,
    region: str,
    instance_id: str,
    strategy: str = "eip",
    rule: IpRule | None = None,
    progress: ProgressFn = _noop,
) -> IpChangeResult:
    """换掉实例的公网 IPv4。strategy 为 'eip' 或 'dynamic'。"""
    session = aws.ec2(creds, region)
    rule = rule or IpRule()
    if rule.max_attempts < 1:
        raise IpChangeError("max_attempts 必须 >= 1")

    if strategy == "eip":
        return _change_via_eip(session, instance_id, rule, progress)
    if strategy == "dynamic":
        return _change_via_restart(session, instance_id, rule, progress)
    raise IpChangeError(f"未知策略: {strategy}（可选 eip / dynamic）")


def _change_via_eip(
    session: Any, instance_id: str, rule: IpRule, progress: ProgressFn
) -> IpChangeResult:
    inst = _describe(session, instance_id)
    old_ip = inst.get("PublicIpAddress")
    old_assoc = _current_eip(session, instance_id, old_ip)

    released: list[str] = []
    attempts = 0
    tried: list[str] = []
    last_alloc: str | None = None

    while attempts < rule.max_attempts:
        attempts += 1
        progress(f"第 {attempts} 次尝试：正在分配新的弹性 IP")
        alloc = session.allocate_address(Domain="vpc")
        new_ip = alloc["PublicIp"]
        alloc_id = alloc["AllocationId"]
        last_alloc = alloc_id

        if new_ip == old_ip or not rule.matches(new_ip):
            # 不合格，立刻释放再试
            tried.append(new_ip)
            progress(f"新 IP {new_ip} 不满足规则，释放后重试")
            _release(session, alloc_id)
            last_alloc = None
            if attempts >= rule.max_attempts:
                raise IpChangeError(
                    f"连续 {attempts} 次分配的 IP 都不满足规则（{', '.join(tried)}）"
                )
            time.sleep(1)
            continue

        progress(f"正在把 {new_ip} 绑定到实例")
        try:
            session.associate_address(
                AllocationId=alloc_id,
                InstanceId=instance_id,
                AllowReassociation=True,
            )
        except ClientError as exc:
            _release(session, alloc_id)
            raise IpChangeError(f"绑定弹性 IP 失败: {exc}") from exc

        # 先确认新地址已生效，再释放旧的。顺序反过来的话，一旦新地址绑定失败
        # 就会同时丢掉新旧两个 IP，实例彻底失去公网地址。
        confirmed = _wait_public_ip(session, instance_id, expect=new_ip)

        if old_assoc:
            progress("正在释放旧的弹性 IP")
            old_alloc_id = old_assoc.get("AllocationId")
            if old_alloc_id and old_alloc_id != alloc_id:
                _release(session, old_alloc_id)
                released.append(old_assoc.get("PublicIp", ""))

        progress(f"换 IP 完成：{old_ip or '无'} → {confirmed}")
        return IpChangeResult(
            instance_id=instance_id,
            old_ip=old_ip,
            new_ip=confirmed,
            strategy="eip",
            attempts=attempts,
            allocation_id=alloc_id,
            released=[r for r in released if r],
        )

    if last_alloc:
        _release(session, last_alloc)
    raise IpChangeError("换 IP 未成功")


def _change_via_restart(
    session: Any, instance_id: str, rule: IpRule, progress: ProgressFn
) -> IpChangeResult:
    """停机再开机换动态 IP。

    AWS 官方文档（Stop and start Amazon EC2 instances）明确列出两种例外，
    这两种情况下 stop/start 不会分配新的公网 IPv4，必须提前拦住而不是
    重启一遍再发现 IP 没变：
      1. 实例绑定了弹性 IP —— EIP 在 stop/start 期间保持关联
      2. 实例有辅助网卡，或有关联了 EIP 的辅助私有 IPv4
    """
    inst = _describe(session, instance_id)
    old_ip = inst.get("PublicIpAddress")

    eip = _current_eip(session, instance_id, old_ip)
    if eip:
        raise IpChangeError(
            f"实例绑定了弹性 IP {eip.get('PublicIp')}，重启不会更换地址。"
            "请改用 eip 策略，或先在控制台解绑。"
        )

    blocker = _dynamic_ip_blocker(session, inst)
    if blocker:
        raise IpChangeError(
            f"{blocker}，AWS 在这种配置下重启不会分配新的公网 IPv4。请改用 eip 策略。"
        )

    attempts = 0
    tried: list[str] = []
    while attempts < rule.max_attempts:
        attempts += 1
        progress(f"第 {attempts} 次尝试：正在关机")
        session.stop_instances(InstanceIds=[instance_id])
        _wait_state(session, instance_id, "stopped", progress, timeout=300)

        progress("正在开机")
        session.start_instances(InstanceIds=[instance_id])
        _wait_state(session, instance_id, "running", progress, timeout=300)

        new_ip = _wait_public_ip(session, instance_id, exclude=old_ip if attempts == 1 else None)
        if new_ip == old_ip:
            tried.append(new_ip)
            progress(f"IP 没有变化（仍为 {new_ip}），继续重试")
            if attempts >= rule.max_attempts:
                raise IpChangeError(
                    f"重启 {attempts} 次后 IP 仍为 {new_ip}，未能更换"
                )
            continue
        if not rule.matches(new_ip):
            tried.append(new_ip)
            progress(f"新 IP {new_ip} 不满足规则，继续重试")
            if attempts >= rule.max_attempts:
                raise IpChangeError(
                    f"重启 {attempts} 次，IP 都不满足规则（{', '.join(tried)}）"
                )
            continue

        progress(f"换 IP 完成：{old_ip or '无'} → {new_ip}")
        return IpChangeResult(
            instance_id=instance_id,
            old_ip=old_ip,
            new_ip=new_ip,
            strategy="dynamic",
            attempts=attempts,
        )

    raise IpChangeError("换 IP 未成功")


def _dynamic_ip_blocker(session: Any, inst: dict[str, Any]) -> str | None:
    """返回阻止 stop/start 换 IP 的原因，没有则返回 None。"""
    nics = inst.get("NetworkInterfaces") or []
    if len(nics) > 1:
        return f"实例有 {len(nics)} 张网卡（存在辅助网卡）"

    eip_public_ips = {
        addr.get("PublicIp")
        for addr in session.describe_addresses(
            Filters=[{"Name": "instance-id", "Values": [inst["InstanceId"]]}]
        ).get("Addresses", [])
    }
    for nic in nics:
        for private in nic.get("PrivateIpAddresses") or []:
            if private.get("Primary"):
                continue
            assoc = private.get("Association") or {}
            if assoc.get("PublicIp") in eip_public_ips and assoc.get("PublicIp"):
                return (
                    f"辅助私有地址 {private.get('PrivateIpAddress')} "
                    f"关联了弹性 IP {assoc.get('PublicIp')}"
                )
    return None


def _current_eip(
    session: Any, instance_id: str, public_ip: str | None = None
) -> dict[str, Any] | None:
    """查实例当前绑定的弹性 IP。

    实例挂多张网卡时可能返回多条，优先匹配当前生效的公网地址，
    避免误释放另一张网卡上的 EIP。
    """
    resp = session.describe_addresses(
        Filters=[{"Name": "instance-id", "Values": [instance_id]}]
    )
    addrs = resp.get("Addresses", [])
    if not addrs:
        return None
    if public_ip:
        for addr in addrs:
            if addr.get("PublicIp") == public_ip:
                return addr
    return addrs[0]


def _release(session: Any, allocation_id: str) -> None:
    try:
        session.release_address(AllocationId=allocation_id)
    except ClientError:
        # 已释放或已被回收，不影响主流程
        pass


def _wait_state(
    session: Any,
    instance_id: str,
    target: str,
    progress: ProgressFn,
    timeout: int = 300,
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = _describe(session, instance_id).get("State", {}).get("Name")
        if state == target:
            return
        progress(f"当前状态 {state}，等待 {target}")
        time.sleep(3)
    raise IpChangeError(f"等待实例进入 {target} 超时")


def _wait_public_ip(
    session: Any,
    instance_id: str,
    expect: str | None = None,
    exclude: str | None = None,
    timeout: int = 120,
) -> str:
    """等公网 IP 就绪。expect 指定时等到该值，exclude 指定时等到不同于它的值。"""
    deadline = time.time() + timeout
    last: str | None = None
    while time.time() < deadline:
        ip = _describe(session, instance_id).get("PublicIpAddress")
        last = ip
        if ip:
            if expect is not None and ip != expect:
                time.sleep(2)
                continue
            if exclude is not None and ip == exclude:
                time.sleep(2)
                continue
            return ip
        time.sleep(2)
    if last:
        return last
    raise IpChangeError("等待公网 IP 超时，实例可能未分配公网地址")


def _describe(session: Any, instance_id: str) -> dict[str, Any]:
    try:
        resp = session.describe_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if "NotFound" in exc.response.get("Error", {}).get("Code", ""):
            raise IpChangeError(f"找不到实例 {instance_id}") from exc
        raise
    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            if inst["InstanceId"] == instance_id:
                return inst
    raise IpChangeError(f"找不到实例 {instance_id}")


def list_addresses(creds: aws.Credentials, region: str) -> list[dict[str, Any]]:
    """列出区域内的弹性 IP，标出未绑定的和挂在已消失实例上的。

    两种都在计费：`idle` 是完全没绑定，`orphaned` 是绑定记录还在但实例
    已终止或不存在 —— 后者容易被漏掉，因为它看起来是"已绑定"状态。
    """
    session = aws.ec2(creds, region)
    resp = session.describe_addresses()
    addresses = resp.get("Addresses", [])

    attached_ids = {a["InstanceId"] for a in addresses if a.get("InstanceId")}
    alive = _alive_instances(session, attached_ids) if attached_ids else set()

    out = []
    for addr in addresses:
        instance_id = addr.get("InstanceId") or None
        out.append(
            {
                "public_ip": addr.get("PublicIp"),
                "allocation_id": addr.get("AllocationId"),
                "instance_id": instance_id,
                "idle": instance_id is None,
                "orphaned": bool(instance_id) and instance_id not in alive,
            }
        )
    return out


def _alive_instances(session: Any, instance_ids: set[str]) -> set[str]:
    try:
        resp = session.describe_instances(InstanceIds=sorted(instance_ids))
    except ClientError:
        # 有 ID 已不存在时整批查询会失败，此时无法判定，保守视为全部存活
        return set(instance_ids)
    alive = set()
    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            if inst.get("State", {}).get("Name") not in ("terminated", "shutting-down"):
                alive.add(inst["InstanceId"])
    return alive


def release_idle(creds: aws.Credentials, region: str) -> list[str]:
    """释放所有在计费但没在用的弹性 IP（未绑定 + 绑到已消失实例的）。"""
    session = aws.ec2(creds, region)
    freed = []
    for addr in list_addresses(creds, region):
        if (addr["idle"] or addr["orphaned"]) and addr["allocation_id"]:
            _release(session, addr["allocation_id"])
            freed.append(addr["public_ip"])
    return freed
