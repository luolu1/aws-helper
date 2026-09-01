"""DDNS：公网 IP 变了自动更新 DNS 解析。

面板部署在动态 IP 的机器上时（家宽、部分 VPS），IP 一变域名就失效。
这一栏做的是：定期探测本机公网 IP，和 DNS 上的记录比对，变了才更新。

设计上和 EC2 的自动换 IP 是相反方向的两件事：
- 自动换 IP —— 实例的 IP 被墙了，换一个新 IP
- DDNS      —— 本机 IP 变了，让域名指到新 IP

供应商用 Protocol 抽象，现在实现 Cloudflare。加新供应商只要写一个类，
不用动监控循环和页面。
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator, Protocol

# 与 AWS_HELPER_ENDPOINT_URL 同理：本地起假服务端做联调时覆盖，平时不设
CF_API = os.environ.get("AWS_HELPER_CF_API", "https://api.cloudflare.com/client/v4")

# 取本机公网 IP 的探测点。v4 和 v6 必须分开问 —— api.ipify.org 只有 A 记录，
# 强制走 v6 会直接连不上，那不是"没有 v6"而是探测点本身不支持。
IPV4_SOURCES: tuple[str, ...] = (
    "https://one.one.one.one/cdn-cgi/trace",
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
)
IPV6_SOURCES: tuple[str, ...] = (
    "https://one.one.one.one/cdn-cgi/trace",
    "https://api6.ipify.org",
    "https://ipv6.icanhazip.com",
)

# Cloudflare 的 ttl=1 表示"自动"（内部 300 秒）。代理开启时 TTL 被强制为自动
# 且不可改，传数字会被拒。
TTL_AUTO = 1


class DdnsError(RuntimeError):
    """DDNS 操作失败。"""


@dataclass
class DnsRecord:
    """DNS 上已存在的记录。update 时要原样带回 proxied/ttl，别覆盖用户的设置。"""

    record_id: str
    name: str
    type: str
    content: str
    ttl: int = TTL_AUTO
    proxied: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class UpdateResult:
    hostname: str
    record_type: str
    action: str
    ip: str
    old_ip: str = ""
    detail: str = ""


class DnsProvider(Protocol):
    """DNS 供应商接口。加新供应商实现这四个方法即可。"""

    kind: str

    def zone_id(self, zone: str) -> str: ...

    def find_record(self, zone: str, hostname: str, record_type: str) -> DnsRecord | None: ...

    def create_record(
        self, zone: str, hostname: str, record_type: str, ip: str, *, ttl: int, proxied: bool
    ) -> DnsRecord: ...

    def update_record(self, zone: str, record: DnsRecord, ip: str) -> DnsRecord: ...


# ---------------- 取本机公网 IP ----------------


@contextmanager
def _force_family(family: int) -> Iterator[None]:
    """把 getaddrinfo 钉在指定地址族上，等价于 curl -4 / -6。

    urllib 不给切换地址族的入口。不钉住的话，同一个域名可能解析到 v6，
    "取 IPv4"就取回一个 v6 地址，写进 A 记录直接失败。
    """
    original = socket.getaddrinfo

    def patched(host: Any, port: Any, _family: int = 0, *args: Any, **kwargs: Any) -> Any:
        return original(host, port, family, *args, **kwargs)

    socket.getaddrinfo = patched  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = original  # type: ignore[assignment]


def _parse_body(url: str, body: str) -> str:
    """cdn-cgi/trace 是 key=value 行，不是 JSON；其余探测点直接回一行 IP。"""
    if "cdn-cgi/trace" in url:
        for line in body.splitlines():
            if line.startswith("ip="):
                return line[3:].strip()
        return ""
    return body.strip()


def detect_ip(version: int = 4, sources: tuple[str, ...] | None = None, timeout: float = 8.0) -> str:
    """取本机公网 IP。拿不到返回空串，不抛异常。

    单个探测点会挂、会限流、会返回垃圾，所以按顺序试多个，并且用
    ipaddress 校验版本对得上 —— 探测点偶尔会回一个 v4 映射地址或错误页。
    """
    if version not in (4, 6):
        raise ValueError(f"未知 IP 版本: {version}")

    family = socket.AF_INET if version == 4 else socket.AF_INET6
    for url in sources or (IPV4_SOURCES if version == 4 else IPV6_SOURCES):
        try:
            with _force_family(family):
                request = urllib.request.Request(url, headers={"User-Agent": "aws-helper-ddns"})
                with urllib.request.urlopen(request, timeout=timeout) as resp:
                    body = resp.read(4096).decode("utf-8", "replace")
        except Exception:
            continue

        candidate = _parse_body(url, body)
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if parsed.version == version:
            return str(parsed)
    return ""


# ---------------- Cloudflare ----------------


class CloudflareProvider:
    """Cloudflare DNS。用 API Token（不是 Global API Key）。

    Token 需要 Zone -> DNS -> Edit 权限，用控制台的「编辑区域 DNS」模板即可。
    Global Key 是账号级全权限，放在一台动态 IP 的机器上风险太大。
    """

    kind = "cloudflare"

    def __init__(self, token: str, timeout: float = 15.0) -> None:
        if not token.strip():
            raise DdnsError("缺少 Cloudflare API Token")
        self.token = token.strip()
        self.timeout = timeout
        self._zone_cache: dict[str, str] = {}

    def _call(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f"{CF_API}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                body = json.loads(raw)
            except ValueError:
                raise DdnsError(f"Cloudflare 返回 HTTP {exc.code}: {raw[:160]}") from exc
            raise DdnsError(self._error_message(body, exc.code)) from exc
        except urllib.error.URLError as exc:
            raise DdnsError(f"连接 Cloudflare 失败: {exc.reason}") from exc

        # Cloudflare 有时用 HTTP 200 配 success=false 表示逻辑错误，
        # 只看状态码会把失败当成功。
        if not body.get("success", False):
            raise DdnsError(self._error_message(body, 200))
        return body

    @staticmethod
    def _error_message(body: dict[str, Any], status: int) -> str:
        errors = body.get("errors") or []
        parts = []
        for err in errors:
            code = err.get("code", "")
            message = err.get("message", "")
            # 细节常常藏在 error_chain 里，只读外层会得到一句没用的"无法路由"
            for chained in err.get("error_chain") or []:
                message += f"（{chained.get('message', '')}）"
            parts.append(f"{code}: {message}" if code else message)

        detail = "；".join(p for p in parts if p) or f"HTTP {status}"
        hint = ""
        codes = {err.get("code") for err in errors}
        if status in (400, 401) or codes & {1000, 6003, 6111, 9109}:
            hint = " —— Token 无效或格式不对，确认用的是 API Token 而不是 Global API Key"
        elif status == 403 or 10000 in codes:
            hint = " —— Token 权限不足，需要 Zone → DNS → Edit"
        elif status == 429 or 10502 in codes:
            hint = " —— 触发 Cloudflare 限流（1200 次/5 分钟），稍后再试"
        return f"Cloudflare: {detail}{hint}"

    def zone_id(self, zone: str) -> str:
        """域名 -> zone id。缓存起来，每轮检查没必要重复问。"""
        zone = zone.strip().lower()
        if zone in self._zone_cache:
            return self._zone_cache[zone]

        query = urllib.parse.urlencode({"name": zone})
        result = self._call("GET", f"/zones?{query}").get("result") or []
        if not result:
            # 单区域 Token 查不到别的区域时返回空数组而不是 403，
            # 所以"没找到"要同时提示权限范围。
            raise DdnsError(
                f"找不到区域 {zone} —— 确认域名已托管在 Cloudflare，"
                "且 Token 的权限范围覆盖这个区域"
            )
        if len(result) > 1:
            raise DdnsError(f"区域 {zone} 匹配到 {len(result)} 个结果，无法确定")

        zid = str(result[0]["id"])
        self._zone_cache[zone] = zid
        return zid

    def find_record(self, zone: str, hostname: str, record_type: str) -> DnsRecord | None:
        # name.exact 是当前支持的精确匹配参数；老的 name=contains: 之类语法已被移除
        query = urllib.parse.urlencode({"type": record_type, "name.exact": hostname})
        result = (
            self._call("GET", f"/zones/{self.zone_id(zone)}/dns_records?{query}").get("result")
            or []
        )
        if not result:
            return None
        return self._to_record(result[0])

    def create_record(
        self,
        zone: str,
        hostname: str,
        record_type: str,
        ip: str,
        *,
        ttl: int = TTL_AUTO,
        proxied: bool = False,
    ) -> DnsRecord:
        payload = {
            "type": record_type,
            "name": hostname,
            "content": ip,
            # 开了代理的记录 TTL 被强制为自动，传数字会被拒
            "ttl": TTL_AUTO if proxied else ttl,
            "proxied": proxied,
        }
        body = self._call("POST", f"/zones/{self.zone_id(zone)}/dns_records", payload)
        return self._to_record(body.get("result") or {})

    def update_record(self, zone: str, record: DnsRecord, ip: str) -> DnsRecord:
        """只改 content，用 PATCH。

        PUT 是整条替换：漏传 proxied 或 ttl 会被重置成默认值，
        用户在控制台开的橙云会被静默关掉。PATCH 碰不到没传的字段。
        """
        body = self._call(
            "PATCH",
            f"/zones/{self.zone_id(zone)}/dns_records/{record.record_id}",
            {"content": ip},
        )
        return self._to_record(body.get("result") or {})

    @staticmethod
    def _to_record(item: dict[str, Any]) -> DnsRecord:
        return DnsRecord(
            record_id=str(item.get("id", "")),
            name=str(item.get("name", "")),
            type=str(item.get("type", "")),
            content=str(item.get("content", "")),
            ttl=int(item.get("ttl") or TTL_AUTO),
            proxied=bool(item.get("proxied")),
            raw=item,
        )


PROVIDERS: dict[str, str] = {"cloudflare": "Cloudflare"}


def build_provider(kind: str, token: str) -> DnsProvider:
    if kind != "cloudflare":
        raise DdnsError(f"暂不支持的 DNS 供应商: {kind}")
    return CloudflareProvider(token)


# ---------------- 同步一条记录 ----------------


def sync_record(
    provider: DnsProvider,
    zone: str,
    hostname: str,
    record_type: str,
    ip: str,
    *,
    ttl: int = TTL_AUTO,
    proxied: bool = False,
) -> UpdateResult:
    """把 hostname 的解析对到 ip 上。IP 没变就什么都不做。

    没变也照发一次更新是能跑的（幂等），但白烧限流额度，
    而 Cloudflare 的额度是账号级共享的。
    """
    existing = provider.find_record(zone, hostname, record_type)
    if existing is None:
        created = provider.create_record(
            zone, hostname, record_type, ip, ttl=ttl, proxied=proxied
        )
        return UpdateResult(hostname, record_type, "created", created.content, "", "新建记录")

    if existing.content == ip:
        return UpdateResult(hostname, record_type, "unchanged", ip, ip, "IP 未变化")

    updated = provider.update_record(zone, existing, ip)
    return UpdateResult(
        hostname,
        record_type,
        "updated",
        updated.content,
        existing.content,
        f"{existing.content} → {updated.content}",
    )


def verify_token(kind: str, token: str, zone: str) -> dict[str, Any]:
    """校验凭据能否真的读到这个区域。保存前调一次，别等到定时任务里才发现配错。"""
    provider = build_provider(kind, token)
    zid = provider.zone_id(zone)
    return {"ok": True, "zone": zone, "zone_id": zid}
