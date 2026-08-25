"""boto3 客户端工厂与区域/镜像元数据。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, unquote, urlparse, urlunparse

import boto3
from botocore.config import Config as BotoConfig
from botocore.httpsession import ProxyConfiguration, URLLib3Session

# moto 测试或自建端点时通过环境变量覆盖 endpoint
_ENDPOINT_ENV = "AWS_HELPER_ENDPOINT_URL"

_CONNECT_TIMEOUT = 15
_READ_TIMEOUT = 60
_MAX_POOL = 10

_BOTO_CONFIG = BotoConfig(
    retries={"max_attempts": 5, "mode": "standard"},
    connect_timeout=_CONNECT_TIMEOUT,
    read_timeout=_READ_TIMEOUT,
    max_pool_connections=_MAX_POOL,
)

SOCKS_SCHEMES = ("socks5", "socks5h", "socks4", "socks4a")
PROXY_SCHEMES = SOCKS_SCHEMES + ("http", "https")


class ProxyError(ValueError):
    """代理地址不合法。"""


class _SocksProxyConfiguration(ProxyConfiguration):
    """保留 socks scheme 不被改写成 http。

    botocore 的 _fix_proxy_url 假定代理只可能是 http/https，对其他 scheme
    一律前缀 'http://'，会把 socks5h://host:port 变成
    http://socks5h://host:port。socks 地址必须原样保留。
    """

    def _fix_proxy_url(self, proxy_url: str) -> str:
        if proxy_url.lower().startswith(SOCKS_SCHEMES):
            return proxy_url
        return super()._fix_proxy_url(proxy_url)

    def proxy_headers_for(self, proxy_url: str) -> dict[str, str]:
        # socks 认证在协议层完成（RFC 1929），不能发 Proxy-Authorization 头
        if proxy_url.lower().startswith(SOCKS_SCHEMES):
            return {}
        return super().proxy_headers_for(proxy_url)


class _SocksCapableSession(URLLib3Session):
    """让 botocore 支持 socks5 代理。

    botocore 把代理 URL 交给 urllib3 的 proxy_from_url，后者只认
    http/https，遇到 socks5 会抛 ProxySchemeUnknown。这里拦下 socks 前缀
    改用 SOCKSProxyManager，其余 scheme 仍走原实现。
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._proxy_config = _SocksProxyConfiguration(
            proxies=kwargs.get("proxies") or {},
            proxies_settings=kwargs.get("proxies_config") or {},
        )

    def _get_proxy_manager(self, proxy_url: str) -> Any:
        if not proxy_url.lower().startswith(SOCKS_SCHEMES):
            return super()._get_proxy_manager(proxy_url)

        if proxy_url not in self._proxy_managers:
            from urllib3.contrib.socks import SOCKSProxyManager

            kwargs = self._get_pool_manager_kwargs()
            # SOCKSProxyManager 不接受 socket_options，传入会 TypeError
            kwargs.pop("socket_options", None)
            self._proxy_managers[proxy_url] = SOCKSProxyManager(proxy_url, **kwargs)
        return self._proxy_managers[proxy_url]


def normalize_proxy(raw: str | None) -> str | None:
    """校验并规范化代理地址，返回可直接交给 botocore 的 URL。

    不带 scheme 时按 socks5h 处理（h 表示域名在代理端解析，
    避免本地 DNS 泄漏并保证代理侧能解析 AWS endpoint）。
    """
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None

    if "://" not in value:
        value = f"socks5h://{value}"

    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme not in PROXY_SCHEMES:
        raise ProxyError(
            f"不支持的代理协议 {parsed.scheme}（可用：{', '.join(PROXY_SCHEMES)}）"
        )
    if not parsed.hostname:
        raise ProxyError("代理地址缺少主机名")

    # urlparse.port 对越界端口直接抛 ValueError，需转成本模块的错误类型
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProxyError(f"代理端口不合法: {value}") from exc
    if port is None:
        raise ProxyError("代理地址必须带端口，例如 socks5h://127.0.0.1:1080")
    if port == 0:
        raise ProxyError("代理端口不能为 0")

    # socks5 会在本地解析域名，统一升级成 socks5h 交给代理解析
    if scheme == "socks5":
        scheme = "socks5h"

    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}"
    if parsed.username:
        # 先 unquote 再 quote，让已编码的输入不被二次编码
        auth = quote(unquote(parsed.username), safe="")
        if parsed.password:
            auth += f":{quote(unquote(parsed.password), safe='')}"
        netloc = f"{auth}@{netloc}"

    return urlunparse((scheme, netloc, "", "", "", ""))


def mask_proxy(proxy_url: str | None) -> str:
    """隐去代理 URL 里的密码，用于页面展示和日志。"""
    if not proxy_url:
        return ""
    parsed = urlparse(proxy_url)
    if not parsed.username:
        return proxy_url
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port else ""
    secret = ":***" if parsed.password else ""
    return f"{parsed.scheme}://{parsed.username}{secret}@{host}{port}"


@dataclass(frozen=True)
class Credentials:
    """一个 AWS 账号的访问凭据，可带独立的出站代理。"""

    access_key: str
    secret_key: str
    region: str = "us-east-1"
    proxy: str | None = None

    def masked_key(self) -> str:
        if len(self.access_key) <= 8:
            return "*" * len(self.access_key)
        return f"{self.access_key[:4]}{'*' * 8}{self.access_key[-4:]}"

    def masked_proxy(self) -> str:
        return mask_proxy(self.proxy)


def client(service: str, creds: Credentials, region: str | None = None) -> Any:
    """构造 boto3 客户端。region 显式传入时覆盖凭据里的默认区域。"""
    config = _BOTO_CONFIG
    proxy = normalize_proxy(creds.proxy)
    if proxy:
        config = config.merge(
            BotoConfig(proxies={"http": proxy, "https": proxy})
        )

    kwargs: dict[str, Any] = {
        "service_name": service,
        "region_name": region or creds.region,
        "aws_access_key_id": creds.access_key,
        "aws_secret_access_key": creds.secret_key,
        "config": config,
    }
    endpoint = os.environ.get(_ENDPOINT_ENV)
    if endpoint:
        kwargs["endpoint_url"] = endpoint

    built = boto3.client(**kwargs)
    if proxy and proxy.lower().startswith("socks"):
        _install_socks_session(built, proxy)
    return built


def _install_socks_session(built: Any, proxy: str) -> None:
    """替换 endpoint 的 http_session 为支持 socks 的实现。

    botocore 建客户端时已按 config.proxies 造好 URLLib3Session，但它不认
    socks scheme。这里用本模块自己的超时/连接数常量重建，不去读 botocore
    的私有属性 —— 那些名字会随版本变化。
    """
    built._endpoint.http_session = _SocksCapableSession(
        timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
        proxies={"http": proxy, "https": proxy},
        max_pool_connections=_MAX_POOL,
    )


def ec2(creds: Credentials, region: str | None = None) -> Any:
    return client("ec2", creds, region)


def verify(creds: Credentials, region: str | None = None) -> dict[str, Any]:
    """调用 DescribeRegions 验证凭据可用，返回可用区域数量。"""
    proxy = normalize_proxy(creds.proxy)
    if proxy:
        probe_proxy(proxy, target=_api_target(region or creds.region))
    resp = ec2(creds, region).describe_regions()
    return {"ok": True, "regions": len(resp.get("Regions", []))}


def _api_target(region: str) -> tuple[str, int]:
    """返回代理需要能连通的目标地址，即本次实际访问的 EC2 endpoint。"""
    endpoint = os.environ.get(_ENDPOINT_ENV)
    if endpoint:
        parsed = urlparse(endpoint)
        default_port = 443 if parsed.scheme == "https" else 80
        return parsed.hostname or "127.0.0.1", parsed.port or default_port
    return f"ec2.{region}.amazonaws.com", 443


def probe_proxy(
    proxy_url: str,
    target: tuple[str, int] | None = None,
    timeout: float = 8.0,
) -> None:
    """先单独验一次代理，让报错能区分"代理坏"和"凭据错"。

    botocore 把 SOCKS 握手/认证失败一律包装成 EndpointConnectionError，
    信息里只提 AWS endpoint，会误导用户去查凭据。这里提前握手拿真实原因。
    """
    parsed = urlparse(proxy_url)
    host, port = parsed.hostname, parsed.port
    if not host or not port:
        raise ProxyError(f"代理地址不完整: {mask_proxy(proxy_url)}")

    target = target or ("ec2.us-east-1.amazonaws.com", 443)
    scheme = parsed.scheme.lower()
    if scheme not in SOCKS_SCHEMES:
        _probe_tcp(host, port, timeout, proxy_url)
        return

    import socket

    import socks

    sock = socks.socksocket()
    sock.settimeout(timeout)
    sock.set_proxy(
        socks.SOCKS4 if scheme.startswith("socks4") else socks.SOCKS5,
        host,
        port,
        rdns=True,
        username=unquote(parsed.username) if parsed.username else None,
        password=unquote(parsed.password) if parsed.password else None,
    )
    try:
        sock.connect(target)
    except socks.ProxyConnectionError as exc:
        raise ProxyError(f"无法连接到代理 {mask_proxy(proxy_url)}: {exc}") from exc
    except socks.ProxyError as exc:
        message = str(exc)
        if "auth" in message.lower():
            raise ProxyError(
                f"代理认证失败（检查用户名和密码）: {message}"
            ) from exc
        raise ProxyError(
            f"代理无法连接到 {target[0]}:{target[1]}: {message}"
        ) from exc
    except (OSError, socket.timeout) as exc:
        raise ProxyError(f"代理连接异常: {exc}") from exc
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _probe_tcp(host: str, port: int, timeout: float, proxy_url: str) -> None:
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except OSError as exc:
        raise ProxyError(f"无法连接到代理 {mask_proxy(proxy_url)}: {exc}") from exc


REGIONS: dict[str, str] = {
    "us-east-1": "美国东部（弗吉尼亚北部）",
    "us-east-2": "美国东部（俄亥俄）",
    "us-west-1": "美国西部（加利福尼亚北部）",
    "us-west-2": "美国西部（俄勒冈）",
    "af-south-1": "非洲（开普敦）",
    "ap-east-1": "亚太（香港）",
    "ap-south-1": "亚太（孟买）",
    "ap-northeast-1": "亚太（东京）",
    "ap-northeast-2": "亚太（首尔）",
    "ap-northeast-3": "亚太（大阪）",
    "ap-southeast-1": "亚太（新加坡）",
    "ap-southeast-2": "亚太（悉尼）",
    "ap-southeast-3": "亚太（雅加达）",
    "ca-central-1": "加拿大（中部）",
    "eu-central-1": "欧洲（法兰克福）",
    "eu-west-1": "欧洲（爱尔兰）",
    "eu-west-2": "欧洲（伦敦）",
    "eu-west-3": "欧洲（巴黎）",
    "eu-north-1": "欧洲（斯德哥尔摩）",
    "eu-south-1": "欧洲（米兰）",
    "me-south-1": "中东（巴林）",
    "sa-east-1": "南美（圣保罗）",
}

# 常用规格。value 为展示文本
INSTANCE_TYPES: dict[str, str] = {
    "t3.nano": "2 vCPU / 0.5 GiB",
    "t3.micro": "2 vCPU / 1 GiB（免费额度）",
    "t3.small": "2 vCPU / 2 GiB",
    "t3.medium": "2 vCPU / 4 GiB",
    "t3.large": "2 vCPU / 8 GiB",
    "t3a.micro": "2 vCPU / 1 GiB",
    "t3a.small": "2 vCPU / 2 GiB",
    "t3a.medium": "2 vCPU / 4 GiB",
    "t2.micro": "1 vCPU / 1 GiB（免费额度）",
    "t2.small": "1 vCPU / 2 GiB",
    "t2.medium": "2 vCPU / 4 GiB",
    "c5.large": "2 vCPU / 4 GiB",
    "c5.xlarge": "4 vCPU / 8 GiB",
    "c6i.large": "2 vCPU / 4 GiB",
    "m6i.large": "2 vCPU / 8 GiB",
    "t4g.micro": "2 vCPU / 1 GiB（ARM）",
    "t4g.small": "2 vCPU / 2 GiB（ARM）",
    "c6g.large": "2 vCPU / 4 GiB（ARM）",
}


@dataclass(frozen=True)
class ImageSpec:
    """镜像查找规则。用 name 通配符 + owner 定位最新 AMI。"""

    label: str
    owner: str
    name_pattern: str
    arch: str = "x86_64"
    ssh_user: str = "ubuntu"


IMAGES: dict[str, ImageSpec] = {
    "ubuntu-24.04": ImageSpec(
        "Ubuntu 24.04 LTS",
        "099720109477",
        "ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-amd64-server-*",
        ssh_user="ubuntu",
    ),
    "ubuntu-22.04": ImageSpec(
        "Ubuntu 22.04 LTS",
        "099720109477",
        "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*",
        ssh_user="ubuntu",
    ),
    "ubuntu-24.04-arm": ImageSpec(
        "Ubuntu 24.04 LTS (ARM64)",
        "099720109477",
        "ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-arm64-server-*",
        arch="arm64",
        ssh_user="ubuntu",
    ),
    "debian-12": ImageSpec(
        "Debian 12",
        "136693071363",
        "debian-12-amd64-*",
        ssh_user="admin",
    ),
    "debian-11": ImageSpec(
        "Debian 11",
        "136693071363",
        "debian-11-amd64-*",
        ssh_user="admin",
    ),
    "al2023": ImageSpec(
        "Amazon Linux 2023",
        "137112412989",
        "al2023-ami-2023*-x86_64",
        ssh_user="ec2-user",
    ),
}


def resolve_ami(session: Any, image_key: str) -> str:
    """按名称通配符查最新 AMI ID。找不到时抛 LookupError。"""
    spec = IMAGES.get(image_key)
    if spec is None:
        raise LookupError(f"未知镜像: {image_key}")

    resp = session.describe_images(
        Owners=[spec.owner],
        Filters=[
            {"Name": "name", "Values": [spec.name_pattern]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:
        raise LookupError(
            f"区域内找不到镜像 {spec.label}（pattern={spec.name_pattern}）"
        )
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    return images[0]["ImageId"]
