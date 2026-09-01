"""boto3 客户端工厂与区域/镜像元数据。"""

from __future__ import annotations

import ipaddress
import os
import time
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
    # 本机 endpoint（演示环境的 moto、本地 LocalStack）必须绕过代理，
    # 远端代理连不回我们的 127.0.0.1。
    if _endpoint_is_local():
        proxy = None
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
        target = _api_target(region or creds.region)
        if target:
            probe_proxy(proxy, target=target)
    resp = ec2(creds, region).describe_regions()
    return {"ok": True, "regions": len(resp.get("Regions", []))}


def _endpoint_is_local(endpoint: str | None = None) -> bool:
    """自定义 endpoint 是否指向本机。

    远端代理无法连回我们的 127.0.0.1，这种 endpoint 必须绕过代理直连，
    否则任何真实代理都会报 Connection refused。等同于 no_proxy 对
    localhost 的标准行为。
    """
    endpoint = endpoint if endpoint is not None else os.environ.get(_ENDPOINT_ENV)
    if not endpoint:
        return False
    host = urlparse(endpoint).hostname
    if not host:
        return False
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _api_target(region: str) -> tuple[str, int] | None:
    """返回代理预检要连的目标地址，无需预检时返回 None。"""
    endpoint = os.environ.get(_ENDPOINT_ENV)
    if not endpoint:
        return f"ec2.{region}.amazonaws.com", 443
    if _endpoint_is_local(endpoint):
        return None

    parsed = urlparse(endpoint)
    host = parsed.hostname
    if not host:
        return None
    default_port = 443 if parsed.scheme == "https" else 80
    return host, parsed.port or default_port


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

# 无法调用 DescribeInstanceTypes 时的兜底清单，仅作降级用。
# 正常路径是 list_instance_types() 直接问 AWS 该区域真实支持什么。
FALLBACK_INSTANCE_TYPES: dict[str, list[str]] = {
    "x86_64": [
        "t3.nano", "t3.micro", "t3.small", "t3.medium", "t3.large",
        "t3a.micro", "t3a.small", "t3a.medium",
        "t2.micro", "t2.small", "t2.medium",
        "c5.large", "c6i.large", "m6i.large",
    ],
    "arm64": [
        "t4g.nano", "t4g.micro", "t4g.small", "t4g.medium", "t4g.large",
        "c6g.medium", "c6g.large", "c7g.medium", "m6g.medium",
    ],
}

# 规格清单按 (region, arch) 缓存。DescribeInstanceTypes 要翻 4 页拉近 400 条，
# 每次开开机页都拉一遍太慢。
#
# 不带 account_id 是有意的：DescribeInstanceTypes 返回的是区域支持哪些规格，
# 与账号无关，带上只会让每个账号各冷启动一次。其他账号相关的缓存不能照抄。
_TYPE_CACHE: dict[tuple[str, str], tuple[float, list[dict[str, Any]]]] = {}
# 只有 AWS 上新机型才会变，6 小时足够
_TYPE_CACHE_TTL = 6 * 3600


def list_instance_types(
    creds: Credentials,
    region: str,
    arch: str = "x86_64",
    use_cache: bool = True,
) -> list[dict[str, Any]]:
    """列出该区域真实支持的实例规格，按内存和 vCPU 升序。

    直接问 DescribeInstanceTypes，而不是维护一份写死的清单 ——
    各区域支持的规格不同，写死的清单必然出现"选了但开不出来"。
    """
    if arch not in ARCHITECTURES:
        raise ValueError(f"未知架构: {arch}")

    key = (region, arch)
    now = time.time()
    if use_cache and key in _TYPE_CACHE:
        cached_at, cached = _TYPE_CACHE[key]
        if now - cached_at < _TYPE_CACHE_TTL:
            return cached

    session = ec2(creds, region)
    out: list[dict[str, Any]] = []
    token: str | None = None
    while True:
        params: dict[str, Any] = {
            "MaxResults": 100,
            "Filters": [{"Name": "processor-info.supported-architecture", "Values": [arch]}],
        }
        if token:
            params["NextToken"] = token
        resp = session.describe_instance_types(**params)
        for item in resp.get("InstanceTypes", []):
            mib = item["MemoryInfo"]["SizeInMiB"]
            vcpu = item["VCpuInfo"]["DefaultVCpus"]
            gib = mib / 1024
            out.append(
                {
                    "name": item["InstanceType"],
                    "vcpu": vcpu,
                    "memory_gib": round(gib, 2),
                    "label": f"{item['InstanceType']} — {vcpu} vCPU / {gib:g} GiB",
                    "free_tier": bool(item.get("FreeTierEligible")),
                    "current_gen": bool(item.get("CurrentGeneration")),
                }
            )
        token = resp.get("NextToken")
        if not token:
            break

    out.sort(key=lambda t: (t["memory_gib"], t["vcpu"], t["name"]))
    _TYPE_CACHE[key] = (now, out)
    return out


def instance_types_cached(
    creds: Credentials, region: str, arch: str = "x86_64", force: bool = False
) -> tuple[list[dict[str, Any]], bool, float]:
    """同 list_instance_types，但一并返回 (清单, 是否命中缓存, 缓存年龄秒)。

    页面要如实告诉用户看到的是几分钟前的数据，而不是假装刚拉的。
    """
    key = (region, arch)
    if force:
        _TYPE_CACHE.pop(key, None)
    else:
        hit = _TYPE_CACHE.get(key)
        if hit is not None and time.time() - hit[0] < _TYPE_CACHE_TTL:
            return hit[1], True, round(time.time() - hit[0], 1)

    out = list_instance_types(creds, region, arch, use_cache=False)
    # list_instance_types 内部会写缓存，但它可能被 mock 掉或将来改实现，
    # 这里显式补一次，保证「下次调用能命中」这个约定成立。
    _TYPE_CACHE[key] = (time.time(), out)
    return out, False, 0.0


def fallback_instance_types(arch: str = "x86_64") -> list[dict[str, Any]]:
    """DescribeInstanceTypes 不可用时的降级清单。"""
    return [
        {
            "name": name,
            "vcpu": 0,
            "memory_gib": 0,
            "label": f"{name}（未校验）",
            "free_tier": False,
            "current_gen": True,
        }
        for name in FALLBACK_INSTANCE_TYPES.get(arch, [])
    ]


ARCHITECTURES: dict[str, str] = {
    "x86_64": "64 位（x86）",
    "arm64": "64 位（ARM）",
}

OS_FAMILIES: dict[str, str] = {
    "linux": "Linux / UNIX",
    "windows": "Windows",
}


@dataclass(frozen=True)
class ImageSpec:
    """镜像条目。

    优先用发行方发布的 SSM 公共参数（AWS 与发行方推荐的官方方式，
    各区域自动解析且始终指向最新版本），参数不可用时退回 describe_images
    名称匹配。name_patterns 按顺序尝试，因为发行方会变更命名
    （Canonical 24.04 起从 hvm-ssd 改为 hvm-ssd-gp3）。
    """

    label: str
    owner: str
    name_patterns: tuple[str, ...]
    ssm_parameter: str | None = None
    arch: str = "x86_64"
    os_family: str = "linux"
    ssh_user: str = "ubuntu"

    @property
    def is_windows(self) -> bool:
        return self.os_family == "windows"


def _canonical(release: str, codename: str, arch: str, volume: str) -> ImageSpec:
    """按 Canonical 官方文档构造 Ubuntu 镜像条目。

    参数路径格式见 documentation.ubuntu.com/aws：
    /aws/service/canonical/ubuntu/server/RELEASE/stable/current/ARCH/hvm/VOL/ami-id
    """
    suffix = "arm64" if arch == "arm64" else "amd64"
    label = f"Ubuntu {release} LTS" + (" (ARM64)" if arch == "arm64" else "")
    return ImageSpec(
        label=label,
        owner="099720109477",
        ssm_parameter=(
            f"/aws/service/canonical/ubuntu/server/{release}/stable/current"
            f"/{suffix}/hvm/{volume}/ami-id"
        ),
        name_patterns=(
            f"ubuntu/images/hvm-ssd-gp3/ubuntu-{codename}-{release}-{suffix}-server-*",
            f"ubuntu/images/hvm-ssd/ubuntu-{codename}-{release}-{suffix}-server-*",
            f"ubuntu/images/hvm-ssd*/ubuntu-{codename}-*-{suffix}-server-*",
        ),
        arch=arch,
        ssh_user="ubuntu",
    )


def _windows(key_label: str, parameter_name: str, arch: str = "x86_64") -> ImageSpec:
    """Windows 镜像走 AWS 官方 ami-windows-latest 参数空间。

    Windows AMI 不在 describe_images 的 Owners=amazon 结果里可靠出现
    （实测 ap-east-1 返回 0 条），只能靠 SSM 参数，所以没有名称兜底。
    """
    return ImageSpec(
        label=key_label,
        owner="801119661308",
        ssm_parameter=f"/aws/service/ami-windows-latest/{parameter_name}",
        name_patterns=(f"{parameter_name}-*",),
        arch=arch,
        os_family="windows",
        ssh_user="Administrator",
    )


IMAGES: dict[str, ImageSpec] = {
    "ubuntu-24.04": _canonical("24.04", "noble", "x86_64", "ebs-gp3"),
    "ubuntu-24.04-arm": _canonical("24.04", "noble", "arm64", "ebs-gp3"),
    "ubuntu-22.04": _canonical("22.04", "jammy", "x86_64", "ebs-gp2"),
    "ubuntu-22.04-arm": _canonical("22.04", "jammy", "arm64", "ebs-gp2"),
    "ubuntu-20.04": _canonical("20.04", "focal", "x86_64", "ebs-gp2"),
    "debian-12": ImageSpec(
        label="Debian 12",
        owner="136693071363",
        name_patterns=("debian-12-amd64-*",),
        ssh_user="admin",
    ),
    "debian-12-arm": ImageSpec(
        label="Debian 12 (ARM64)",
        owner="136693071363",
        name_patterns=("debian-12-arm64-*",),
        arch="arm64",
        ssh_user="admin",
    ),
    "debian-11": ImageSpec(
        label="Debian 11",
        owner="136693071363",
        name_patterns=("debian-11-amd64-*",),
        ssh_user="admin",
    ),
    "al2023": ImageSpec(
        label="Amazon Linux 2023",
        owner="137112412989",
        ssm_parameter=(
            "/aws/service/ami-amazon-linux-latest"
            "/al2023-ami-kernel-default-x86_64"
        ),
        name_patterns=("al2023-ami-2023*-x86_64",),
        ssh_user="ec2-user",
    ),
    "al2023-arm": ImageSpec(
        label="Amazon Linux 2023 (ARM64)",
        owner="137112412989",
        ssm_parameter=(
            "/aws/service/ami-amazon-linux-latest"
            "/al2023-ami-kernel-default-arm64"
        ),
        name_patterns=("al2023-ami-2023*-arm64",),
        arch="arm64",
        ssh_user="ec2-user",
    ),
    "windows-2025": _windows(
        "Windows Server 2025", "Windows_Server-2025-English-Full-Base"
    ),
    "windows-2022": _windows(
        "Windows Server 2022", "Windows_Server-2022-English-Full-Base"
    ),
    "windows-2019": _windows(
        "Windows Server 2019", "Windows_Server-2019-English-Full-Base"
    ),
    "windows-2022-cn": _windows(
        "Windows Server 2022（简体中文）",
        "Windows_Server-2022-Chinese_Simplified-Full-Base",
    ),
    "windows-2019-cn": _windows(
        "Windows Server 2019（简体中文）",
        "Windows_Server-2019-Chinese_Simplified-Full-Base",
    ),
}


# EC2 的 vCPU 配额按实例族分组，QuotaCode 见 Service Quotas 控制台
VCPU_QUOTAS: dict[str, tuple[str, str]] = {
    "standard": ("L-1216C47A", "标准按需实例（A C D H I M R T Z）"),
    "spot": ("L-34B43A08", "Spot 实例（标准族）"),
    "g_family": ("L-DB2E81BA", "G 和 VT 按需实例"),
    "p_family": ("L-417A185B", "P 按需实例"),
    "inf": ("L-1945791B", "Inf 按需实例"),
}


def probe_account(creds: Credentials, region: str) -> dict[str, Any]:
    """探测账号在该区域的可用性、配额与用量。

    分项返回而不是一次成败：账号可能只读正常但写操作被封
    （账号级 Blocked），或者只是缺某个权限。分开报才能定位。
    """
    result: dict[str, Any] = {
        "region": region,
        "checks": [],
        "quotas": [],
        "usage": {},
        "healthy": True,
    }

    def record(name: str, ok: bool, detail: str) -> None:
        result["checks"].append({"name": name, "ok": ok, "detail": detail})
        if not ok:
            result["healthy"] = False

    session = ec2(creds, region)

    try:
        regions = session.describe_regions()["Regions"]
        record("凭据与网络", True, f"可访问 {len(regions)} 个区域")
    except Exception as exc:
        record("凭据与网络", False, _short(exc))
        return result

    try:
        identity = client("sts", creds, region).get_caller_identity()
        arn = identity.get("Arn", "")
        is_root = arn.endswith(":root")
        result["account_id"] = identity.get("Account", "")
        result["is_root"] = is_root
        record(
            "账号身份",
            not is_root,
            f"{arn}" + ("（root 凭据风险高，建议换 IAM 用户）" if is_root else ""),
        )
    except Exception as exc:
        record("账号身份", False, _short(exc))

    # DryRun 只校验权限，不校验账号状态；账号被封时 DryRun 仍会通过，
    # 所以这里额外做一次真实的只读写探测组合来判断。
    try:
        session.run_instances(
            ImageId="ami-00000000000000000",
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            DryRun=True,
        )
        record("开机权限", True, "DryRun 通过")
    except Exception as exc:
        message = str(exc)
        if "DryRunOperation" in message:
            record("开机权限", True, "DryRun 通过")
        elif "InvalidAMIID" in message or "does not exist" in message:
            record("开机权限", True, "有权限（AMI 占位符无效属预期）")
        elif "Blocked" in message:
            record("开机权限", False, "账号被 AWS 封禁，需提工单解封")
        else:
            record("开机权限", False, _short(exc))

    try:
        quotas = client("service-quotas", creds, region)
        for key, (code, label) in VCPU_QUOTAS.items():
            try:
                quota = quotas.get_service_quota(ServiceCode="ec2", QuotaCode=code)
                value = quota["Quota"]["Value"]
                result["quotas"].append(
                    {
                        "key": key,
                        "label": label,
                        "code": code,
                        "value": value,
                        "adjustable": quota["Quota"].get("Adjustable", False),
                    }
                )
            except Exception:
                continue
        if result["quotas"]:
            zero = [q for q in result["quotas"] if q["value"] == 0]
            record(
                "vCPU 配额",
                not zero,
                f"读到 {len(result['quotas'])} 项"
                + (
                    f"，其中 {len(zero)} 项为 0（账号未激活或被限制）"
                    if zero
                    else ""
                ),
            )
        else:
            record("vCPU 配额", False, "读不到配额，可能缺 servicequotas:GetServiceQuota")
    except Exception as exc:
        record("vCPU 配额", False, _short(exc))

    result["usage"] = _count_usage(session)
    result["proxy_in_use"] = mask_proxy(normalize_proxy(creds.proxy))

    # 出口 IP 直接影响 AWS 风控判定，能确认就报出来
    egress = _egress_ip(creds)
    if egress:
        result["egress_ip"] = egress
        record(
            "出口 IP",
            True,
            f"{egress}" + ("（经代理）" if result["proxy_in_use"] else "（直连）"),
        )
    return result


def _egress_ip(creds: Credentials, timeout: float = 10.0) -> str | None:
    """查 AWS 看到的出口 IP，用与业务调用完全相同的代理配置。

    风控是按出口 IP 判的，用户在浏览器看到的自己 IP 和面板调 AWS 的出口
    往往不是同一个 —— 必须把实际出口报出来才能定位风控原因。
    """
    proxy = normalize_proxy(creds.proxy)
    try:
        import urllib.request

        if proxy and proxy.lower().startswith(SOCKS_SCHEMES):
            from urllib3.contrib.socks import SOCKSProxyManager

            manager = SOCKSProxyManager(proxy, timeout=timeout)
            resp = manager.request("GET", "https://checkip.amazonaws.com")
            return resp.data.decode().strip() or None

        handler = (
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            if proxy
            else urllib.request.ProxyHandler({})
        )
        opener = urllib.request.build_opener(handler)
        with opener.open("https://checkip.amazonaws.com", timeout=timeout) as fh:
            return fh.read().decode().strip() or None
    except Exception:
        return None


def _count_usage(session: Any) -> dict[str, Any]:
    """统计当前占用：运行中 vCPU、实例数、卷容量、弹性 IP。"""
    usage = {
        "running_instances": 0,
        "running_vcpus": 0,
        "stopped_instances": 0,
        "volumes": 0,
        "volume_gib": 0,
        "addresses": 0,
        "idle_addresses": 0,
    }
    try:
        resp = session.describe_instances(
            Filters=[
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                }
            ]
        )
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                state = inst.get("State", {}).get("Name")
                cpu = inst.get("CpuOptions") or {}
                vcpus = cpu.get("CoreCount", 0) * cpu.get("ThreadsPerCore", 1)
                if state in ("pending", "running"):
                    usage["running_instances"] += 1
                    usage["running_vcpus"] += vcpus
                else:
                    usage["stopped_instances"] += 1
    except Exception:
        pass

    try:
        for vol in session.describe_volumes().get("Volumes", []):
            usage["volumes"] += 1
            usage["volume_gib"] += vol.get("Size", 0)
    except Exception:
        pass

    try:
        for addr in session.describe_addresses().get("Addresses", []):
            usage["addresses"] += 1
            if not addr.get("InstanceId"):
                usage["idle_addresses"] += 1
    except Exception:
        pass

    return usage


def _short(exc: Exception) -> str:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    text = str(exc)
    return f"{code}: {text[:120]}" if code else text[:140]


def images_by_os_arch(os_family: str, arch: str) -> dict[str, ImageSpec]:
    """按系统类别和架构筛镜像，供级联选择使用。"""
    return {
        key: spec
        for key, spec in IMAGES.items()
        if spec.os_family == os_family and spec.arch == arch
    }


def _resolve_via_ssm(creds: Credentials, region: str, parameter: str) -> str | None:
    """用 SSM 公共参数解析 AMI ID。这是 AWS 与发行方推荐的官方方式。

    失败原因很多（IAM 缺 ssm:GetParameter、区域无此参数、endpoint 不支持），
    任何失败都返回 None 交给名称匹配兜底，不阻断开机。
    """
    try:
        ssm = client("ssm", creds, region)
        value = ssm.get_parameter(Name=parameter)["Parameter"]["Value"]
    except Exception:
        return None
    return value if value.startswith("ami-") else None


def resolve_ami(
    session: Any,
    image_key: str,
    creds: Credentials | None = None,
    region: str | None = None,
) -> str:
    """解析镜像 AMI ID。先试 SSM 公共参数，再退回名称通配符。"""
    spec = IMAGES.get(image_key)
    if spec is None:
        raise LookupError(f"未知镜像: {image_key}")

    if spec.ssm_parameter and creds is not None:
        ami = _resolve_via_ssm(creds, region or creds.region, spec.ssm_parameter)
        if ami:
            return ami

    tried: list[str] = []
    for pattern in spec.name_patterns:
        resp = session.describe_images(
            Owners=[spec.owner],
            Filters=[
                {"Name": "name", "Values": [pattern]},
                {"Name": "state", "Values": ["available"]},
            ],
        )
        images = resp.get("Images", [])
        if images:
            images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
            return images[0]["ImageId"]
        tried.append(pattern)

    hint = "；".join(tried)
    raise LookupError(
        f"区域内找不到 {spec.label}。已尝试 SSM 公共参数和以下名称匹配：{hint}。"
        "可在开机表单的「指定 AMI ID」里手动填一个该区域可用的 AMI"
    )
