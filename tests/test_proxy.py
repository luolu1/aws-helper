"""SOCKS 代理支持测试：用真实 SOCKS5 服务器验证流量确实经过代理。"""

from __future__ import annotations

import pytest

from aws_helper.core import aws
from aws_helper.core.aws import Credentials, ProxyError, mask_proxy, normalize_proxy

from .socks_server import Socks5Server


# ---------- 地址规范化 ----------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("127.0.0.1:1080", "socks5h://127.0.0.1:1080"),
        ("socks5://1.2.3.4:1080", "socks5h://1.2.3.4:1080"),
        ("socks5h://1.2.3.4:1080", "socks5h://1.2.3.4:1080"),
        ("socks4://1.2.3.4:9050", "socks4://1.2.3.4:9050"),
        ("http://proxy:8080", "http://proxy:8080"),
        ("https://proxy:8443", "https://proxy:8443"),
        ("  socks5://1.2.3.4:1080  ", "socks5h://1.2.3.4:1080"),
        ("socks5://[::1]:1080", "socks5h://[::1]:1080"),
        (None, None),
        ("", None),
        ("   ", None),
    ],
)
def test_normalize_proxy(raw, expected):
    assert normalize_proxy(raw) == expected


def test_socks5_upgraded_to_socks5h():
    """socks5 在本地解析域名会泄漏 DNS，必须升级成 socks5h。"""
    assert normalize_proxy("socks5://1.2.3.4:1080").startswith("socks5h://")


def test_credentials_keep_auth():
    assert (
        normalize_proxy("socks5h://user:pass@1.2.3.4:1080")
        == "socks5h://user:pass@1.2.3.4:1080"
    )


def test_encoded_password_not_double_encoded():
    assert normalize_proxy("socks5://u:p%40ss@1.2.3.4:1080") == (
        "socks5h://u:p%40ss@1.2.3.4:1080"
    )


@pytest.mark.parametrize(
    "bad,msg",
    [
        ("ftp://1.2.3.4:21", "不支持的代理协议"),
        ("socks5://1.2.3.4", "必须带端口"),
        ("socks5://:1080", "缺少主机名"),
        ("socks5://1.2.3.4:99999", "端口不合法"),
        ("socks5://1.2.3.4:0", "端口不能为 0"),
    ],
)
def test_rejects_bad_proxy(bad, msg):
    with pytest.raises(ProxyError, match=msg):
        normalize_proxy(bad)


def test_mask_hides_password():
    masked = mask_proxy("socks5h://user:secret@1.2.3.4:1080")
    assert "secret" not in masked
    assert "user" in masked
    assert masked == "socks5h://user:***@1.2.3.4:1080"


def test_mask_without_auth_unchanged():
    assert mask_proxy("socks5h://1.2.3.4:1080") == "socks5h://1.2.3.4:1080"
    assert mask_proxy(None) == ""


def test_credentials_masked_proxy():
    creds = Credentials("ak", "sk", "us-east-1", proxy="socks5h://u:p@1.2.3.4:1080")
    assert "p@" not in creds.masked_proxy()


# ---------- 真实链路 ----------


def _lan_ip() -> str:
    """取一个非 loopback 的本机地址。

    代理测试必须用它：loopback endpoint 会被有意绕过代理
    （远端代理连不回我们的 127.0.0.1），那样测不到代理链路。
    """
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


@pytest.fixture
def moto_endpoint(monkeypatch):
    """起一个真实 HTTP 的 moto 服务，代理需要真的转发 TCP 才能通。"""
    from moto.server import ThreadedMotoServer

    host = _lan_ip()
    server = ThreadedMotoServer(ip_address=host, port=0, verbose=False)
    server.start()
    _, port = server.get_host_and_port()
    monkeypatch.setenv("AWS_HELPER_ENDPOINT_URL", f"http://{host}:{port}")
    yield host, port
    server.stop()


def test_traffic_actually_goes_through_proxy(moto_endpoint, creds):
    """代理必须真的被使用 —— 断言代理端记录到了目标连接。"""
    host, port = moto_endpoint
    with Socks5Server() as proxy:
        with_proxy = Credentials(
            creds.access_key, creds.secret_key, creds.region, proxy=proxy.url
        )
        resp = aws.ec2(with_proxy).describe_regions()
        assert resp["Regions"]
        assert (host, port) in proxy.targets


def test_proxy_with_authentication(moto_endpoint, creds):
    host, port = moto_endpoint
    with Socks5Server(username="u1", password="p1") as proxy:
        with_proxy = Credentials(
            creds.access_key, creds.secret_key, creds.region, proxy=proxy.url
        )
        assert aws.ec2(with_proxy).describe_regions()["Regions"]
        assert (host, port) in proxy.targets
        assert proxy.auth_failures == 0


def test_wrong_password_fails_loudly(moto_endpoint, creds):
    """认证失败必须报错，绝不能静默绕过代理直连。"""
    with Socks5Server(username="right", password="right") as proxy:
        bad_url = proxy.url.replace("right:right", "wrong:wrong")
        with_proxy = Credentials(
            creds.access_key, creds.secret_key, creds.region, proxy=bad_url
        )
        with pytest.raises(Exception):
            aws.ec2(with_proxy).describe_regions()
        assert proxy.auth_failures > 0


# ---------- 代理预检报错要能区分原因 ----------


def test_probe_reports_auth_failure(moto_endpoint, creds):
    """密码错时报"认证失败"，不能报成 AWS endpoint 不通。"""
    host, port = moto_endpoint
    with Socks5Server(username="right", password="right") as proxy:
        bad_url = proxy.url.replace("right:right", "wrong:wrong")
        with pytest.raises(ProxyError, match="代理认证失败"):
            aws.probe_proxy(bad_url, target=(host, port))


def test_probe_reports_unreachable_proxy():
    with pytest.raises(ProxyError, match="无法连接到代理"):
        aws.probe_proxy("socks5h://127.0.0.1:1", target=("127.0.0.1", 80))


def test_probe_passes_for_working_proxy(moto_endpoint):
    host, port = moto_endpoint
    with Socks5Server() as proxy:
        aws.probe_proxy(proxy.url, target=(host, port))
        assert (host, port) in proxy.targets


def test_probe_masks_password_in_error():
    with pytest.raises(ProxyError) as excinfo:
        aws.probe_proxy("socks5h://u:topsecret@127.0.0.1:1", target=("127.0.0.1", 80))
    assert "topsecret" not in str(excinfo.value)


def test_verify_distinguishes_proxy_from_credential_error(moto_endpoint, creds):
    """代理不通时抛 ProxyError，而不是含糊的 endpoint 错误。"""
    with_bad_proxy = Credentials(
        creds.access_key, creds.secret_key, creds.region, proxy="socks5h://127.0.0.1:1"
    )
    with pytest.raises(ProxyError):
        aws.verify(with_bad_proxy)


def test_verify_succeeds_through_proxy(moto_endpoint, creds):
    host, port = moto_endpoint
    with Socks5Server() as proxy:
        with_proxy = Credentials(
            creds.access_key, creds.secret_key, creds.region, proxy=proxy.url
        )
        info = aws.verify(with_proxy)
        assert info["regions"] > 0
        assert proxy.targets


def test_unreachable_proxy_fails_loudly(moto_endpoint, creds):
    with_proxy = Credentials(
        creds.access_key, creds.secret_key, creds.region, proxy="socks5h://127.0.0.1:1"
    )
    with pytest.raises(Exception):
        aws.ec2(with_proxy).describe_regions()


def test_no_proxy_still_works(moto_endpoint, creds):
    assert aws.ec2(creds).describe_regions()["Regions"]


# ---------- 本机 endpoint 必须绕过代理 ----------


@pytest.mark.parametrize(
    "endpoint,expected",
    [
        ("http://127.0.0.1:5001", True),
        ("http://localhost:5001", True),
        ("http://[::1]:5001", True),
        ("http://127.0.0.53:8080", True),
        ("http://10.0.0.5:5001", False),
        ("https://ec2.us-east-1.amazonaws.com", False),
        ("", False),
    ],
)
def test_endpoint_is_local_detection(monkeypatch, endpoint, expected):
    monkeypatch.setenv("AWS_HELPER_ENDPOINT_URL", endpoint)
    assert aws._endpoint_is_local() is expected


def test_local_endpoint_skips_proxy_probe(monkeypatch):
    """本机 endpoint 不做代理预检。

    远端代理连不回我们的 127.0.0.1，预检必然 Connection refused，
    会把一个完全可用的代理误判成坏的。
    """
    monkeypatch.setenv("AWS_HELPER_ENDPOINT_URL", "http://127.0.0.1:5001")
    assert aws._api_target("us-east-1") is None


def test_remote_endpoint_still_probed(monkeypatch):
    monkeypatch.delenv("AWS_HELPER_ENDPOINT_URL", raising=False)
    assert aws._api_target("ap-northeast-1") == (
        "ec2.ap-northeast-1.amazonaws.com",
        443,
    )


def test_local_endpoint_bypasses_proxy_entirely(mock_ec2, monkeypatch):
    """配了代理也不能把本机 endpoint 的流量送进代理。

    演示环境（moto 跑在 127.0.0.1）配上真实远端代理时，
    必须仍然可用 —— 等同于 no_proxy 对 localhost 的标准行为。
    """
    monkeypatch.setenv("AWS_HELPER_ENDPOINT_URL", "http://127.0.0.1:5001")
    with Socks5Server() as proxy:
        creds = Credentials("testing", "testing", "us-east-1", proxy=proxy.url)
        assert aws.verify(creds)["regions"] > 0
        assert proxy.targets == [], "本机 endpoint 的流量不应经过代理"


def test_two_accounts_use_separate_proxies(moto_endpoint, creds):
    """不同账号配不同代理时，各自的流量只走自己的代理。"""
    with Socks5Server() as p1, Socks5Server() as p2:
        c1 = Credentials("k1", "s1", "us-east-1", proxy=p1.url)
        c2 = Credentials("k2", "s2", "us-east-1", proxy=p2.url)

        aws.ec2(c1).describe_regions()
        aws.ec2(c1).describe_regions()
        aws.ec2(c2).describe_regions()

        assert len(p1.targets) >= 2
        assert len(p2.targets) >= 1


def test_launch_through_proxy(moto_endpoint, creds, monkeypatch):
    """开机这类实际业务调用也必须走代理。"""
    from aws_helper.core import launch

    session = aws.ec2(creds)
    img = session.describe_images()["Images"][0]
    monkeypatch.setitem(
        aws.IMAGES,
        "ubuntu-24.04",
        aws.ImageSpec("moto", img["OwnerId"], img["Name"]),
    )

    with Socks5Server() as proxy:
        with_proxy = Credentials(
            creds.access_key, creds.secret_key, creds.region, proxy=proxy.url
        )
        results = launch.launch(
            with_proxy, launch.LaunchRequest(name="via-proxy", region="us-east-1")
        )
        assert results[0].state == "running"
        assert len(proxy.targets) >= 3
