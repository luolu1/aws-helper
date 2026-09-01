"""DDNS：公网 IP 变了自动更新解析。

Cloudflare 侧用一个真实 HTTP 假服务端验证，而不是 mock 掉 urllib ——
要断言的正是「发出去的请求长什么样」：用 PATCH 还是 PUT、带了哪些字段。
mock 掉就等于把要验证的东西替换掉了。
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from aws_helper.core import ddns

ZONE = "example.com"
HOST = "home.example.com"
ZONE_ID = "zone-abc123"
RECORD_ID = "rec-def456"


class _FakeCloudflare(BaseHTTPRequestHandler):
    """最小可用的 Cloudflare API v4 假实现，记录收到的每个请求。"""

    state: dict[str, Any] = {}

    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, payload: dict[str, Any], code: int = 200) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _record_payload(self) -> dict[str, Any]:
        return {
            "id": RECORD_ID,
            "name": HOST,
            "type": self.state["record_type"],
            "content": self.state["record_ip"],
            "ttl": self.state["record_ttl"],
            "proxied": self.state["record_proxied"],
        }

    def _auth_ok(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {self.state['token']}"

    def do_GET(self) -> None:
        self.state["calls"].append(("GET", self.path))
        self.state["auth_headers"].append(self.headers.get("Authorization", ""))
        if not self._auth_ok():
            return self._send(
                {"success": False, "errors": [{"code": 1000, "message": "Invalid API Token"}]},
                401,
            )

        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.path.endswith("/zones"):
            name = (query.get("name") or [""])[0]
            if name != ZONE:
                return self._send({"success": True, "errors": [], "result": []})
            return self._send(
                {"success": True, "errors": [], "result": [{"id": ZONE_ID, "name": ZONE}]}
            )

        if "/dns_records" in parsed.path:
            self.state["record_queries"].append(query)
            if not self.state["record_exists"]:
                return self._send({"success": True, "errors": [], "result": []})
            if (query.get("type") or [""])[0] != self.state["record_type"]:
                return self._send({"success": True, "errors": [], "result": []})
            return self._send(
                {"success": True, "errors": [], "result": [self._record_payload()]}
            )

        return self._send({"success": False, "errors": [{"code": 7003}]}, 404)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_POST(self) -> None:
        body = self._body()
        self.state["calls"].append(("POST", self.path))
        self.state["bodies"].append(("POST", body))
        if not self._auth_ok():
            return self._send({"success": False, "errors": [{"code": 1000}]}, 401)
        self.state["record_exists"] = True
        self.state["record_ip"] = body.get("content", "")
        self.state["record_ttl"] = body.get("ttl", 1)
        self.state["record_proxied"] = bool(body.get("proxied"))
        return self._send({"success": True, "errors": [], "result": self._record_payload()})

    def do_PATCH(self) -> None:
        body = self._body()
        self.state["calls"].append(("PATCH", self.path))
        self.state["bodies"].append(("PATCH", body))
        if not self._auth_ok():
            return self._send({"success": False, "errors": [{"code": 1000}]}, 401)
        self.state["record_ip"] = body.get("content", self.state["record_ip"])
        return self._send({"success": True, "errors": [], "result": self._record_payload()})

    def do_PUT(self) -> None:
        body = self._body()
        self.state["calls"].append(("PUT", self.path))
        self.state["bodies"].append(("PUT", body))
        return self._send({"success": True, "errors": [], "result": self._record_payload()})


@pytest.fixture
def fake_cf(monkeypatch):
    """起一个真实 HTTP 服务当 Cloudflare，并把 CF_API 指过去。"""
    state: dict[str, Any] = {
        "token": "tok-valid",
        "record_exists": True,
        "record_type": "A",
        "record_ip": "1.1.1.1",
        "record_ttl": 120,
        "record_proxied": True,
        "calls": [],
        "bodies": [],
        "record_queries": [],
        "auth_headers": [],
    }
    _FakeCloudflare.state = state

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = HTTPServer(("127.0.0.1", port), _FakeCloudflare)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(ddns, "CF_API", f"http://127.0.0.1:{port}/client/v4")
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


# ---------- 取本机 IP ----------


def test_parse_trace_extracts_ip():
    body = "fl=1\nh=one.one.one.one\nip=203.0.113.9\nts=1\n"
    assert ddns._parse_body("https://x/cdn-cgi/trace", body) == "203.0.113.9"


def test_parse_plain_body_strips_newline():
    assert ddns._parse_body("https://api.ipify.org", "203.0.113.9\n") == "203.0.113.9"


def test_detect_ip_rejects_wrong_family(monkeypatch):
    """探测点回了 v6 地址却在问 v4 时必须丢弃，不能写进 A 记录。"""
    monkeypatch.setattr(ddns, "_parse_body", lambda url, body: "2001:db8::1")
    monkeypatch.setattr(
        ddns.urllib.request, "urlopen", lambda *a, **k: _FakeResponse("2001:db8::1")
    )
    assert ddns.detect_ip(4, sources=("https://x",)) == ""


def test_detect_ip_falls_through_to_next_source(monkeypatch):
    """单个探测点挂掉要接着试下一个，不能直接放弃。"""
    calls = []

    def flaky(request, timeout=0):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        calls.append(url)
        if len(calls) == 1:
            raise OSError("connection refused")
        return _FakeResponse("203.0.113.9")

    monkeypatch.setattr(ddns.urllib.request, "urlopen", flaky)
    got = ddns.detect_ip(4, sources=("https://bad", "https://good"))
    assert got == "203.0.113.9"
    assert len(calls) == 2


def test_detect_ip_rejects_garbage(monkeypatch):
    monkeypatch.setattr(
        ddns.urllib.request, "urlopen", lambda *a, **k: _FakeResponse("<html>error</html>")
    )
    assert ddns.detect_ip(4, sources=("https://x",)) == ""


def test_detect_ip_bad_version():
    with pytest.raises(ValueError, match="未知 IP 版本"):
        ddns.detect_ip(5)


class _FakeResponse:
    def __init__(self, body: str) -> None:
        self._body = body.encode()

    def read(self, _size: int = -1) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


# ---------- Cloudflare ----------


def test_zone_lookup_and_cache(fake_cf):
    provider = ddns.CloudflareProvider("tok-valid")
    assert provider.zone_id(ZONE) == ZONE_ID
    provider.zone_id(ZONE)
    zone_calls = [c for c in fake_cf["calls"] if "/zones?" in c[1]]
    assert len(zone_calls) == 1, "zone id 该缓存，不必每轮重复查"


def test_zone_uses_bearer_token(fake_cf):
    """必须用 Authorization: Bearer，不是旧的 X-Auth-Key。"""
    ddns.CloudflareProvider("tok-valid").zone_id(ZONE)
    assert fake_cf["auth_headers"][0] == "Bearer tok-valid"


def test_unknown_zone_mentions_token_scope(fake_cf):
    """查不到区域时要提示权限范围 —— 单区域 Token 查别的区域会返回空数组而不是 403。"""
    provider = ddns.CloudflareProvider("tok-valid")
    with pytest.raises(ddns.DdnsError, match="权限范围"):
        provider.zone_id("nope.com")


def test_invalid_token_is_actionable(fake_cf):
    provider = ddns.CloudflareProvider("tok-wrong")
    with pytest.raises(ddns.DdnsError, match="Global API Key"):
        provider.zone_id(ZONE)


def test_record_lookup_uses_name_exact(fake_cf):
    """必须用 name.exact 精确匹配。

    老的 name=contains: 语法已被 Cloudflare 移除，用裸 name 也能工作但语义不明确。
    """
    provider = ddns.CloudflareProvider("tok-valid")
    provider.find_record(ZONE, HOST, "A")
    query = fake_cf["record_queries"][0]
    assert query["name.exact"] == [HOST]
    assert query["type"] == ["A"]


def test_update_uses_patch_and_only_sends_content(fake_cf):
    """这是整个功能最关键的一条断言。

    PUT 是整条替换：漏传 proxied/ttl 会被重置成默认值，用户在控制台开的
    橙云会被静默关掉、自定义 TTL 也会丢。PATCH 只改传了的字段。
    """
    fake_cf.update({"record_ip": "1.1.1.1", "record_proxied": True, "record_ttl": 120})
    provider = ddns.CloudflareProvider("tok-valid")
    result = ddns.sync_record(provider, ZONE, HOST, "A", "203.0.113.9")

    methods = [m for m, _ in fake_cf["bodies"]]
    assert "PUT" not in methods, "绝不能用 PUT，会清掉 proxied 和 ttl"
    assert methods == ["PATCH"]

    _, body = fake_cf["bodies"][0]
    assert body == {"content": "203.0.113.9"}, f"只该传 content，实际传了 {body}"
    assert result.action == "updated"
    assert fake_cf["record_proxied"] is True, "代理设置必须保持不变"
    assert fake_cf["record_ttl"] == 120, "TTL 必须保持不变"


def test_unchanged_ip_sends_no_write(fake_cf):
    """IP 没变就一个写请求都不该发 —— Cloudflare 限流额度是账号级共享的。"""
    fake_cf["record_ip"] = "203.0.113.9"
    provider = ddns.CloudflareProvider("tok-valid")
    result = ddns.sync_record(provider, ZONE, HOST, "A", "203.0.113.9")

    assert result.action == "unchanged"
    assert fake_cf["bodies"] == [], "IP 未变化不该产生任何写请求"


def test_missing_record_is_created(fake_cf):
    fake_cf["record_exists"] = False
    provider = ddns.CloudflareProvider("tok-valid")
    result = ddns.sync_record(provider, ZONE, HOST, "A", "203.0.113.9", ttl=300)

    method, body = fake_cf["bodies"][0]
    assert method == "POST"
    assert body["type"] == "A" and body["content"] == "203.0.113.9"
    assert result.action == "created"


def test_create_forces_auto_ttl_when_proxied(fake_cf):
    """开了代理的记录 TTL 被强制为自动，传数字会被 Cloudflare 拒。"""
    fake_cf["record_exists"] = False
    provider = ddns.CloudflareProvider("tok-valid")
    ddns.sync_record(provider, ZONE, HOST, "A", "203.0.113.9", ttl=300, proxied=True)

    _, body = fake_cf["bodies"][0]
    assert body["ttl"] == ddns.TTL_AUTO
    assert body["proxied"] is True


def test_aaaa_record_supported(fake_cf):
    fake_cf.update({"record_type": "AAAA", "record_ip": "2001:db8::1"})
    provider = ddns.CloudflareProvider("tok-valid")
    result = ddns.sync_record(provider, ZONE, HOST, "AAAA", "2001:db8::2")

    assert result.action == "updated"
    assert fake_cf["record_queries"][0]["type"] == ["AAAA"]


def test_error_chain_is_surfaced(fake_cf, monkeypatch):
    """细节常藏在 error_chain 里，只读外层会得到一句没用的「无法路由」。"""
    body = {
        "success": False,
        "errors": [
            {
                "code": 7003,
                "message": "Could not route",
                "error_chain": [{"code": 6111, "message": "Invalid format for Authorization header"}],
            }
        ],
    }
    provider = ddns.CloudflareProvider("tok-valid")
    message = provider._error_message(body, 400)
    assert "Invalid format for Authorization header" in message


def test_rate_limit_hint(fake_cf):
    provider = ddns.CloudflareProvider("tok-valid")
    body = {"success": False, "errors": [{"code": 10502, "message": "blocked"}]}
    assert "限流" in provider._error_message(body, 429)


def test_permission_hint(fake_cf):
    provider = ddns.CloudflareProvider("tok-valid")
    body = {"success": False, "errors": [{"code": 10000, "message": "auth error"}]}
    assert "DNS → Edit" in provider._error_message(body, 403)


def test_empty_token_rejected():
    with pytest.raises(ddns.DdnsError, match="缺少 Cloudflare API Token"):
        ddns.CloudflareProvider("   ")


def test_unknown_provider_rejected():
    with pytest.raises(ddns.DdnsError, match="暂不支持"):
        ddns.build_provider("route53", "tok")


def test_verify_token_returns_zone_id(fake_cf):
    out = ddns.verify_token("cloudflare", "tok-valid", ZONE)
    assert out["zone_id"] == ZONE_ID


# ---------- 存储层 ----------


def test_store_encrypts_token(store):
    """API Token 必须加密落库，且列表接口不回传密文。"""
    rule_id = store.save_ddns_rule(ZONE, HOST, token="tok-secret")
    assert store.ddns_token(rule_id) == "tok-secret"

    rows = store.list_ddns_rules()
    assert rows[0]["has_token"] is True
    assert "tok-secret" not in json.dumps(rows), "列表接口不能泄漏 Token"


def test_store_token_never_leaves_as_ciphertext(store):
    store.save_ddns_rule(ZONE, HOST, token="tok-secret")
    row = store.list_ddns_rules()[0]
    assert "token_blob" not in row, "连密文都不该出现在列表里"


def test_store_reuses_token_when_omitted(store):
    """编辑规则时留空 Token 表示沿用，不必重新粘贴。"""
    first = store.save_ddns_rule(ZONE, HOST, token="tok-1", note="初次")
    second = store.save_ddns_rule(ZONE, HOST, token=None, note="改备注")
    assert first == second
    assert store.ddns_token(second) == "tok-1"
    assert store.ddns_rule(second)["note"] == "改备注"


def test_store_rejects_new_rule_without_token(store):
    with pytest.raises(ValueError, match="必须提供 API Token"):
        store.save_ddns_rule(ZONE, "new.example.com", token=None)


def test_store_rejects_hostname_outside_zone(store):
    """主机名必须落在区域内，否则 Cloudflare 侧一定失败。"""
    with pytest.raises(ValueError, match="不属于区域"):
        store.save_ddns_rule(ZONE, "home.other.com", token="tok")


def test_store_rejects_both_families_disabled(store):
    with pytest.raises(ValueError, match="至少要开启"):
        store.save_ddns_rule(ZONE, HOST, token="tok", want_ipv4=0, want_ipv6=0)


def test_store_normalizes_case(store):
    rule_id = store.save_ddns_rule("Example.COM", "Home.Example.COM", token="tok")
    row = store.ddns_rule(rule_id)
    assert row["zone"] == ZONE and row["hostname"] == HOST


def test_store_upsert_keyed_by_provider_and_hostname(store):
    a = store.save_ddns_rule(ZONE, HOST, token="tok")
    b = store.save_ddns_rule(ZONE, HOST, token="tok2")
    assert a == b
    assert len(store.list_ddns_rules()) == 1
    assert store.ddns_token(b) == "tok2"


def test_store_enabled_only_filter(store):
    store.save_ddns_rule(ZONE, HOST, token="tok", enabled=1)
    store.save_ddns_rule(ZONE, "off.example.com", token="tok", enabled=0)
    assert len(store.list_ddns_rules()) == 2
    assert len(store.list_ddns_rules(enabled_only=True)) == 1


def test_store_delete(store):
    rule_id = store.save_ddns_rule(ZONE, HOST, token="tok")
    store.delete_ddns_rule(rule_id)
    assert store.list_ddns_rules() == []


def test_store_state_update(store):
    rule_id = store.save_ddns_rule(ZONE, HOST, token="tok")
    store.update_ddns_state(
        rule_id, last_check=123, last_ipv4="1.2.3.4", last_status="ok", fail_count=2
    )
    row = store.ddns_rule(rule_id)
    assert (row["last_check"], row["last_ipv4"], row["fail_count"]) == (123, "1.2.3.4", 2)


# ---------- 监控循环 ----------


def test_monitor_skips_before_interval(store):
    from aws_helper import ddnsmon

    rule_id = store.save_ddns_rule(ZONE, HOST, token="tok", interval_sec=300)
    store.update_ddns_state(rule_id, last_check=int(time.time()))
    out = ddnsmon.check_rule(store, store.ddns_rule(rule_id))
    assert out["action"] == "skip"


def test_monitor_shares_detected_ip_across_rules(store, monkeypatch):
    """一轮里多条规则共用一次 IP 探测。

    探测公网 IP 要走外部 HTTP，N 条规则各探一次纯属浪费，
    而且不同规则拿到的 IP 还可能不一致。
    """
    from aws_helper import ddnsmon

    for host in ("a.example.com", "b.example.com", "c.example.com"):
        store.save_ddns_rule(ZONE, host, token="tok", interval_sec=0)

    calls = []

    def counting(version=4, **kw):
        calls.append(version)
        return "203.0.113.9"

    monkeypatch.setattr(ddnsmon.ddns, "detect_ip", counting)
    monkeypatch.setattr(
        ddnsmon.ddns, "build_provider", lambda kind, token, acct="": _StubProvider()
    )
    ddnsmon.run_once(store)

    assert calls == [4], f"3 条规则只该探一次 IPv4，实际 {calls}"


def test_monitor_backs_off_after_repeated_failures(store):
    """连续失败后降频。

    配错 Token 时每轮都去撞，会同时触发限流和 Cloudflare 的防爆破
    （连续认证失败会被临时封）。
    """
    from aws_helper import ddnsmon

    rule = {"interval_sec": 300, "fail_count": 0}
    assert ddnsmon._effective_interval(rule) == 300
    assert ddnsmon._effective_interval({**rule, "fail_count": 5}) > 300


def test_monitor_missing_ipv6_is_not_a_failure(store, monkeypatch):
    """机器没有 v6 连通性是常态，不该算失败触发降频。"""
    from aws_helper import ddnsmon

    rule_id = store.save_ddns_rule(
        ZONE, HOST, token="tok", want_ipv4=1, want_ipv6=1, interval_sec=0
    )
    monkeypatch.setattr(
        ddnsmon.ddns, "detect_ip", lambda version=4, **kw: "203.0.113.9" if version == 4 else ""
    )
    monkeypatch.setattr(
        ddnsmon.ddns, "build_provider", lambda kind, token, acct="": _StubProvider()
    )
    out = ddnsmon.check_rule(store, store.ddns_rule(rule_id))

    assert any("IPv6" in e for e in out["errors"])
    assert out["updates"], "v4 那条仍然应该更新成功"


def test_monitor_survives_database_outage(store, monkeypatch):
    """库短暂不可用时监控线程不能死掉。

    错误处理里的 store.log() 自己也要连库，会二次抛出 —— 未捕获就会让线程
    永久退出，DDNS 之后再也不工作。
    """
    from aws_helper import ddnsmon

    monitor = ddnsmon.Monitor(store, tick=1)
    calls: list[int] = []

    def boom(_store):
        calls.append(1)
        raise RuntimeError("connection closed")

    original_run = ddnsmon.run_once
    original_log = type(store).log
    ddnsmon.run_once = boom
    type(store).log = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down"))
    try:
        monitor.start()
        time.sleep(2.5)
        assert monitor.running, "监控线程因日志写入失败而退出"
        assert len(calls) >= 2, "线程没有继续下一轮"
    finally:
        type(store).log = original_log
        ddnsmon.run_once = original_run
        monitor.stop()


class _StubProvider:
    kind = "stub"

    def zone_id(self, zone: str) -> str:
        return ZONE_ID

    def find_record(self, zone, hostname, record_type):
        return None

    def create_record(self, zone, hostname, record_type, ip, *, ttl, proxied):
        return ddns.DnsRecord(RECORD_ID, hostname, record_type, ip, ttl, proxied)

    def update_record(self, zone, record, ip):
        return ddns.DnsRecord(record.record_id, record.name, record.type, ip)


# ---------- 页面与 API ----------


@pytest.fixture
def panel(mock_ec2, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from .test_web import build_app, login

    app_module = build_app(monkeypatch, tmp_path / "ddns-web")
    client = TestClient(app_module.app)
    login(client)
    return client, app_module


def test_ddns_page_renders(panel):
    c, _ = panel
    html = c.get("/ddns").text
    assert "DDNS 动态解析" in html
    assert "API Token" in html
    assert "Global API Key" in html, "要提醒用户别用 Global Key"


def test_ddns_page_requires_login(mock_ec2, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from .test_web import build_app

    app_module = build_app(monkeypatch, tmp_path / "ddns-anon")
    c = TestClient(app_module.app)
    assert c.get("/ddns", follow_redirects=False).status_code == 302
    assert c.get("/api/ddns/detect").status_code == 401


def test_save_rule_verifies_token_before_saving(panel, monkeypatch):
    """Token 校验不过就不该落库 —— 否则定时任务会默默失败几小时。"""
    c, app_module = panel

    def boom(kind, token, zone, acct=""):
        raise ddns.DdnsError("Cloudflare: 1000: Invalid API Token")

    monkeypatch.setattr(app_module.ddns, "verify_token", boom)
    resp = c.post(
        "/api/ddns/rules",
        json={"zone": ZONE, "hostname": HOST, "token": "bad"},
    )
    assert resp.status_code == 400
    assert "Invalid API Token" in resp.json()["error"]
    assert app_module.store.list_ddns_rules() == [], "校验失败不能落库"


def test_save_rule_persists_after_verification(panel, monkeypatch):
    c, app_module = panel
    monkeypatch.setattr(
        app_module.ddns, "verify_token", lambda kind, token, zone, acct="": {"ok": True}
    )
    resp = c.post(
        "/api/ddns/rules",
        json={"zone": ZONE, "hostname": HOST, "token": "tok", "want_ipv6": 1},
    )
    assert resp.status_code == 200
    rules = app_module.store.list_ddns_rules()
    assert len(rules) == 1 and rules[0]["hostname"] == HOST
    assert rules[0]["want_ipv6"] == 1


def test_api_never_returns_token(panel, monkeypatch):
    """页面和接口都不能回传 Token，连密文也不行。"""
    c, app_module = panel
    monkeypatch.setattr(
        app_module.ddns, "verify_token", lambda kind, token, zone, acct="": {"ok": True}
    )
    c.post("/api/ddns/rules", json={"zone": ZONE, "hostname": HOST, "token": "tok-leak"})
    assert "tok-leak" not in c.get("/ddns").text


def test_detect_endpoint_shape(panel, monkeypatch):
    c, app_module = panel
    monkeypatch.setattr(
        app_module.ddns,
        "detect_ip",
        lambda version=4, **kw: "203.0.113.9" if version == 4 else "",
    )
    body = c.get("/api/ddns/detect").json()
    assert body["ipv4"] == "203.0.113.9"
    assert body["ipv6"] == ""


def test_run_now_ignores_interval(panel, monkeypatch):
    """点「立即同步」就该马上执行，不受检查间隔限制。"""
    c, app_module = panel
    rule_id = app_module.store.save_ddns_rule(
        ZONE, HOST, token="tok", interval_sec=3600
    )
    app_module.store.update_ddns_state(rule_id, last_check=int(time.time()))

    monkeypatch.setattr(
        app_module.ddns, "detect_ip", lambda version=4, **kw: "203.0.113.9"
    )
    monkeypatch.setattr(
        app_module.ddns, "build_provider", lambda kind, token, acct="": _StubProvider()
    )
    body = c.post(f"/api/ddns/rules/{rule_id}/run").json()
    assert body["action"] != "skip", "立即同步不该被间隔挡住"


def test_run_now_unknown_rule(panel):
    c, _ = panel
    assert c.post("/api/ddns/rules/9999/run").status_code == 404


def test_delete_rule(panel, monkeypatch):
    c, app_module = panel
    rule_id = app_module.store.save_ddns_rule(ZONE, HOST, token="tok")
    assert c.request("DELETE", f"/api/ddns/rules/{rule_id}").status_code == 200
    assert app_module.store.list_ddns_rules() == []


# ---------- 脚本生成接口 ----------


def test_script_endpoint_returns_bash(panel):
    c, _ = panel
    body = c.post(
        "/api/ddns/script",
        json={"zone": ZONE, "hostname": HOST, "token": "t" * 40, "want_ipv6": 1},
    ).json()
    assert body["ok"] is True
    assert body["script"].startswith("#!/usr/bin/env bash")
    assert body["filename"] == "ddns-deploy.sh"


def test_script_endpoint_does_not_persist(panel):
    """生成脚本是给别的机器用的，不该在面板里留一条规则。"""
    c, app_module = panel
    c.post(
        "/api/ddns/script",
        json={"zone": ZONE, "hostname": HOST, "token": "t" * 40},
    )
    assert app_module.store.list_ddns_rules() == []


def test_script_endpoint_validates(panel):
    c, _ = panel
    resp = c.post(
        "/api/ddns/script",
        json={"zone": ZONE, "hostname": "home.other.com", "token": "t" * 40},
    )
    assert resp.status_code == 400
    assert "不属于区域" in resp.json()["error"]


def test_script_endpoint_requires_login(mock_ec2, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from .test_web import build_app

    app_module = build_app(monkeypatch, tmp_path / "ddns-script-anon")
    c = TestClient(app_module.app)
    assert c.post("/api/ddns/script", json={}).status_code == 401


def test_script_endpoint_rejects_bad_numbers(panel):
    c, _ = panel
    resp = c.post(
        "/api/ddns/script",
        json={"zone": ZONE, "hostname": HOST, "token": "t" * 40, "ttl": "abc"},
    )
    assert resp.status_code == 400
    assert "参数错误" in resp.json()["error"]


# ---------- 出站 IP 与 Account ID ----------


def test_ip_sb_is_first_source():
    """ip.sb 放第一位 —— 用户明确要求用它锁定出站地址。"""
    assert ddns.IPV4_SOURCES[0] == "https://ip.sb"
    assert ddns.IPV6_SOURCES[0] == "https://ip.sb"


def test_v4_and_v6_sources_are_different():
    """v4/v6 探测点不能共用。

    api.ipify.org 只有 A 记录，强制走 v6 会连不上 —— 那会被误判成
    "这台机器没有 v6"，AAAA 记录永远不更新。
    """
    assert "https://api.ipify.org" in ddns.IPV4_SOURCES
    assert "https://api6.ipify.org" in ddns.IPV6_SOURCES
    assert "https://api.ipify.org" not in ddns.IPV6_SOURCES


def test_force_family_pins_getaddrinfo():
    """_force_family 必须真的把 getaddrinfo 钉在指定协议族上。

    urllib 不给切换地址族的入口。不钉住的话同一个域名可能解析到 v4，
    "取 IPv6"就取回一个 v4 地址，写进 AAAA 记录直接失败。
    """
    import socket as socket_mod

    seen: list[int] = []
    original = socket_mod.getaddrinfo
    try:
        socket_mod.getaddrinfo = lambda host, port, family=0, *a, **kw: (
            seen.append(family) or []
        )
        with ddns._force_family(socket_mod.AF_INET6):
            socket_mod.getaddrinfo("example.com", 443)
        assert seen == [socket_mod.AF_INET6]

        # 退出上下文后必须还原，否则会污染整个进程的域名解析
        seen.clear()
        socket_mod.getaddrinfo("example.com", 443, 0)
        assert seen == [0]
    finally:
        socket_mod.getaddrinfo = original


def test_detect_ip_uses_force_family(monkeypatch):
    """detect_ip 取 v6 时要走 _force_family(AF_INET6)。"""
    import socket as socket_mod

    used: list[int] = []
    original = ddns._force_family

    def spy(family):
        used.append(family)
        return original(family)

    monkeypatch.setattr(ddns, "_force_family", spy)
    monkeypatch.setattr(
        ddns.urllib.request, "urlopen", lambda *a, **k: _FakeResponse("2001:db8::1")
    )
    ddns.detect_ip(6, sources=("https://x",))
    assert used == [socket_mod.AF_INET6]

    used.clear()
    monkeypatch.setattr(
        ddns.urllib.request, "urlopen", lambda *a, **k: _FakeResponse("203.0.113.9")
    )
    ddns.detect_ip(4, sources=("https://x",))
    assert used == [socket_mod.AF_INET]


def test_zone_lookup_omits_account_id_when_absent(fake_cf):
    """不填 Account ID 时不该带这个参数 —— DNS 增删改本来不需要它。"""
    ddns.CloudflareProvider("tok-valid").zone_id(ZONE)
    zone_calls = [path for method, path in fake_cf["calls"] if "/zones?" in path]
    assert zone_calls and "account.id" not in zone_calls[0]


def test_zone_lookup_sends_account_id_when_given(fake_cf):
    """过滤参数名是 account.id（点号），写成 account_id 不会生效。"""
    provider = ddns.CloudflareProvider("tok-valid", account_id="a" * 32)
    try:
        provider.zone_id(ZONE)
    except ddns.DdnsError:
        pass
    zone_calls = [path for method, path in fake_cf["calls"] if "/zones?" in path]
    assert zone_calls
    assert "account.id=" + "a" * 32 in urllib.parse.unquote(zone_calls[0])


def test_duplicate_zone_asks_for_account_id(fake_cf, monkeypatch):
    """同名 zone 出现在多个账号下时，要明确让用户填 Account ID。

    这正是 Cloudflare 需要账号维度信息的唯一场景 —— 报"匹配到 2 个结果"
    对用户毫无帮助。
    """
    provider = ddns.CloudflareProvider("tok-valid")

    def two_zones(method, path, payload=None):
        return {
            "success": True,
            "errors": [],
            "result": [
                {"id": "z1", "name": ZONE, "account": {"id": "acct-one"}},
                {"id": "z2", "name": ZONE, "account": {"id": "acct-two"}},
            ],
        }

    monkeypatch.setattr(provider, "_call", two_zones)
    with pytest.raises(ddns.DdnsError, match="请填写 Account ID"):
        provider.zone_id(ZONE)


def test_duplicate_zone_error_lists_account_ids(fake_cf, monkeypatch):
    provider = ddns.CloudflareProvider("tok-valid")
    monkeypatch.setattr(
        provider,
        "_call",
        lambda *a, **k: {
            "success": True,
            "errors": [],
            "result": [
                {"id": "z1", "name": ZONE, "account": {"id": "acct-one"}},
                {"id": "z2", "name": ZONE, "account": {"id": "acct-two"}},
            ],
        },
    )
    with pytest.raises(ddns.DdnsError) as err:
        provider.zone_id(ZONE)
    assert "acct-one" in str(err.value) and "acct-two" in str(err.value)


def test_not_found_error_mentions_account_when_filtered(fake_cf):
    provider = ddns.CloudflareProvider("tok-valid", account_id="b" * 32)
    with pytest.raises(ddns.DdnsError, match="属于账号"):
        provider.zone_id("nope.com")


def test_build_provider_passes_account_id():
    provider = ddns.build_provider("cloudflare", "tok", "c" * 32)
    assert provider.account_id == "c" * 32


def test_store_saves_cf_account_id(store):
    rule_id = store.save_ddns_rule(
        ZONE, HOST, token="tok", cf_account_id="d" * 32
    )
    assert store.ddns_rule(rule_id)["cf_account_id"] == "d" * 32
    assert store.list_ddns_rules()[0]["cf_account_id"] == "d" * 32


def test_store_defaults_cf_account_id_to_empty(store):
    rule_id = store.save_ddns_rule(ZONE, HOST, token="tok")
    assert store.ddns_rule(rule_id)["cf_account_id"] == ""
