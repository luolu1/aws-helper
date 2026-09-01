"""缓存与失效：压掉重复 AWS 调用，但绝不显示已经不成立的状态。

这里盯的是两类回归：
1. 该省的调用没省下（缓存没生效、autoip 每条规则各拉一次）
2. 不该省的省了（改完状态还给旧快照、换了账号还用旧结果）
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from aws_helper.cache import TTLCache
from aws_helper.core import aws

from .test_web import build_app, login


# ---------- TTLCache 本身 ----------


def test_cache_returns_hit_within_ttl():
    c = TTLCache()
    calls = []

    def loader():
        calls.append(1)
        return ["x"]

    v1, cached1, _ = c.fetch(("k",), 60, loader)
    v2, cached2, age = c.fetch(("k",), 60, loader)

    assert v1 == v2 == ["x"]
    assert (cached1, cached2) == (False, True)
    assert len(calls) == 1, "TTL 内应该只调一次 loader"
    assert age >= 0


def test_cache_expires_after_ttl():
    c = TTLCache()
    calls = []
    c.fetch(("k",), 0.05, lambda: calls.append(1))
    time.sleep(0.08)
    c.fetch(("k",), 0.05, lambda: calls.append(1))
    assert len(calls) == 2


def test_cache_force_bypasses_hit():
    """force 必须真的回源 —— 用户点「强制刷新」就是不信缓存了。"""
    c = TTLCache()
    calls = []

    def loader():
        calls.append(1)
        return len(calls)

    c.fetch(("k",), 60, loader)
    value, cached, _ = c.fetch(("k",), 60, loader, force=True)

    assert (value, cached) == (2, False)
    assert len(calls) == 2


def test_cache_does_not_store_failures():
    """loader 抛异常时不能写缓存。

    否则一次权限失败就把降级结果粘住整个 TTL，用户修好 IAM 也得干等。
    """
    c = TTLCache()

    with pytest.raises(RuntimeError):
        c.fetch(("k",), 60, lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    assert c.size() == 0
    value, cached, _ = c.fetch(("k",), 60, lambda: "ok")
    assert (value, cached) == ("ok", False)


def test_cache_drop_by_prefix():
    c = TTLCache()
    c.fetch(("ec2-instances", 1, "us-east-1"), 60, lambda: "a")
    c.fetch(("ec2-instances", 1, "eu-west-1"), 60, lambda: "b")
    c.fetch(("ec2-instances", 2, "us-east-1"), 60, lambda: "c")

    assert c.drop("ec2-instances", 1, "us-east-1") == 1
    assert c.size() == 2


def test_cache_drop_account_clears_all_regions():
    """换密钥或换代理后，该账号所有区域的缓存都得清 —— 出口和权限都变了。"""
    c = TTLCache()
    c.fetch(("ec2-instances", 7, "us-east-1"), 60, lambda: "a")
    c.fetch(("ls-catalog", 7, "ap-northeast-1"), 60, lambda: "b")
    c.fetch(("ec2-instances", 8, "us-east-1"), 60, lambda: "c")

    assert c.drop_account(7) == 2
    assert c.size() == 1


def test_cache_evicts_oldest_over_cap():
    """多账号多区域下缓存不能无限长。"""
    c = TTLCache(max_entries=3)
    for i in range(5):
        c.fetch(("k", i), 60, lambda: i)
    assert c.size() == 3


def test_cache_keys_isolate_accounts():
    """同区域不同账号绝不能相互串数据。"""
    c = TTLCache()
    a, _, _ = c.fetch(("ec2-instances", 1, "us-east-1"), 60, lambda: "账号1")
    b, cached, _ = c.fetch(("ec2-instances", 2, "us-east-1"), 60, lambda: "账号2")
    assert (a, b) == ("账号1", "账号2")
    assert cached is False


# ---------- /api/instances ----------


FAKE_INSTANCE = {
    "instance_id": "i-aaa",
    "name": "web",
    "state": "running",
    "instance_type": "t3.micro",
    "public_ip": "1.2.3.4",
    "private_ip": "10.0.0.5",
    "launch_time": "2026-01-01T00:00:00",
}


@pytest.fixture
def panel(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "cache")
    client = TestClient(app_module.app)
    login(client)
    app_module.cache.clear()
    return client, app_module


def _add_account(app_module) -> int:
    return app_module.store.add_account(
        "acct", "AKIA0000000000000000", "secret", "us-east-1"
    )


def test_instances_second_call_hits_cache(panel):
    """同一 (账号,区域) 连续请求只该打一次 AWS。"""
    client, app_module = panel
    aid = _add_account(app_module)

    with patch.object(app_module.launch, "list_instances") as spy:
        spy.return_value = [FAKE_INSTANCE]
        first = client.get(f"/api/instances?account_id={aid}&region=us-east-1").json()
        second = client.get(f"/api/instances?account_id={aid}&region=us-east-1").json()

    assert spy.call_count == 1
    assert first["cached"] is False
    assert second["cached"] is True


def test_instances_force_bypasses_cache(panel):
    client, app_module = panel
    aid = _add_account(app_module)

    with patch.object(app_module.launch, "list_instances") as spy:
        spy.return_value = [FAKE_INSTANCE]
        client.get(f"/api/instances?account_id={aid}&region=us-east-1")
        body = client.get(
            f"/api/instances?account_id={aid}&region=us-east-1&force=1"
        ).json()

    assert spy.call_count == 2
    assert body["cached"] is False


def test_instances_omits_payload_when_unchanged(panel):
    """指纹相同时不回传列表，前端好保留勾选状态。"""
    client, app_module = panel
    aid = _add_account(app_module)

    with patch.object(app_module.launch, "list_instances") as spy:
        spy.return_value = [FAKE_INSTANCE]
        first = client.get(f"/api/instances?account_id={aid}&region=us-east-1").json()
        again = client.get(
            f"/api/instances?account_id={aid}&region=us-east-1"
            f"&fingerprint={first['fingerprint']}"
        ).json()

    assert first["changed"] is True and "instances" in first
    assert again["changed"] is False and "instances" not in again


def test_instances_reports_change_when_state_differs(panel):
    client, app_module = panel
    aid = _add_account(app_module)

    with patch.object(app_module.launch, "list_instances") as spy:
        spy.return_value = [FAKE_INSTANCE]
        first = client.get(f"/api/instances?account_id={aid}&region=us-east-1").json()
        spy.return_value = [{**FAKE_INSTANCE, "state": "stopped"}]
        after = client.get(
            f"/api/instances?account_id={aid}&region=us-east-1&force=1"
            f"&fingerprint={first['fingerprint']}"
        ).json()

    assert after["changed"] is True
    assert after["instances"][0]["state"] == "stopped"


def test_fingerprint_ignores_aws_ordering(panel):
    """AWS 返回顺序变化不算「变了」。

    同批开机的实例 launch_time 相同，顺序不固定 —— 不做稳定排序会让指纹
    每次都不一样，缓存和增量渲染全部失效。
    """
    client, app_module = panel
    aid = _add_account(app_module)
    a = {**FAKE_INSTANCE, "instance_id": "i-aaa"}
    b = {**FAKE_INSTANCE, "instance_id": "i-bbb"}

    with patch.object(app_module.launch, "list_instances") as spy:
        spy.return_value = [a, b]
        first = client.get(f"/api/instances?account_id={aid}&region=us-east-1").json()
        spy.return_value = [b, a]
        again = client.get(
            f"/api/instances?account_id={aid}&region=us-east-1&force=1"
            f"&fingerprint={first['fingerprint']}"
        ).json()

    assert again["changed"] is False


def test_power_invalidates_instance_cache(panel):
    """关机之后再查必须回源。

    这是缓存最危险的地方：10 秒窗口正好会把变更前的快照端回来，
    用户看到「已经关机了却还显示 running」。
    """
    client, app_module = panel
    aid = _add_account(app_module)

    with patch.object(app_module.launch, "list_instances") as lister, patch.object(
        app_module.launch, "power"
    ) as power:
        lister.return_value = [FAKE_INSTANCE]
        power.return_value = {"ok": True}
        client.get(f"/api/instances?account_id={aid}&region=us-east-1")
        client.post(
            "/api/instances/power",
            json={
                "account_id": aid,
                "region": "us-east-1",
                "action": "stop",
                "instance_ids": ["i-aaa"],
            },
        )
        lister.return_value = [{**FAKE_INSTANCE, "state": "stopped"}]
        body = client.get(f"/api/instances?account_id={aid}&region=us-east-1").json()

    assert body["cached"] is False, "关机后必须回源，不能再给缓存"
    assert body["instances"][0]["state"] == "stopped"


def test_failed_power_also_invalidates(panel):
    """开关机报错也可能已经部分生效，同样要失效缓存。"""
    client, app_module = panel
    aid = _add_account(app_module)

    with patch.object(app_module.launch, "list_instances") as lister, patch.object(
        app_module.launch, "power"
    ) as power:
        lister.return_value = [FAKE_INSTANCE]
        power.side_effect = RuntimeError("部分失败")
        client.get(f"/api/instances?account_id={aid}&region=us-east-1")
        client.post(
            "/api/instances/power",
            json={
                "account_id": aid,
                "region": "us-east-1",
                "action": "stop",
                "instance_ids": ["i-aaa"],
            },
        )
        body = client.get(f"/api/instances?account_id={aid}&region=us-east-1").json()

    assert body["cached"] is False


def test_account_update_clears_cache(panel):
    """改了账号（可能换密钥换代理）之后不能再用旧结果。"""
    client, app_module = panel
    aid = _add_account(app_module)

    with patch.object(app_module.launch, "list_instances") as lister:
        lister.return_value = [FAKE_INSTANCE]
        client.get(f"/api/instances?account_id={aid}&region=us-east-1")
        assert app_module.cache.size() >= 1
        app_module.cache.drop_account(aid)
        assert app_module.cache.size() == 0


def test_delete_account_purges_cache(panel):
    client, app_module = panel
    aid = _add_account(app_module)

    with patch.object(app_module.launch, "list_instances") as lister:
        lister.return_value = [FAKE_INSTANCE]
        client.get(f"/api/instances?account_id={aid}&region=us-east-1")
        client.request("DELETE", f"/api/accounts/{aid}")

    assert app_module.cache.size() == 0


# ---------- 规格清单 ----------


def test_instance_types_cached_reports_age():
    """页面要如实说明数据是几秒前的，不能假装刚拉的。"""
    aws._TYPE_CACHE.clear()
    creds = aws.Credentials("a", "b", "us-east-1")
    with patch.object(aws, "list_instance_types") as spy:
        spy.return_value = [{"name": "t3.micro"}]
        first = aws.instance_types_cached(creds, "us-east-1", "x86_64")
        second = aws.instance_types_cached(creds, "us-east-1", "x86_64")

    assert first[1] is False
    assert second[1] is True
    assert spy.call_count == 1
    aws._TYPE_CACHE.clear()


def test_instance_types_force_refetches():
    aws._TYPE_CACHE.clear()
    creds = aws.Credentials("a", "b", "us-east-1")
    with patch.object(aws, "list_instance_types") as spy:
        spy.return_value = [{"name": "t3.micro"}]
        aws.instance_types_cached(creds, "us-east-1", "x86_64")
        aws.instance_types_cached(creds, "us-east-1", "x86_64", force=True)

    assert spy.call_count == 2
    aws._TYPE_CACHE.clear()


def test_catalog_degraded_result_not_cached(panel):
    """降级清单不能进缓存，否则修好权限还得等 TTL 到期。"""
    client, app_module = panel
    aid = _add_account(app_module)
    aws._TYPE_CACHE.clear()

    with patch.object(aws, "list_instance_types") as spy:
        spy.side_effect = RuntimeError("AccessDenied")
        first = client.get(f"/api/catalog?account_id={aid}&region=us-east-1").json()
        assert first["degraded"] is True

        spy.side_effect = None
        spy.return_value = [
            {"name": "t3.micro", "vcpu": 2, "memory_gib": 1, "label": "t3.micro",
             "free_tier": True, "current_gen": True}
        ]
        second = client.get(f"/api/catalog?account_id={aid}&region=us-east-1").json()

    assert second["degraded"] is False, "权限恢复后应立刻拿到真实清单"
    aws._TYPE_CACHE.clear()
