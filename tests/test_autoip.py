"""自动换 IP 监控逻辑测试。"""

from __future__ import annotations

import socket
import time

import pytest

from aws_helper import autoip
from aws_helper.core import launch


@pytest.fixture
def env(mock_ec2, ubuntu_ami, store, creds):
    aid = store.add_account("t", "testing", "testing", "us-east-1")
    inst = launch.launch(creds, launch.LaunchRequest(name="mon", region="us-east-1"))[0]
    return store, aid, inst


def _rule(store, aid, instance_id, **over):
    kw = dict(
        account_id=aid,
        region="us-east-1",
        instance_id=instance_id,
        enabled=1,
        strategy="eip",
        check_port=22,
        interval_sec=0,
        fail_threshold=2,
        max_attempts=2,
    )
    kw.update(over)
    store.save_ip_rule(**kw)
    return store.list_ip_rules()[0]


def test_probe_detects_open_port():
    """起一个真实监听端口，探测应报可达。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        result = autoip.probe("127.0.0.1", "tcp", port)
        assert result.ok
    finally:
        srv.close()


def test_probe_detects_closed_port():
    result = autoip.probe("127.0.0.1", "tcp", 1, timeout=1.0)
    assert not result.ok
    assert "不可达" in result.detail


def test_probe_empty_ip():
    result = autoip.probe("", "tcp", 22)
    assert not result.ok
    assert "没有公网 IP" in result.detail


def test_icmp_mode_falls_back_to_tcp():
    """容器里没有 CAP_NET_RAW，icmp 模式必须退回 tcp 而不是崩溃。"""
    result = autoip.probe("127.0.0.1", "icmp", 1, timeout=1.0)
    assert "tcp/1" in result.detail


@pytest.fixture
def always_down(monkeypatch):
    """强制探测失败。

    moto 分配的地址落在 127.0.0.0/8，本机可路由，真实探测结果不确定，
    所以触发逻辑的测试必须把探测结果固定下来。
    """
    monkeypatch.setattr(
        autoip, "probe", lambda *a, **k: autoip.ProbeResult(False, "强制失败")
    )


def test_failure_below_threshold_only_counts(env, always_down):
    store, aid, inst = env
    rule = _rule(store, aid, inst.instance_id, fail_threshold=3)

    out = autoip.check_rule(store, rule)
    assert out["action"] == "fail"
    assert out["count"] == 1
    assert store.list_ip_rules()[0]["fail_count"] == 1


def test_threshold_reached_triggers_change(env, always_down):
    """连续失败达到阈值后必须真的换掉 IP。"""
    store, aid, inst = env
    old_ip = inst.public_ip

    first = autoip.check_rule(store, _rule(store, aid, inst.instance_id))
    assert first["action"] == "fail"

    second = autoip.check_rule(store, store.list_ip_rules()[0])
    assert second["action"] == "changed", second
    assert second["old_ip"] == old_ip
    assert second["new_ip"] != old_ip

    live = launch.list_instances(store.credentials(aid, "us-east-1"), "us-east-1")
    actual = [i for i in live if i["instance_id"] == inst.instance_id][0]
    assert actual["public_ip"] == second["new_ip"]

    rule = store.list_ip_rules()[0]
    assert rule["fail_count"] == 0
    assert rule["last_change"] > 0


def test_recovery_resets_fail_count(env, monkeypatch):
    """探测恢复后失败计数必须清零，否则会累积到阈值误触发换 IP。"""
    store, aid, inst = env
    monkeypatch.setattr(
        autoip, "probe", lambda *a, **k: autoip.ProbeResult(False, "down")
    )
    autoip.check_rule(store, _rule(store, aid, inst.instance_id, fail_threshold=5))
    assert store.list_ip_rules()[0]["fail_count"] == 1

    monkeypatch.setattr(autoip, "probe", lambda *a, **k: autoip.ProbeResult(True, "up"))
    out = autoip.check_rule(store, store.list_ip_rules()[0])
    assert out["action"] == "ok"
    assert store.list_ip_rules()[0]["fail_count"] == 0


def test_change_is_logged(env, always_down):
    store, aid, inst = env
    autoip.check_rule(store, _rule(store, aid, inst.instance_id))
    autoip.check_rule(store, store.list_ip_rules()[0])
    logs = store.list_logs()
    assert any(l["kind"] == "autoip" and l["ok"] == 1 for l in logs)


def test_interval_not_reached_skips(env):
    store, aid, inst = env
    rule = _rule(store, aid, inst.instance_id, interval_sec=3600)
    store.update_rule_state(rule["id"], last_check=int(time.time()))
    out = autoip.check_rule(store, store.list_ip_rules()[0])
    assert out["action"] == "skip"


def test_stopped_instance_is_skipped(env):
    store, aid, inst = env
    creds = store.credentials(aid, "us-east-1")
    launch.power(creds, "us-east-1", "stop", [inst.instance_id])

    out = autoip.check_rule(store, _rule(store, aid, inst.instance_id))
    assert out["action"] == "skip"
    assert "stopped" in out["reason"]


def test_missing_instance_reports_error(env):
    store, aid, _ = env
    out = autoip.check_rule(store, _rule(store, aid, "i-00000000000000000"))
    assert out["action"] == "error"
    logs = store.list_logs()
    assert any(l["ok"] == 0 for l in logs)


def test_run_once_covers_enabled_rules_only(env):
    store, aid, inst = env
    _rule(store, aid, inst.instance_id)
    store.save_ip_rule(
        account_id=aid, region="us-east-1", instance_id="i-disabled", enabled=0
    )
    results = autoip.run_once(store)
    assert len(results) == 1


def test_monitor_start_stop(store):
    monitor = autoip.Monitor(store, tick=1)
    assert not monitor.running
    monitor.start()
    assert monitor.running
    monitor.stop()
    time.sleep(1.4)
    assert not monitor.running


def test_monitor_survives_bad_rule(mock_ec2, store):
    """规则指向不存在的实例时，监控线程不能崩掉。"""
    aid = store.add_account("t", "testing", "testing", "us-east-1")
    store.save_ip_rule(
        account_id=aid,
        region="us-east-1",
        instance_id="i-00000000000000000",
        enabled=1,
        interval_sec=0,
    )
    monitor = autoip.Monitor(store, tick=1)
    monitor.start()
    time.sleep(1.5)
    assert monitor.running
    monitor.stop()
