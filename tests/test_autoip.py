"""自动换 IP：只保留实例侧 agent 上报的测试。"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from aws_helper import autoip


def _rule(**over):
    base = {
        "id": 7,
        "account_id": 1,
        "region": "us-east-1",
        "instance_id": "i-0abc",
        "enabled": 1,
        "strategy": "eip",
        "allow_cidrs": [],
        "deny_cidrs": [],
        "max_attempts": 3,
        "last_change": 0,
        "agent_interval_sec": 60,
    }
    base.update(over)
    return base


def test_heartbeat_does_not_change_ip():
    """正常上报只更新心跳，不能触发换 IP。"""
    store = MagicMock()
    with patch.object(autoip.ipchange, "change_ip") as change:
        out = autoip.handle_agent_report(store, _rule(), "alive", "探测正常")
        change.assert_not_called()

    assert out["action"] == "heartbeat"
    store.touch_agent.assert_called_once()


def test_started_does_not_change_ip():
    """脚本启动上报和心跳一样，只用于显示部署状态。"""
    store = MagicMock()
    with patch.object(autoip.ipchange, "change_ip") as change:
        out = autoip.handle_agent_report(store, _rule(), "started", "启动")
        change.assert_not_called()

    assert out == {"action": "heartbeat", "kind": "started"}


def test_blocked_report_changes_ip():
    """连续失败达到阈值后，实例报 blocked 才换 IP。"""
    store = MagicMock()
    with patch.object(autoip.ipchange, "change_ip") as change:
        change.return_value = MagicMock(old_ip="1.1.1.1", new_ip="2.2.2.2", attempts=1)
        out = autoip.handle_agent_report(store, _rule(), "blocked", "连不上国内站点")

    assert out["action"] == "changed"
    assert out["new_ip"] == "2.2.2.2"
    assert store.touch_agent.call_args.kwargs["reported"] is True


def test_blocked_report_respects_cooldown():
    """新 IP 路由还没生效时不能连续换，白烧 EIP 配额。"""
    store = MagicMock()
    recent = int(time.time()) - 60
    with patch.object(autoip.ipchange, "change_ip") as change:
        out = autoip.handle_agent_report(
            store, _rule(last_change=recent), "blocked", "连不上"
        )
        change.assert_not_called()

    assert out["action"] == "cooldown"
    assert out["retry_after"] > 0


def test_disabled_rule_ignores_blocked_report():
    store = MagicMock()
    with patch.object(autoip.ipchange, "change_ip") as change:
        out = autoip.handle_agent_report(store, _rule(enabled=0), "blocked", "x")
        change.assert_not_called()

    assert out["action"] == "skip"
    assert out["reason"] == "规则已停用"


def test_change_failure_is_returned_and_logged():
    """换 IP 失败要给实例脚本可读结果，也要进审计日志。"""
    store = MagicMock()
    with patch.object(autoip.ipchange, "change_ip", side_effect=RuntimeError("配额用尽")):
        out = autoip.handle_agent_report(store, _rule(), "blocked", "x")

    assert out == {"action": "error", "reason": "配额用尽"}
    store.log.assert_called_once()


def test_blocked_report_invalidates_instance_cache():
    """换完 IP 后实例列表缓存不能继续显示旧 IP。"""
    store = MagicMock()
    with patch.object(autoip.ipchange, "change_ip") as change, \
            patch.object(autoip.cache, "drop") as drop:
        change.return_value = MagicMock(old_ip="1.1.1.1", new_ip="2.2.2.2", attempts=1)
        autoip.handle_agent_report(store, _rule(), "blocked", "x")

    drop.assert_called_once()


def test_module_has_no_panel_probe_or_monitor():
    """local 已下线：不能保留 TCP socket 探测、DescribeInstances 或后台线程。"""
    assert not hasattr(autoip, "probe")
    assert not hasattr(autoip, "check_rule")
    assert not hasattr(autoip, "run_once")
    assert not hasattr(autoip, "Monitor")
