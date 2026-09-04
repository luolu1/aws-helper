"""实例侧自动换 IP 的上报处理。

面板不再从海外 TCP 探测实例：那种信号不能判断「IP 被墙」，还会产生无意义的
DescribeInstances 调用。探测完全由实例上的 aws-helper-guard 完成，只有连续失败
时才上报；本模块只处理上报、冷却和换 IP。
"""

from __future__ import annotations

import time
from typing import Any

from .cache import cache, ec2_instances_key
from .core import ipchange
from .store import Store

DEFAULT_COOLDOWN = 1800


def handle_agent_report(
    store: Store,
    rule: dict[str, Any],
    kind: str,
    detail: str,
    cooldown: int = DEFAULT_COOLDOWN,
) -> dict[str, Any]:
    """处理实例探测器的上报；只有 blocked 才可能换 IP。"""
    now = int(time.time())
    rule_id = int(rule["id"])

    if kind != "blocked":
        store.touch_agent(rule_id, detail=detail or kind)
        return {"action": "heartbeat", "kind": kind}

    store.touch_agent(rule_id, reported=True, detail=detail)

    if not int(rule["enabled"]):
        store.log("autoip", rule["instance_id"], False, f"规则已停用，忽略上报: {detail}")
        return {"action": "skip", "reason": "规则已停用"}

    since_change = now - int(rule["last_change"])
    if int(rule["last_change"]) and since_change < cooldown:
        store.log(
            "autoip",
            rule["instance_id"],
            False,
            f"实例上报被墙但在冷却期（{since_change}s 前刚换过）",
        )
        return {
            "action": "cooldown",
            "reason": f"{since_change}s 前刚换过 IP，冷却 {cooldown}s",
            "retry_after": cooldown - since_change,
        }

    account_id = int(rule["account_id"])
    creds = store.credentials(account_id, rule["region"])
    try:
        changed = ipchange.change_ip(
            creds,
            rule["region"],
            rule["instance_id"],
            strategy=rule["strategy"],
            rule=ipchange.IpRule(
                allow_cidrs=rule["allow_cidrs"],
                deny_cidrs=rule["deny_cidrs"],
                max_attempts=int(rule["max_attempts"]),
            ),
        )
    except Exception as exc:
        store.log("autoip", rule["instance_id"], False, f"按实例上报换 IP 失败: {exc}")
        return {"action": "error", "reason": str(exc)}

    store.update_rule_state(rule_id, fail_count=0, last_check=now, last_change=now)
    store.record_ip_change(
        account_id,
        rule["region"],
        rule["instance_id"],
        changed.new_ip,
        strategy=rule["strategy"],
        trigger="agent",
        reason=detail or "实例上报被墙",
    )
    cache.drop(*ec2_instances_key(account_id, rule["region"]))
    store.log(
        "autoip",
        rule["instance_id"],
        True,
        f"实例上报被墙（{detail}），已换 IP: {changed.old_ip} → {changed.new_ip}",
    )
    return {
        "action": "changed",
        "old_ip": changed.old_ip,
        "new_ip": changed.new_ip,
        "attempts": changed.attempts,
    }
