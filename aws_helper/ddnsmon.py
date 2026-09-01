"""DDNS 监控循环：定期把本机公网 IP 同步到 DNS。

和 autoip 的 Monitor 是同一套结构，但两者解决的是相反的问题：
autoip 是实例 IP 被墙了换新 IP，DDNS 是本机 IP 变了让域名跟上。
"""

from __future__ import annotations

import threading
import time
from typing import Any

from .core import ddns
from .store import Store

DEFAULT_TICK = 60

# 连续失败到这个次数就降频，避免配错 Token 后每轮都去撞 Cloudflare 的
# 限流和防爆破（连续认证失败会被临时封）。
_BACKOFF_AFTER = 3
_BACKOFF_FACTOR = 6


def _effective_interval(rule: dict[str, Any]) -> int:
    interval = max(30, int(rule["interval_sec"]))
    fails = int(rule["fail_count"])
    if fails >= _BACKOFF_AFTER:
        return min(interval * _BACKOFF_FACTOR, 3600)
    return interval


def check_rule(
    store: Store,
    rule: dict[str, Any],
    detected: dict[int, str] | None = None,
) -> dict[str, Any]:
    """检查一条 DDNS 规则，必要时更新解析。

    detected 是本轮共享的 IP 探测结果 —— 探测公网 IP 要走一次外部 HTTP，
    N 条规则各探一次纯属浪费，而且不同规则拿到的 IP 还可能不一致。
    """
    now = int(time.time())
    if now - int(rule["last_check"]) < _effective_interval(rule):
        return {"action": "skip", "reason": "未到检查间隔"}

    rule_id = int(rule["id"])
    wants = [(4, "A")] if rule["want_ipv4"] else []
    if rule["want_ipv6"]:
        wants.append((6, "AAAA"))

    try:
        token = store.ddns_token(rule_id)
        provider = ddns.build_provider(rule["provider"], token)
    except Exception as exc:
        store.update_ddns_state(
            rule_id,
            last_check=now,
            last_status=f"配置错误: {exc}",
            fail_count=int(rule["fail_count"]) + 1,
        )
        store.log("ddns", rule["hostname"], False, f"配置错误: {exc}")
        return {"action": "error", "reason": str(exc)}

    results: list[ddns.UpdateResult] = []
    errors: list[str] = []
    seen_ips: dict[int, str] = {}

    for version, record_type in wants:
        ip = (detected or {}).get(version)
        if ip is None:
            ip = ddns.detect_ip(version)
            if detected is not None:
                detected[version] = ip
        if not ip:
            # 没有 v6 连通性是常态，不算失败 —— 别把它算进失败计数触发降频
            errors.append(f"取不到 IPv{version} 地址")
            continue

        seen_ips[version] = ip
        try:
            results.append(
                ddns.sync_record(
                    provider,
                    rule["zone"],
                    rule["hostname"],
                    record_type,
                    ip,
                    ttl=int(rule["ttl"]),
                    proxied=bool(rule["proxied"]),
                )
            )
        except ddns.DdnsError as exc:
            errors.append(f"{record_type}: {exc}")

    changed = [r for r in results if r.action in ("created", "updated")]
    ok = bool(results) and not errors
    summary = "；".join(r.detail for r in results) or "；".join(errors) or "无动作"

    store.update_ddns_state(
        rule_id,
        last_check=now,
        last_ipv4=seen_ips.get(4, rule["last_ipv4"]),
        last_ipv6=seen_ips.get(6, rule["last_ipv6"]),
        last_status=summary,
        fail_count=0 if ok else int(rule["fail_count"]) + 1,
    )

    # 只有真的改了解析才记日志。没变化每轮都记会把日志刷满，
    # 真出问题时反而找不到。
    if changed or errors:
        store.log("ddns", rule["hostname"], not errors, summary)

    return {
        "action": "changed" if changed else ("ok" if ok else "error"),
        "reason": summary,
        "updates": [
            {
                "hostname": r.hostname,
                "type": r.record_type,
                "action": r.action,
                "ip": r.ip,
                "old_ip": r.old_ip,
            }
            for r in results
        ],
        "errors": errors,
    }


def run_once(store: Store) -> list[dict[str, Any]]:
    """跑一轮全部启用的规则。本轮内共享 IP 探测结果。"""
    detected: dict[int, str] = {}
    return [
        {"rule_id": rule["id"], **check_rule(store, rule, detected)}
        for rule in store.list_ddns_rules(enabled_only=True)
    ]


class Monitor:
    """后台 DDNS 线程。"""

    def __init__(self, store: Store, tick: int = DEFAULT_TICK) -> None:
        self.store = store
        self.tick = tick
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="ddns", daemon=True)
        self._thread.start()

    def stop(self, wait: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=wait)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                run_once(self.store)
            except Exception as exc:
                # 记日志本身也要连数据库，库不可用时会二次抛出。
                # 不捕获就会让线程永久退出、DDNS 之后再也不工作。
                try:
                    self.store.log("ddns", "", False, f"监控循环异常: {exc}")
                except Exception:
                    pass
            self._stop.wait(self.tick)


def main() -> None:
    store = Store()
    monitor = Monitor(store)
    monitor.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        monitor.stop()


if __name__ == "__main__":
    main()
