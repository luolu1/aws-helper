"""自动换 IP 监控循环。

按规则周期性探测实例连通性，连续失败达到阈值就自动换 IP。
可作为独立进程运行（python -m aws_helper.autoip），也可由 Web 进程内嵌启动。
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from typing import Any

from .cache import cache, ec2_instances_key
from .core import ipchange, launch
from .store import Store


@dataclass
class ProbeResult:
    ok: bool
    detail: str


def probe(
    ip: str, mode: str = "tcp", port: int = 22, timeout: float = 5.0, attempts: int = 2
) -> ProbeResult:
    """探测 IP 是否可达。

    tcp  — 连指定端口，能建连即视为通
    icmp — 无 root 权限时 raw socket 不可用，退回 tcp

    单次超时就判失败会被瞬时抖动误触发（换 IP 是有代价的操作），
    所以重试 attempts 次，任意一次成功即视为可达。
    """
    if not ip:
        return ProbeResult(False, "实例没有公网 IP")
    if mode == "icmp":
        # 容器里通常没有 CAP_NET_RAW，统一用 TCP 探测更可靠
        mode = "tcp"

    last = ""
    for i in range(max(1, attempts)):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                suffix = f"（第 {i + 1} 次尝试）" if i else ""
                return ProbeResult(True, f"tcp/{port} 可达{suffix}")
        except OSError as exc:
            last = str(exc)
            if i + 1 < max(1, attempts):
                time.sleep(1)
    return ProbeResult(False, f"tcp/{port} 连续 {max(1, attempts)} 次不可达: {last}")


DEFAULT_COOLDOWN = 1800

# 一轮里每条失败规则要跑两次 5s TCP 探测，整轮可能上百秒。超过这个岁数的
# 实例清单对 autoip 不可信 —— public_ip 可能已经变了，拿旧 IP 去探测会记
# 一次假失败，累积到阈值就白换一次 IP。
_SEEN_MAX_AGE = 30


def check_rule(
    store: Store,
    rule: dict[str, Any],
    cooldown: int = DEFAULT_COOLDOWN,
    seen: dict[tuple[int, str], tuple[float, dict[str, dict[str, Any]]]] | None = None,
) -> dict[str, Any]:
    """检查单条规则，必要时触发换 IP。返回本轮动作说明。

    seen 是 run_once 传进来的本轮共享清单，用来避免同一 (账号, 区域) 重复
    调 DescribeInstances。不传时行为与从前一致（每次自己拉）。
    """
    now = int(time.time())
    if now - int(rule["last_check"]) < int(rule["interval_sec"]):
        return {"action": "skip", "reason": "未到检查间隔"}

    account_id = int(rule["account_id"])
    seen_key = (account_id, rule["region"])
    creds = store.credentials(account_id, rule["region"])

    hit = seen.get(seen_key) if seen is not None else None
    if hit is not None and time.time() - hit[0] < _SEEN_MAX_AGE:
        instances = hit[1]
    else:
        try:
            instances = {
                i["instance_id"]: i
                for i in launch.list_instances(creds, rule["region"])
            }
        except Exception as exc:
            store.update_rule_state(int(rule["id"]), last_check=now)
            store.log("autoip", rule["instance_id"], False, f"拉取实例失败: {exc}")
            return {"action": "error", "reason": str(exc)}
        if seen is not None:
            seen[seen_key] = (time.time(), instances)

    inst = instances.get(rule["instance_id"])
    if inst is None:
        store.update_rule_state(int(rule["id"]), last_check=now)
        store.log("autoip", rule["instance_id"], False, "实例不存在或已终止")
        return {"action": "error", "reason": "实例不存在"}

    if inst["state"] != "running":
        store.update_rule_state(int(rule["id"]), last_check=now)
        return {"action": "skip", "reason": f"实例状态 {inst['state']}"}

    result = probe(inst.get("public_ip") or "", rule["check_mode"], int(rule["check_port"]))
    fail_count = int(rule["fail_count"])

    if result.ok:
        if fail_count:
            store.update_rule_state(int(rule["id"]), fail_count=0, last_check=now)
        else:
            store.update_rule_state(int(rule["id"]), last_check=now)
        return {"action": "ok", "reason": result.detail, "ip": inst.get("public_ip")}

    fail_count += 1
    threshold = int(rule["fail_threshold"])
    if fail_count < threshold:
        store.update_rule_state(int(rule["id"]), fail_count=fail_count, last_check=now)
        store.log(
            "autoip",
            rule["instance_id"],
            False,
            f"探测失败 {fail_count}/{threshold}: {result.detail}",
        )
        return {"action": "fail", "reason": result.detail, "count": fail_count}

    # 冷却期：刚换过 IP 就再换往往是新 IP 的路由还没生效或服务没起来，
    # 继续换只会白烧弹性 IP 配额（默认每区域 5 个）并把实例反复停机。
    since_change = now - int(rule["last_change"])
    if int(rule["last_change"]) and since_change < cooldown:
        store.update_rule_state(int(rule["id"]), fail_count=fail_count, last_check=now)
        return {
            "action": "cooldown",
            "reason": f"{since_change}s 前刚换过 IP，冷却 {cooldown}s",
            "retry_after": cooldown - since_change,
        }

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
        store.update_rule_state(int(rule["id"]), fail_count=fail_count, last_check=now)
        store.log("autoip", rule["instance_id"], False, f"自动换 IP 失败: {exc}")
        return {"action": "error", "reason": str(exc)}

    store.update_rule_state(
        int(rule["id"]), fail_count=0, last_check=now, last_change=now
    )
    # IP 已经变了：本轮共享清单和页面缓存都必须作废，否则同区域的下一条规则
    # 会拿旧 IP 去探测，页面也会继续显示已经失效的地址。
    if seen is not None:
        seen.pop(seen_key, None)
    cache.drop(*ec2_instances_key(account_id, rule["region"]))
    store.log(
        "autoip",
        rule["instance_id"],
        True,
        f"连续 {threshold} 次探测失败，已换 IP: {changed.old_ip} → {changed.new_ip}",
    )
    return {
        "action": "changed",
        "old_ip": changed.old_ip,
        "new_ip": changed.new_ip,
        "attempts": changed.attempts,
    }


def run_once(store: Store, cooldown: int = DEFAULT_COOLDOWN) -> list[dict[str, Any]]:
    """遍历所有启用的规则跑一轮。

    同一 (账号, 区域) 下的多条规则共用一次 DescribeInstances —— 否则 N 条规则
    就是 N 次调用，无人值守地一直跑，是最容易触发风控的地方。
    """
    seen: dict[tuple[int, str], tuple[float, dict[str, dict[str, Any]]]] = {}
    out = []
    for rule in store.list_ip_rules(enabled_only=True):
        out.append({"rule_id": rule["id"], **check_rule(store, rule, cooldown, seen)})
    return out


class Monitor:
    """后台监控线程。"""

    def __init__(self, store: Store, tick: int = 30) -> None:
        self.store = store
        self.tick = tick
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="autoip", daemon=True)
        self._thread.start()

    def stop(self, wait: float = 5.0) -> None:
        """请求停止并等线程真正退出，让 running 立刻反映真实状态。

        正在执行的那一轮 check_rule 可能包含换 IP 的长阻塞调用，
        等待超时后直接返回，线程会在本轮结束时自行退出。
        """
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
                # 记日志本身也要连数据库。库短暂不可用时这一句会二次抛出，
                # 未捕获就会让监控线程直接死掉、之后永不恢复。
                try:
                    self.store.log("autoip", "", False, f"监控循环异常: {exc}")
                except Exception:
                    pass
            self._stop.wait(self.tick)


def main() -> None:
    store = Store()
    monitor = Monitor(store)
    monitor.start()
    print("自动换 IP 监控已启动，Ctrl+C 退出")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print("已停止")


if __name__ == "__main__":
    main()
