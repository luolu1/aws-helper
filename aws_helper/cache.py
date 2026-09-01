"""进程内 TTL 缓存，用来压掉重复的 AWS 调用。

只缓存成功结果。降级结果（拿不到数据时的内置清单）一旦进了缓存，
一次权限失败就会粘住整个 TTL —— 用户修好权限后仍然看到旧的降级数据。

键的约定：`(kind, account_id, ...)`，account_id 固定在第 1 位。
`drop_account` 依赖这个位置来清掉某账号的全部缓存 —— 改密钥、换代理、
删账号之后必须清，否则新凭据仍然读到旧账号的结果。
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

# 规格、套餐这类清单几乎不变，AWS 上新机型才会变
CATALOG_TTL = 6 * 3600
# 模型访问权限是用户在控制台申请的，开通后不该等太久
BEDROCK_TTL = 900
# 实例状态是用户盯着看的东西，缓存窗口必须短于人的反应时间
INSTANCES_TTL = 10


class TTLCache:
    """带 TTL 和条数上限的线程安全缓存。"""

    def __init__(self, max_entries: int = 256) -> None:
        self._data: dict[tuple[Any, ...], tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self._max = max_entries

    def fetch(
        self,
        key: tuple[Any, ...],
        ttl: float,
        loader: Callable[[], Any],
        *,
        force: bool = False,
    ) -> tuple[Any, bool, float]:
        """返回 (值, 是否命中缓存, 缓存年龄秒)。

        loader 抛异常时不写缓存，异常照常向外抛 —— 让调用方决定是否降级，
        降级结果不会被缓存住。
        """
        now = time.time()
        if not force:
            with self._lock:
                hit = self._data.get(key)
            if hit is not None and now - hit[0] < ttl:
                return hit[1], True, round(now - hit[0], 1)

        # loader 在锁外调用：AWS 请求可能几秒，不能挡住其他 key 的读写
        value = loader()

        with self._lock:
            self._data[key] = (time.time(), value)
            # dict 保持插入序，超额就丢最早写入的
            while len(self._data) > self._max:
                self._data.pop(next(iter(self._data)))
        return value, False, 0.0

    def drop(self, *prefix: Any) -> int:
        """按键前缀清除，返回清掉的条数。"""
        with self._lock:
            gone = [k for k in self._data if k[: len(prefix)] == prefix]
            for key in gone:
                del self._data[key]
            return len(gone)

    def drop_account(self, account_id: int) -> int:
        with self._lock:
            gone = [k for k in self._data if len(k) > 1 and k[1] == account_id]
            for key in gone:
                del self._data[key]
            return len(gone)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._data)


cache = TTLCache()


def ec2_instances_key(account_id: int, region: str) -> tuple[Any, ...]:
    return ("ec2-instances", account_id, region)


def ls_instances_key(account_id: int, region: str) -> tuple[Any, ...]:
    return ("ls-instances", account_id, region)


def ls_catalog_key(account_id: int, region: str) -> tuple[Any, ...]:
    return ("ls-catalog", account_id, region)


def ls_regions_key(account_id: int) -> tuple[Any, ...]:
    return ("ls-regions", account_id)


def bedrock_models_key(account_id: int, region: str) -> tuple[Any, ...]:
    return ("bedrock-models", account_id, region)
