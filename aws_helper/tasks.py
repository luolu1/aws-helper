"""后台任务与进度跟踪。开机、换 IP 都是长耗时操作，需要前端轮询进度。"""

from __future__ import annotations

import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Task:
    id: str
    kind: str
    title: str
    steps: list[str] = field(default_factory=list)
    status: str = "running"  # running / done / error
    result: Any = None
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "status": self.status,
            "steps": list(self.steps),
            "current": self.steps[-1] if self.steps else "准备中",
            "result": self.result,
            "error": self.error,
            "elapsed": round((self.finished_at or time.time()) - self.created_at, 1),
        }


class TaskManager:
    """内存任务表。进程重启即清空 —— 任务结果同时写库，不依赖它做持久化。"""

    def __init__(self, keep: int = 200) -> None:
        self._tasks: dict[str, Task] = {}
        self._lock = threading.Lock()
        self._keep = keep

    def submit(
        self,
        kind: str,
        title: str,
        fn: Callable[[Callable[[str], None]], Any],
    ) -> str:
        task = Task(id=uuid.uuid4().hex, kind=kind, title=title)
        with self._lock:
            self._tasks[task.id] = task
            self._evict()

        def progress(msg: str) -> None:
            with self._lock:
                task.steps.append(msg)

        def runner() -> None:
            try:
                result = fn(progress)
                with self._lock:
                    task.result = result
                    task.status = "done"
                    task.finished_at = time.time()
                    task.steps.append("完成")
            except Exception as exc:  # 后台线程必须捕获全部异常，否则错误会静默丢失
                with self._lock:
                    task.status = "error"
                    task.error = f"{type(exc).__name__}: {exc}"
                    task.finished_at = time.time()
                    task.steps.append(f"失败: {exc}")
                    task.result = {"traceback": traceback.format_exc()[-2000:]}

        threading.Thread(target=runner, name=f"task-{task.id[:8]}", daemon=True).start()
        return task.id

    def get(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            task = self._tasks.get(task_id)
            return task.snapshot() if task else None

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            tasks = sorted(self._tasks.values(), key=lambda t: t.created_at, reverse=True)
            return [t.snapshot() for t in tasks[:limit]]

    def _evict(self) -> None:
        if len(self._tasks) <= self._keep:
            return
        finished = [t for t in self._tasks.values() if t.status != "running"]
        finished.sort(key=lambda t: t.finished_at or 0)
        for task in finished[: len(self._tasks) - self._keep]:
            self._tasks.pop(task.id, None)


manager = TaskManager()
