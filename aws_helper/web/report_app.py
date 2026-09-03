"""实例上报专用端口。

跟面板主端口彻底分开，只开一个 `/report` 路由 —— 面板主端口上有 AWS 凭据、
密钥下载、实例密码这些东西，不能因为要给实例开一个上报入口就把整个面板
暴露给它们。这个端口上没有任何其他接口，就算实例被入侵，拿到的也只是
「上报自己被墙」这一个能力。

鉴权靠 `X-Guard-Token`：每条规则一个独立凭证，库里只存 SHA-256 摘要。
凭证对不上一律 401，不区分「规则不存在」和「凭证错了」。
"""

from __future__ import annotations

import threading
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from .. import autoip
from ..store import Store

app = FastAPI(
    title="AWS 小助手 — 实例上报端口",
    docs_url=None,
    redoc_url=None,
    # 连 schema 都不给：这个端口在公网上，没必要把接口结构公开
    openapi_url=None,
)

_store: Store | None = None


def bind_store(store: Store) -> None:
    """注入主进程已经建好的 Store，共用同一个连接池。"""
    global _store
    _store = store


@app.get("/health")
def health() -> dict[str, Any]:
    """给部署脚本和面板的状态检测用，不需要凭证，也不吐任何信息。"""
    return {"ok": True, "service": "aws-helper-report"}


@app.post("/report")
async def report(
    request: Request,
    x_guard_token: str = Header(default=""),
) -> Any:
    """接收实例上报。kind=blocked 时触发换 IP，其余只记心跳。"""
    if _store is None:
        return JSONResponse({"ok": False, "error": "服务未就绪"}, status_code=503)

    rule = _store.rule_by_agent_token(x_guard_token)
    if rule is None:
        # 不说明是凭证错还是规则没了 —— 这个端口在公网上，别给探测者线索
        return JSONResponse({"ok": False, "error": "凭证无效"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        body = {}

    kind = str(body.get("kind") or "alive")[:32]
    detail = str(body.get("detail") or "")[:400]
    claimed = str(body.get("instance_id") or "")

    # 凭证是按实例发的，实例 ID 对不上说明脚本被复制到了别的机器 ——
    # 那台机器的网络状况不能代表这台，照它上报换 IP 是错的。
    if claimed and claimed != rule["instance_id"]:
        _store.log(
            "autoip",
            rule["instance_id"],
            False,
            f"上报的实例 ID {claimed} 与凭证不匹配，已拒绝",
        )
        return JSONResponse(
            {"ok": False, "error": "实例 ID 与凭证不匹配"}, status_code=403
        )

    result = autoip.handle_agent_report(_store, rule, kind, detail)
    return {"ok": True, **result}


class ReportServer:
    """在后台线程里跑上报端口。

    单独一个 uvicorn Server 实例：主端口那个由 systemd/命令行启动，
    信号处理必须留给它，所以这里用 install_signal_handlers=False。
    """

    def __init__(self, store: Store, host: str = "0.0.0.0", port: int = 8766) -> None:
        bind_store(store)
        self.host = host
        self.port = port
        self._thread: threading.Thread | None = None
        self._server: Any = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        import uvicorn

        config = uvicorn.Config(
            app, host=self.host, port=self.port, log_level="warning"
        )
        self._server = uvicorn.Server(config)
        # 非主线程装不了信号处理器，装了还会抢主端口的
        self._server.install_signal_handlers = False
        self._thread = threading.Thread(
            target=self._server.run, name="report-port", daemon=True
        )
        self._thread.start()

    def stop(self, wait: float = 5.0) -> None:
        if self._server is not None:
            self._server.should_exit = True
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=wait)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())
