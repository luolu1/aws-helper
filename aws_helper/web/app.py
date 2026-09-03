"""FastAPI Web 面板。

安全说明：默认绑定 127.0.0.1，登录密码经 PBKDF2 哈希存库，会话令牌只存摘要。
首次启动会生成随机初始密码并打印到控制台，登录后可在用户面板自行修改；
忘记密码用 `python3 -m aws_helper.cli reset-password` 重置。
若要对外暴露，务必放到 HTTPS 反代之后 —— 这个面板持有你的 AWS 凭据。
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__, auth
from ..autoip import Monitor, probe, run_once
from ..cache import (
    BEDROCK_TTL,
    CATALOG_TTL,
    INSTANCES_TTL,
    bedrock_models_key,
    cache,
    ec2_instances_key,
    ls_catalog_key,
    ls_instances_key,
    ls_regions_key,
)
from ..core import (
    aws,
    bedrock,
    ddns,
    ddns_script,
    guard_script,
    ipchange,
    launch,
    launch_deploy,
    lightsail,
    reinstall,
    respw,
)
from ..core.userdata import ScriptOptions, ScriptError, render
from ..ddnsmon import Monitor as DdnsMonitor
from ..ddnsmon import check_rule as ddns_check_rule
from ..store import Store
from ..tasks import manager
from .report_app import ReportServer

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

store = Store()
monitor = Monitor(store)
ddns_monitor = DdnsMonitor(store)

# 实例上报走独立端口，不跟面板主端口混在一起 —— 主端口上有 AWS 凭据、
# 密钥下载、实例密码，不能为了给实例开个上报入口就整个暴露给它们。
REPORT_PORT = int(os.environ.get("AWS_HELPER_REPORT_PORT", "8766"))
REPORT_HOST = os.environ.get("AWS_HELPER_REPORT_HOST", "0.0.0.0")
# 生成脚本时写进 GUARD_REPORT_URL。留空则按面板出站 IP + 上报端口自动拼，
# 但那个 IP 未必是实例能连到的地址（NAT、多网卡），所以允许显式指定。
REPORT_PUBLIC_URL = os.environ.get("AWS_HELPER_REPORT_URL", "")
report_server = ReportServer(store, REPORT_HOST, REPORT_PORT)

SESSION_TTL = int(os.environ.get("AWS_HELPER_SESSION_TTL", "86400"))

# 登录页的「忘记密码」指向这里。自建仓库可用环境变量改写。
DOCS_URL = os.environ.get(
    "AWS_HELPER_DOCS_URL",
    "https://github.com/luolu1/aws-helper/blob/main/README.md",
)


def _bootstrap_password() -> str | None:
    """首次启动确保有可用密码，返回需要打印给用户的初始密码。

    AWS_HELPER_PASSWORD 仅在库里还没有密码时用作初始值，之后以库为准 ——
    否则用户在面板里改了密码，重启又被环境变量覆盖回去。
    """
    if store.has_password():
        return None
    initial = os.environ.get("AWS_HELPER_PASSWORD") or auth.generate_password()
    # 环境变量给的弱密码也要能用，否则首次启动直接卡死
    store.set_password(initial, validate=False)
    return initial


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    initial = _bootstrap_password()
    if initial:
        print("=" * 64)
        print(f"  面板初始密码: {initial}")
        print("  登录后请在「用户面板」修改；忘记密码可执行：")
        print("    python3 -m aws_helper.cli reset-password")
        print("=" * 64)
    monitor.start()
    ddns_monitor.start()
    report_server.start()
    yield
    monitor.stop()
    ddns_monitor.stop()
    report_server.stop()


app = FastAPI(title="AWS 小助手", version=__version__, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("AWS_HELPER_SESSION_KEY") or secrets.token_hex(32),
    session_cookie="awshelper",
    max_age=SESSION_TTL,
    same_site="lax",
)
static_dir = BASE / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def _client_ip(request: Request) -> str:
    """取客户端 IP。反代后面优先用 X-Forwarded-For 的第一跳。"""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def require_login(request: Request) -> None:
    """会话必须同时通过 Cookie 签名和数据库校验。

    只信 Cookie 的话，改密码或踢下线无法让已发出的 Cookie 失效 ——
    令牌必须在库里还存在才算有效。
    """
    token = request.session.get("token")
    if not token or not store.touch_session(token):
        request.session.clear()
        raise HTTPException(status_code=401, detail="未登录")


Guard = Depends(require_login)


@app.exception_handler(HTTPException)
async def _http_exc(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        if request.url.path.startswith("/api/"):
            return JSONResponse({"ok": False, "error": "未登录"}, status_code=401)
        return RedirectResponse("/login", status_code=302)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"ok": False, "error": exc.detail}, status_code=exc.status_code)
    return HTMLResponse(f"<h3>{exc.status_code}: {exc.detail}</h3>", status_code=exc.status_code)


# ---------------- 页面 ----------------


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        request, "login.html", {"version": __version__, "docs_url": DOCS_URL}
    )


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    ip = _client_ip(request)
    agent = request.headers.get("user-agent", "")

    state = store.lock_state(ip)
    if state.locked:
        minutes = max(1, state.retry_after // 60)
        store.record_login(False, ip, agent, "已锁定，拒绝尝试")
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": f"尝试次数过多，请 {minutes} 分钟后再试",
                "version": __version__,
                "docs_url": DOCS_URL,
            },
            status_code=429,
        )

    if not store.verify_login(password):
        after = store.record_failure(ip)
        store.record_login(False, ip, agent, "密码错误")
        if after.locked:
            message = f"密码错误次数过多，已锁定 {after.retry_after // 60} 分钟"
        else:
            message = f"密码错误，还可尝试 {after.remaining_attempts} 次"
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": message, "version": __version__, "docs_url": DOCS_URL},
            status_code=401,
        )

    store.reset_attempts(ip)
    token = store.create_session(ttl=SESSION_TTL, ip=ip, user_agent=agent)
    request.session.clear()
    request.session["token"] = token
    store.record_login(True, ip, agent, "登录成功")
    return RedirectResponse("/", status_code=302)


@app.post("/logout")
def logout(request: Request):
    token = request.session.get("token")
    if token:
        store.revoke_session_token(token)
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# 页面归属哪个服务。侧边栏按 active 高亮，这里供页面自身判断服务上下文
_SECTIONS: dict[str, str] = {
    "instances": "ec2",
    "launch": "ec2",
    "scripts": "ec2",
    "autoip": "ec2",
    "ls-instances": "lightsail",
    "ls-create": "lightsail",
    "bd-models": "bedrock",
    "bd-play": "bedrock",
}


def _page_ctx(active: str) -> dict[str, Any]:
    return {
        "active": active,
        "section": _SECTIONS.get(active, ""),
        "version": __version__,
        "accounts": store.list_accounts(),
        "regions": aws.REGIONS,
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request,
        "instances.html",
        {**_page_ctx("instances"), "monitor_on": monitor.running},
    )


@app.get("/launch", response_class=HTMLResponse)
def launch_page(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request,
        "launch.html",
        {
            **_page_ctx("launch"),
            "os_families": aws.OS_FAMILIES,
            "architectures": aws.ARCHITECTURES,
            "scripts": store.list_scripts(),
            "default_target": guard_script.DEFAULT_TARGET,
        },
    )


@app.get("/api/probe-account")
def api_probe_account(account_id: int, region: str, _: None = Guard):
    """探测账号可用性、vCPU 配额与当前用量。

    分项返回：账号可能只读正常但写操作被 AWS 封禁（账号级 Blocked），
    DryRun 也会通过，只有分项探测才能定位到底哪一步不行。
    """
    creds = store.credentials(account_id, region)
    try:
        result = aws.probe_account(creds, region)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    failed = [c["name"] for c in result["checks"] if not c["ok"]]
    store.log(
        "probe",
        region,
        result["healthy"],
        "全部通过" if result["healthy"] else f"未通过: {', '.join(failed)}",
    )
    return {"ok": True, **result}


@app.get("/api/catalog")
def api_catalog(
    account_id: int,
    region: str,
    os_family: str = "linux",
    arch: str = "x86_64",
    force: bool = False,
    _: None = Guard,
):
    """返回该区域真实可用的镜像与规格，供级联选择使用。

    规格来自 DescribeInstanceTypes（各区域支持的规格不同，写死的清单
    必然出现"选了但开不出来"）。拉取失败时降级到内置清单并标注。
    """
    if os_family not in aws.OS_FAMILIES:
        raise HTTPException(400, f"未知系统类别: {os_family}")
    if arch not in aws.ARCHITECTURES:
        raise HTTPException(400, f"未知架构: {arch}")

    creds = store.credentials(account_id, region)
    images = [
        {"key": key, "label": spec.label, "ssh_user": spec.ssh_user}
        for key, spec in aws.images_by_os_arch(os_family, arch).items()
    ]

    degraded = False
    cached = False
    age = 0.0
    try:
        types, cached, age = aws.instance_types_cached(
            creds, region, arch, force=force
        )
    except Exception as exc:
        # 降级结果不进缓存，否则一次权限失败会粘住整个 TTL
        degraded = True
        types = aws.fallback_instance_types(arch)
        store.log("catalog", region, False, f"拉取规格失败，已降级: {exc}")

    return {
        "ok": True,
        "os_family": os_family,
        "arch": arch,
        "images": images,
        "instance_types": types,
        "degraded": degraded,
        "cached": cached,
        "age_seconds": age,
        "is_windows": os_family == "windows",
    }


@app.get("/scripts", response_class=HTMLResponse)
def scripts_page(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request, "scripts.html", {**_page_ctx("scripts"), "scripts": store.list_scripts()}
    )


@app.get("/autoip", response_class=HTMLResponse)
def autoip_page(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request,
        "autoip.html",
        {
            **_page_ctx("autoip"),
            "rules": store.list_ip_rules(),
            "monitor_on": monitor.running,
            "report_port": REPORT_PORT,
            "report_port_running": report_server.running,
            "default_target": guard_script.DEFAULT_TARGET,
        },
    )


@app.get("/ddns", response_class=HTMLResponse)
def ddns_page(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request,
        "ddns.html",
        {
            **_page_ctx("ddns"),
            "rules": store.list_ddns_rules(),
            "providers": ddns.PROVIDERS,
            "monitor_on": ddns_monitor.running,
        },
    )


@app.get("/api/ddns/detect")
def api_ddns_detect(_: None = Guard):
    """探测本机公网 IP。IPv6 拿不到是常态，不当错误。"""
    return {
        "ok": True,
        "ipv4": ddns.detect_ip(4),
        "ipv6": ddns.detect_ip(6),
    }


@app.post("/api/ddns/script")
async def api_ddns_script(request: Request, _: None = Guard):
    """生成一键部署脚本。

    这条接口不落库、不校验 Token —— 脚本是给别的机器用的，
    面板只当生成器。要面板自己托管才走 /api/ddns/rules。
    """
    body = await request.json()
    try:
        script = ddns_script.render_script(
            ddns_script.ScriptRequest(
                provider=body.get("provider", "cloudflare"),
                zone=body.get("zone", ""),
                hostname=body.get("hostname", ""),
                token=body.get("token", ""),
                account_id=body.get("cf_account_id", ""),
                want_ipv4=bool(body.get("want_ipv4", True)),
                want_ipv6=bool(body.get("want_ipv6", False)),
                proxied=bool(body.get("proxied", False)),
                ttl=int(body.get("ttl", ddns.TTL_AUTO)),
                interval_sec=int(body.get("interval_sec", 300)),
                schedule=body.get("schedule", "systemd"),
            )
        )
    except ddns_script.ScriptError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except (TypeError, ValueError) as exc:
        return JSONResponse({"ok": False, "error": f"参数错误: {exc}"}, status_code=400)

    return {"ok": True, "script": script, "filename": "ddns-deploy.sh"}


@app.post("/api/ddns/rules")
async def api_ddns_save(request: Request, _: None = Guard):
    body = await request.json()
    token = (body.get("token") or "").strip()
    zone = (body.get("zone") or "").strip()
    hostname = (body.get("hostname") or "").strip()
    provider_kind = body.get("provider", "cloudflare")
    cf_account_id = (body.get("cf_account_id") or "").strip()

    # 保存前实际调一次 API —— 配错 Token 应该当场就知道，
    # 而不是等定时任务默默失败几小时后才在日志里发现。
    if token:
        try:
            ddns.verify_token(provider_kind, token, zone, cf_account_id)
        except ddns.DdnsError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    try:
        rule_id = store.save_ddns_rule(
            zone,
            hostname,
            token=token or None,
            provider=provider_kind,
            cf_account_id=cf_account_id,
            enabled=body.get("enabled", 1),
            want_ipv4=body.get("want_ipv4", 1),
            want_ipv6=body.get("want_ipv6", 0),
            ttl=int(body.get("ttl", ddns.TTL_AUTO)),
            proxied=body.get("proxied", 0),
            interval_sec=int(body.get("interval_sec", 300)),
            note=body.get("note", ""),
        )
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    store.log("ddns", hostname, True, f"保存规则（{provider_kind} / {zone}）")
    return {"ok": True, "id": rule_id}


@app.post("/api/ddns/rules/{rule_id}/run")
def api_ddns_run(rule_id: int, _: None = Guard):
    """立刻跑一次这条规则，不等间隔。"""
    rule = store.ddns_rule(rule_id)
    if rule is None:
        return JSONResponse({"ok": False, "error": "规则不存在"}, status_code=404)
    # last_check 归零绕过间隔判断，用户点了就该立刻执行
    result = ddns_check_rule(store, {**rule, "last_check": 0})
    return {"ok": True, **result}


@app.get("/api/ddns/rules/{rule_id}/status")
def api_ddns_status(rule_id: int, _: None = Guard):
    """查这条 DDNS 规则的运行状态，附排查方向。

    跟自动换 IP 的状态接口对齐：光说「失败」没用，要给出下一步查什么。
    """
    rule = store.ddns_rule(rule_id)
    if rule is None:
        return JSONResponse({"ok": False, "error": "规则不存在"}, status_code=404)

    now = int(time.time())
    last_check = int(rule["last_check"])
    interval = int(rule["interval_sec"]) or 300
    grace = interval * 3
    fail_count = int(rule["fail_count"])
    status = rule["last_status"] or ""

    hints: list[str] = []
    if not int(rule["enabled"]):
        state = "disabled"
        summary = "规则已停用"
    elif last_check == 0:
        state = "not_run"
        summary = "还没跑过"
        hints.append("点「立即执行」跑一次，能直接看到报错")
    elif fail_count:
        state = "failing"
        summary = f"连续失败 {fail_count} 次：{status}"
        hints.append("Token 是否过期、权限是否为 Zone → DNS → Edit")
        hints.append(f"Token 的区域范围是否覆盖 {rule['zone']}")
        hints.append("点「立即执行」看完整报错")
    elif now - last_check > grace:
        state = "stale"
        summary = f"上次执行在 {now - last_check} 秒前，超过 {grace} 秒宽限"
        hints.append("面板的 DDNS 监控线程可能没在跑，检查面板服务状态")
    else:
        state = "ok"
        summary = f"正常，上次执行在 {now - last_check} 秒前"

    return {
        "ok": True,
        "state": state,
        "summary": summary,
        "hints": hints,
        "hostname": rule["hostname"],
        "last_check": last_check,
        "last_check_ago": (now - last_check) if last_check else None,
        "last_status": status,
        "last_ipv4": rule["last_ipv4"],
        "last_ipv6": rule["last_ipv6"],
        "fail_count": fail_count,
        "monitor_running": ddns_monitor.running,
    }


@app.delete("/api/ddns/rules/{rule_id}")
def api_ddns_delete(rule_id: int, _: None = Guard):
    store.delete_ddns_rule(rule_id)
    store.log("ddns", str(rule_id), True, "删除规则")
    return {"ok": True}


@app.get("/accounts", response_class=HTMLResponse)
def accounts_page(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request, "accounts.html", {**_page_ctx("accounts"), "logs": store.list_logs(50)}
    )


@app.get("/lightsail", response_class=HTMLResponse)
def lightsail_page(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request, "lightsail.html", _page_ctx("ls-instances")
    )


@app.get("/lightsail/create", response_class=HTMLResponse)
def lightsail_create_page(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request, "lightsail_create.html", _page_ctx("ls-create")
    )


@app.get("/bedrock", response_class=HTMLResponse)
def bedrock_page(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request,
        "bedrock.html",
        {**_page_ctx("bd-models"), "bedrock_regions": bedrock.supported_regions()},
    )


@app.get("/bedrock/playground", response_class=HTMLResponse)
def bedrock_play_page(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request,
        "bedrock_play.html",
        {**_page_ctx("bd-play"), "bedrock_regions": bedrock.supported_regions()},
    )


# ---------------- Lightsail API ----------------


@app.get("/api/lightsail/catalog")
def api_ls_catalog(account_id: int, region: str, force: bool = False, _: None = Guard):
    """Lightsail 的套餐与蓝图。区域支持范围比 EC2 窄，要单独校验。

    套餐和蓝图基本不变（实测 ap-east-1 有 100 个套餐），缓存 6 小时。
    原先每打开一次创建页就是 3 次 AWS 调用。
    """
    creds = store.credentials(account_id, region)
    try:
        regions, _rc, _ra = cache.fetch(
            ls_regions_key(account_id),
            CATALOG_TTL,
            lambda: lightsail.available_regions(creds, region),
            force=force,
        )
    except lightsail.LightsailError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    if region not in regions:
        return JSONResponse(
            {
                "ok": False,
                "error": f"{region} 不支持 Lightsail。可用区域：{', '.join(regions[:6])} 等",
            },
            status_code=400,
        )

    def load() -> dict[str, Any]:
        return {
            "bundles": lightsail.list_bundles(creds, region),
            "blueprints": lightsail.list_blueprints(creds, region),
        }

    try:
        catalog, cached, age = cache.fetch(
            ls_catalog_key(account_id, region), CATALOG_TTL, load, force=force
        )
    except lightsail.LightsailError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    return {
        "ok": True,
        "region": region,
        "supported_regions": regions,
        "bundles": catalog["bundles"],
        "blueprints": catalog["blueprints"],
        "cached": cached,
        "age_seconds": age,
    }


@app.get("/api/lightsail/instances")
def api_ls_instances(
    account_id: int, region: str, force: bool = False, _: None = Guard
):
    def load() -> dict[str, Any]:
        return {
            "instances": lightsail.list_instances(creds, region),
            "static_ips": lightsail.list_static_ips(creds, region),
        }

    creds = store.credentials(account_id, region)
    try:
        data, cached, age = cache.fetch(
            ls_instances_key(account_id, region), INSTANCES_TTL, load, force=force
        )
    except lightsail.LightsailError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    return {"ok": True, **data, "cached": cached, "age_seconds": age}


@app.post("/api/lightsail/create")
async def api_ls_create(request: Request, _: None = Guard):
    body = await request.json()
    account_id = int(body["account_id"])
    region = body["region"]
    creds = store.credentials(account_id, region)

    def job(progress: Any) -> dict[str, Any]:
        try:
            result = lightsail.create_instance(
                creds,
                region,
                name=str(body.get("name", "")).strip(),
                bundle_id=body.get("bundle_id", ""),
                blueprint_id=body.get("blueprint_id", ""),
                user_data=body.get("user_data", ""),
                progress=progress,
            )
        finally:
            cache.drop(*ls_instances_key(account_id, region))
        store.log(
            "lightsail",
            result["name"],
            True,
            f"{result['bundle_id']} / {result['blueprint_id']} → {result['public_ip']}",
        )
        return result

    task_id = manager.submit(
        "lightsail", f"创建轻量实例 {body.get('name', '')}", job
    )
    return {"ok": True, "task_id": task_id}


@app.post("/api/lightsail/power")
async def api_ls_power(request: Request, _: None = Guard):
    body = await request.json()
    account_id = int(body["account_id"])
    creds = store.credentials(account_id, body["region"])
    names = body.get("names") or []
    action = body["action"]
    try:
        result = lightsail.power(creds, body["region"], action, names)
    except lightsail.LightsailError as exc:
        store.log("lightsail", ",".join(names), False, f"{action} 失败: {exc}")
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    finally:
        cache.drop(*ls_instances_key(account_id, body["region"]))

    detail = f"{action} 完成"
    if result.get("released_static_ips"):
        detail += f"，释放静态 IP {len(result['released_static_ips'])} 个"
    store.log("lightsail", ",".join(names), not result["failed"], detail)
    return {"ok": True, **result}


# ---------------- Bedrock API ----------------


@app.get("/api/bedrock/models")
def api_bd_models(account_id: int, region: str, force: bool = False, _: None = Guard):
    """模型清单。TTL 只给 15 分钟 —— 模型访问是用户在控制台申请的，
    刚开通就得能看到，不能让他等 6 小时。"""
    creds = store.credentials(account_id, region)
    try:
        data, cached, age = cache.fetch(
            bedrock_models_key(account_id, region),
            BEDROCK_TTL,
            lambda: bedrock.list_models(creds, region),
            force=force,
        )
    except bedrock.BedrockError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    return {"ok": True, **data, "cached": cached, "age_seconds": age}


@app.get("/api/bedrock/probe")
def api_bd_probe(account_id: int, region: str, _: None = Guard):
    creds = store.credentials(account_id, region)
    result = bedrock.probe(creds, region)
    store.log(
        "bedrock",
        region,
        result["available"],
        f"{result.get('total', 0)} 个模型" if result["available"] else "服务不可用",
    )
    return {"ok": True, **result}


@app.post("/api/bedrock/invoke")
async def api_bd_invoke(request: Request, _: None = Guard):
    body = await request.json()
    creds = store.credentials(int(body["account_id"]), body["region"])
    try:
        result = bedrock.invoke_text(
            creds,
            body["region"],
            body.get("model_id", ""),
            body.get("prompt", ""),
            int(body.get("max_tokens", 256)),
        )
    except bedrock.BedrockError as exc:
        store.log("bedrock", body.get("model_id", ""), False, str(exc)[:200])
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    store.log(
        "bedrock",
        result["model_id"],
        True,
        f"输入 {result['input_tokens']} / 输出 {result['output_tokens']} tokens",
    )
    return {"ok": True, **result}


@app.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request, _: None = Guard):
    token = request.session.get("token")
    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            **_page_ctx("profile"),
            "sessions": store.list_sessions(current_token=token),
            "history": store.list_login_history(30),
            "password_changed_at": store.password_changed_at(),
            "min_length": auth.MIN_LENGTH,
            "fail_limit": auth.FAIL_LIMIT,
            "lock_minutes": auth.LOCK_SECONDS // 60,
            "session_hours": SESSION_TTL // 3600,
        },
    )


# ---------------- 用户面板 API ----------------


@app.post("/api/profile/password")
async def api_change_password(request: Request, _: None = Guard):
    body = await request.form()
    current = (body.get("current_password") or "").strip()
    new = (body.get("new_password") or "").strip()
    confirm = (body.get("confirm_password") or "").strip()

    if not store.verify_login(current):
        store.record_login(
            False,
            _client_ip(request),
            request.headers.get("user-agent", ""),
            "修改密码时旧密码错误",
        )
        return JSONResponse({"ok": False, "error": "当前密码不正确"}, status_code=400)
    if new != confirm:
        return JSONResponse({"ok": False, "error": "两次输入的新密码不一致"}, status_code=400)
    if new == current:
        return JSONResponse(
            {"ok": False, "error": "新密码不能与当前密码相同"}, status_code=400
        )
    try:
        auth.validate_strength(new)
    except auth.PasswordError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    # set_password 清掉全部会话，这里给当前浏览器补发新令牌，
    # 否则改密码的人会把自己也踢下线。
    store.set_password(new)
    request.session["token"] = store.create_session(
        ttl=SESSION_TTL,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )
    store.log("auth", "password", True, "修改登录密码，其他会话已失效")
    return {"ok": True, "message": "密码已更新，其他设备的登录已失效"}


@app.get("/api/profile/sessions")
def api_list_sessions(request: Request, _: None = Guard):
    token = request.session.get("token")
    return {"ok": True, "sessions": store.list_sessions(current_token=token)}


@app.delete("/api/profile/sessions/{session_id}")
def api_revoke_session(session_id: str, request: Request, _: None = Guard):
    token = request.session.get("token")
    current = store.list_sessions(current_token=token)
    target = [s for s in current if s["id"] == session_id]
    if not target:
        raise HTTPException(404, "会话不存在或已过期")
    if target[0]["current"]:
        return JSONResponse(
            {"ok": False, "error": "不能踢掉当前会话，请直接退出登录"}, status_code=400
        )
    store.revoke_session(session_id)
    store.log("auth", "session", True, f"踢下线会话 {session_id}")
    return {"ok": True}


@app.post("/api/profile/sessions/revoke-others")
def api_revoke_other_sessions(request: Request, _: None = Guard):
    token = request.session.get("token")
    removed = store.clear_sessions(keep_token=token)
    store.log("auth", "session", True, f"下线其他会话 {removed} 个")
    return {"ok": True, "removed": removed}


@app.get("/api/profile/login-history")
def api_login_history(limit: int = 50, _: None = Guard):
    return {"ok": True, "history": store.list_login_history(limit)}


# ---------------- 账号 API ----------------


@app.post("/api/accounts")
def api_add_account(
    label: str = Form(...),
    access_key: str = Form(...),
    secret_key: str = Form(...),
    region: str = Form("us-east-1"),
    note: str = Form(""),
    proxy: str = Form(""),
    _: None = Guard,
):
    try:
        normalized = aws.normalize_proxy(proxy)
    except aws.ProxyError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    creds = aws.Credentials(
        access_key.strip(), secret_key.strip(), region, proxy=normalized
    )
    try:
        info = aws.verify(creds)
    except aws.ProxyError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse(
            {"ok": False, "error": f"凭据校验失败: {exc}"}, status_code=400
        )
    try:
        account_id = store.add_account(
            label.strip(), access_key.strip(), secret_key.strip(), region, note, normalized
        )
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"保存失败: {exc}"}, status_code=400)

    detail = f"添加账号，可用区域 {info['regions']} 个"
    if normalized:
        detail += f"，出站代理 {aws.mask_proxy(normalized)}"
    store.log("account", label, True, detail)
    return {"ok": True, "id": account_id, "regions": info["regions"]}


@app.get("/api/accounts/{account_id}")
def api_get_account(account_id: int, _: None = Guard):
    try:
        acct = store.get_account(account_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {
        "ok": True,
        "account": {
            "id": acct.id,
            "label": acct.label,
            "access_key": acct.access_key,
            "region": acct.region,
            "note": acct.note,
            "proxy": acct.proxy or "",
            "masked_proxy": acct.masked_proxy(),
        },
    }


@app.put("/api/accounts/{account_id}")
async def api_update_account(account_id: int, request: Request, _: None = Guard):
    body = await request.form()
    try:
        current = store.get_account(account_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc

    label = (body.get("label") or "").strip()
    access_key = (body.get("access_key") or "").strip()
    secret_key = (body.get("secret_key") or "").strip()
    region = (body.get("region") or "").strip() or current.region
    note = body.get("note")
    proxy_raw = (body.get("proxy") or "").strip()
    clear_proxy = not proxy_raw

    if not label:
        return JSONResponse({"ok": False, "error": "备注名必填"}, status_code=400)
    if not access_key:
        return JSONResponse({"ok": False, "error": "Access Key 必填"}, status_code=400)

    try:
        normalized = aws.normalize_proxy(proxy_raw)
    except aws.ProxyError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    # 留空表示沿用原密钥，避免编辑时被迫重新粘贴 Secret
    effective_secret = secret_key or store.credentials(account_id).secret_key
    try:
        aws.verify(
            aws.Credentials(access_key, effective_secret, region, proxy=normalized)
        )
    except aws.ProxyError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse(
            {"ok": False, "error": f"凭据校验失败: {exc}"}, status_code=400
        )

    try:
        store.update_account(
            account_id,
            label=label,
            access_key=access_key,
            secret_key=secret_key or None,
            region=region,
            note=note if note is not None else None,
            proxy=normalized,
            clear_proxy=clear_proxy,
        )
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"保存失败: {exc}"}, status_code=400)

    # 换了密钥或代理，出口和权限都可能变了，旧结果不能再用
    cache.drop_account(account_id)
    store.log(
        "account",
        label,
        True,
        f"更新账号，出站代理 {aws.mask_proxy(normalized) or '未配置'}",
    )
    return {"ok": True, "id": account_id}


@app.post("/api/accounts/test-proxy")
async def api_test_proxy(request: Request, _: None = Guard):
    """用给定代理实际调一次 AWS API，验证代理与凭据是否都能用。"""
    body = await request.json()
    try:
        normalized = aws.normalize_proxy(body.get("proxy") or "")
    except aws.ProxyError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    if not normalized:
        return JSONResponse({"ok": False, "error": "请先填写代理地址"}, status_code=400)

    account_id = body.get("account_id")
    if account_id:
        stored = store.credentials(int(account_id))
        access_key, secret_key = stored.access_key, stored.secret_key
        region = body.get("region") or stored.region
    else:
        access_key = (body.get("access_key") or "").strip()
        secret_key = (body.get("secret_key") or "").strip()
        region = body.get("region") or "us-east-1"
        if not access_key or not secret_key:
            return JSONResponse(
                {"ok": False, "error": "新增账号测试代理需要填 Access Key 和 Secret Key"},
                status_code=400,
            )

    started = time.monotonic()
    try:
        info = aws.verify(
            aws.Credentials(access_key, secret_key, region, proxy=normalized)
        )
    except aws.ProxyError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse(
            {"ok": False, "error": f"代理可用，但 AWS 调用失败: {exc}"}, status_code=400
        )
    elapsed = round((time.monotonic() - started) * 1000)
    return {
        "ok": True,
        "proxy": aws.mask_proxy(normalized),
        "regions": info["regions"],
        "elapsed_ms": elapsed,
    }


@app.delete("/api/accounts/{account_id}")
def api_delete_account(account_id: int, _: None = Guard):
    store.delete_account(account_id)
    cache.drop_account(account_id)
    store.log("account", str(account_id), True, "删除账号")
    return {"ok": True}


# ---------------- 实例 API ----------------


def _fingerprint(items: list[dict[str, Any]]) -> str:
    """算清单指纹，用来判断「和上次相比有没有变」。

    先按 instance_id 排序再算 —— 同批开机的实例 launch_time 精确到秒是相同的，
    AWS 返回顺序不固定，直接算会得到假的「变了」。
    """
    stable = sorted(items, key=lambda i: i.get("instance_id", ""))
    raw = json.dumps(stable, sort_keys=True, default=str).encode()
    return hashlib.sha1(raw).hexdigest()[:16]


@app.get("/api/instances")
def api_instances(
    account_id: int,
    region: str,
    force: bool = False,
    fingerprint: str = "",
    _: None = Guard,
):
    """实例清单。默认走 10 秒缓存，force=1 强制回源。

    缓存窗口刻意压得比人的反应时间短 —— 实例状态是用户盯着看的东西，
    宁可多调一次也不能显示已经不成立的状态。开关机、终止、换 IP 之后
    会主动失效缓存，不用等 TTL 到期。
    """
    creds = store.credentials(account_id, region)
    try:
        items, cached, age = cache.fetch(
            ec2_instances_key(account_id, region),
            INSTANCES_TTL,
            lambda: launch.list_instances(creds, region),
            force=force,
        )
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    current = _fingerprint(items)
    body: dict[str, Any] = {
        "ok": True,
        "cached": cached,
        "age_seconds": age,
        "fingerprint": current,
        "changed": current != fingerprint,
    }
    # 没变就不回传列表：前端保留现有 DOM 和勾选状态，避免整表重绘
    if current != fingerprint:
        body["instances"] = items
    return body


@app.get("/api/instances/creds")
def api_instance_creds(account_id: int, region: str, _: None = Guard):
    """本区域所有实例的登录方式。密码只回「有没有」，不回明文。"""
    return {
        "ok": True,
        "creds": store.list_instance_creds(account_id, region),
    }


@app.get("/api/instances/{instance_id}/password")
def api_instance_password(
    account_id: int, region: str, instance_id: str, _: None = Guard
):
    """取实例密码明文。用户点「查看」才调，并记一条审计日志。"""
    try:
        password = store.instance_password(account_id, region, instance_id)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=404)
    store.log("creds", instance_id, True, "查看了实例登录密码")
    return {"ok": True, "instance_id": instance_id, "password": password}


@app.get("/api/instances/ssm-status")
def api_ssm_status(account_id: int, region: str, instance_id: str, _: None = Guard):
    """查实例能不能用 SSM 重置密码。点按钮前先探一下，省得填完表单才发现不支持。"""
    creds = store.credentials(account_id, region)
    return {"ok": True, **respw.ssm_status(creds, region, instance_id)}


@app.post("/api/instances/reset-password")
async def api_reset_password(request: Request, _: None = Guard):
    """重置实例登录密码。走后台任务 —— SSM 下发加轮询可能十几秒。"""
    body = await request.json()
    account_id = int(body["account_id"])
    region = body["region"]
    instance_id = body["instance_id"]
    password = body.get("password") or ""
    user = (body.get("user") or "").strip()
    is_windows = bool(body.get("is_windows"))

    if not user:
        user = "Administrator" if is_windows else "root"

    # 弱密码在这里必须拦住：这个密码是要开着 SSH 密码登录用的，
    # 弱口令等于把机器直接交出去。
    try:
        auth.validate_strength(password)
    except auth.PasswordError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    creds = store.credentials(account_id, region)

    def job(progress: Any) -> dict[str, Any]:
        try:
            result = respw.reset_password(
                creds, region, instance_id, password, user, is_windows, progress
            )
        except respw.PasswordResetError as exc:
            # 密码绝不进日志
            store.log("reset-password", instance_id, False, str(exc)[:400])
            raise
        # 重置成功后这台机器就能用密码登录了，凭据记录要跟上，
        # 否则面板上还显示只能用密钥。
        store.save_instance_creds(
            account_id,
            region,
            instance_id,
            auth_method="password",
            login_user=user,
            password=password,
            os_family="windows" if is_windows else "linux",
            note="通过 SSM 重置",
        )
        store.log("reset-password", instance_id, True, f"已重置 {user} 的密码")
        return result

    task_id = manager.submit(
        "reset-password", f"重置 {instance_id} 的 {user} 密码", job
    )
    return {"ok": True, "task_id": task_id}


@app.get("/api/instances/reinstall-preflight")
def api_reinstall_preflight(
    account_id: int,
    region: str,
    instance_id: str,
    image_key: str = "",
    image_id: str = "",
    _: None = Guard,
):
    """重装前预检。点开弹窗和换镜像时各调一次，把不匹配挡在点确认之前。"""
    creds = store.credentials(account_id, region)
    try:
        return {"ok": True, **reinstall.preflight(
            creds, region, instance_id, image_key, image_id
        )}
    except reinstall.ReinstallError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.post("/api/instances/reinstall")
async def api_reinstall(request: Request, _: None = Guard):
    """重装系统（换根卷）。走后台任务 —— 实测 3-5 分钟。"""
    body = await request.json()
    account_id = int(body["account_id"])
    region = body["region"]
    instance_id = body["instance_id"]
    image_key = (body.get("image_key") or "").strip()
    image_id = (body.get("image_id") or "").strip()
    delete_old = bool(body.get("delete_old_volume", True))
    new_password = body.get("root_password") or ""
    new_public_key = (body.get("ssh_public_key") or "").strip()

    # 重装后设的密码同样要开着 SSH 密码登录，弱口令等于把机器交出去。
    if new_password:
        try:
            auth.validate_strength(new_password)
        except auth.PasswordError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    if new_public_key:
        try:
            new_public_key = respw.validate_public_key(new_public_key)
        except respw.PasswordResetError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    creds = store.credentials(account_id, region)

    def job(progress: Any) -> dict[str, Any]:
        try:
            result = reinstall.reinstall(
                creds,
                region,
                instance_id,
                image_key,
                image_id,
                delete_old,
                progress,
                new_password=new_password,
                new_public_key=new_public_key,
            )
        except reinstall.ReinstallError as exc:
            store.log("reinstall", instance_id, False, str(exc)[:400])
            raise
        finally:
            # 根卷换了，实例的镜像 id 和状态都变了，缓存必须作废
            cache.drop(*ec2_instances_key(account_id, region))
        # 换了系统登录用户可能变了（Ubuntu→ubuntu、Debian→admin），
        # 而根卷重铺后原来设的 root 密码也没了 —— 凭据记录改回密钥登录。
        # 但如果这次重装顺带设了新凭据且设置成功，就记新的那套。
        applied = result.get("creds_applied")
        if applied and new_password:
            store.save_instance_creds(
                account_id,
                region,
                instance_id,
                auth_method="password",
                login_user=result.get("login_user") or "root",
                password=new_password,
                os_family=result.get("os_family", "linux"),
                note=f"重装于 {result['image_id']} 并设置密码",
            )
        elif applied and new_public_key:
            store.save_instance_creds(
                account_id,
                region,
                instance_id,
                auth_method="key",
                login_user=result.get("login_user") or "root",
                key_name=result.get("key_name", ""),
                os_family=result.get("os_family", "linux"),
                note=f"重装于 {result['image_id']}，已写入自备公钥",
            )
        elif result.get("ssh_user"):
            store.save_instance_creds(
                account_id,
                region,
                instance_id,
                auth_method="key",
                login_user=result["ssh_user"],
                key_name=result.get("key_name", ""),
                os_family=result.get("os_family", "linux"),
                note=f"重装于 {result['image_id']}",
            )
        store.log(
            "reinstall",
            instance_id,
            True,
            f"重装完成（{result['image_id']}，耗时 {result['elapsed_sec']}s）",
        )
        return result

    task_id = manager.submit("reinstall", f"重装 {instance_id}", job)
    return {"ok": True, "task_id": task_id}


@app.post("/api/instances/credit-mode")
async def api_credit_mode(request: Request, _: None = Guard):
    """改 T 实例的 CPU 积分模式。unlimited 会按超额积分计费，standard 只降速。"""
    body = await request.json()
    account_id = int(body["account_id"])
    region = body["region"]
    ids = body.get("instance_ids") or []
    mode = body.get("mode") or "standard"
    creds = store.credentials(account_id, region)

    try:
        result = launch.set_credit_mode(creds, region, ids, mode)
    except launch.LaunchError as exc:
        store.log("credit-mode", ",".join(ids), False, str(exc)[:400])
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    # 积分模式变了，实例列表里那一列也得跟着变，缓存必须作废
    cache.drop(*ec2_instances_key(account_id, region))
    store.log(
        "credit-mode",
        ",".join(ids),
        not result["failed"],
        f"改为 {mode}，成功 {len(result['succeeded'])}"
        + (f"，失败: {'; '.join(result['failed'])}" if result["failed"] else ""),
    )
    return {"ok": True, **result}


@app.post("/api/instances/power")
async def api_power(request: Request, _: None = Guard):
    body = await request.json()
    account_id = int(body["account_id"])
    region = body["region"]
    action = body["action"]
    ids = body.get("instance_ids") or []
    cleanup = bool(body.get("cleanup", True))
    creds = store.credentials(account_id, region)

    # terminate 要清理关联资源（等实例真终止 + 删卷/网络），耗时可达数分钟，
    # 必须走后台任务，否则 HTTP 请求会超时。
    if action == "terminate":
        def job(progress: Any) -> dict[str, Any]:
            try:
                result = launch.power(creds, region, action, ids, cleanup, progress)
                cleaned = result.get("cleaned", {})
                summary = "，".join(
                    f"{name} {len(items)}" for name, items in cleaned.items() if items
                )
                store.log(
                    "terminate",
                    ",".join(ids),
                    not result.get("failed"),
                    f"已清理: {summary or '仅实例'}"
                    + (f"；失败: {'; '.join(result['failed'])}" if result.get("failed") else ""),
                )
                # 实例没了就别留着它的密码。实例 ID 会被 AWS 复用，
                # 留着会让下一台同 ID 的机器显示错的凭据。
                for terminated in ids:
                    store.delete_instance_creds(account_id, region, terminated)
                return result
            finally:
                # 必须在后台任务内失效，不能在提交处 —— 提交时实例还没真终止。
                # 用 finally：失败也可能已经部分变更。
                cache.drop(*ec2_instances_key(account_id, region))

        task_id = manager.submit("terminate", f"终止并清理 {len(ids)} 台实例", job)
        return {"ok": True, "task_id": task_id, "action": action}

    try:
        result = launch.power(creds, region, action, ids)
    except Exception as exc:
        store.log("power", ",".join(ids), False, f"{action} 失败: {exc}")
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    finally:
        cache.drop(*ec2_instances_key(account_id, region))
    store.log("power", ",".join(ids), True, f"{action} 成功")
    return {"ok": True, **{k: v for k, v in result.items() if k != "raw"}}


@app.post("/api/launch")
async def api_launch(request: Request, _: None = Guard):
    body = await request.json()
    account_id = int(body["account_id"])
    region = body["region"]
    creds = store.credentials(account_id, region)

    try:
        req = launch.LaunchRequest(
            name=str(body["name"]).strip(),
            region=region,
            instance_type=body.get("instance_type", "t3.micro"),
            image_key=body.get("image_key", "ubuntu-24.04"),
            image_id=(body.get("image_id") or "").strip() or None,
            disk_size=int(body.get("disk_size", 16)),
            count=int(body.get("count", 1)),
            open_ports=[int(p) for p in body.get("open_ports") or [22]],
            # 字段缺失时默认全放通，与表单默认勾选一致
            allow_all_ports=bool(body.get("allow_all_ports", True)),
            enable_ipv6=bool(body.get("enable_ipv6")),
            script=body.get("script", ""),
            root_password=body.get("root_password") or None,
            packages=[p for p in (body.get("packages") or []) if p.strip()],
        )
    except (KeyError, ValueError) as exc:
        return JSONResponse({"ok": False, "error": f"参数错误: {exc}"}, status_code=400)

    if not req.name:
        return JSONResponse({"ok": False, "error": "实例名称必填"}, status_code=400)

    # 开机时附带部署 autoip / DDNS。凭证按这一批签发 —— user-data 必须在
    # RunInstances 之前定稿，那时实例 ID 还不存在。
    agent_token = secrets.token_urlsafe(32) if body.get("deploy_autoip") else ""
    try:
        deploy_blocks, autoip_cfg = _deploy_blocks(body, req, agent_token)
    except (launch_deploy.DeployError, ScriptError, guard_script.GuardScriptError,
            ddns_script.ScriptError, RuntimeError) as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    # 提前校验脚本，避免开机跑到一半才报错
    try:
        render(
            ScriptOptions(
                custom_script=req.script,
                root_password=req.root_password,
                hostname=req.name,
                packages=req.packages,
                deploy_blocks=deploy_blocks,
            )
        )
    except ScriptError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    req.deploy_blocks = deploy_blocks

    def job(progress: Any) -> dict[str, Any]:
        try:
            results = launch.launch(creds, req, progress)
        finally:
            cache.drop(*ec2_instances_key(account_id, region))
        for res in results:
            if res.private_key:
                store.save_keypair(account_id, region, res.key_name, res.private_key)
            # 记下这台机器怎么登录。设了 root 密码就记密码，否则记密钥 ——
            # 不记的话开完机关掉页面，密码就再也找不回来了（它只存在于 user-data）。
            store.save_instance_creds(
                account_id,
                region,
                res.instance_id,
                auth_method="password" if req.root_password else "key",
                login_user="root" if req.root_password else res.ssh_user,
                password=req.root_password,
                key_name=res.key_name,
                name=res.name,
                os_family=res.os_family,
            )
            if autoip_cfg is not None:
                _create_agent_rule(account_id, region, res.instance_id, autoip_cfg)
            store.log(
                "launch",
                res.instance_id,
                True,
                f"{res.name} {res.instance_type} {res.public_ip or '无公网IP'}",
            )
        return {
            "instances": [
                {
                    "instance_id": r.instance_id,
                    "name": r.name,
                    "public_ip": r.public_ip,
                    "private_ip": r.private_ip,
                    "ipv6": r.ipv6,
                    "ssh_user": r.ssh_user,
                    "key_name": r.key_name,
                    "has_private_key": bool(r.private_key),
                    "state": r.state,
                    "os_family": r.os_family,
                }
                for r in results
            ],
            "deployed_autoip": autoip_cfg is not None,
            "deployed_ddns": bool(body.get("deploy_ddns")),
        }

    task_id = manager.submit("launch", f"开机 {req.name} x{req.count}", job)
    return {"ok": True, "task_id": task_id}


def _deploy_blocks(
    body: dict[str, Any], req: launch.LaunchRequest, agent_token: str
) -> tuple[list[str], launch_deploy.AutoipDeploy | None]:
    """按勾选项渲染要内联进 user-data 的部署段。

    Windows 直接拒绝：这两个脚本都是 bash + systemd，装不上去，
    静默跳过会让用户以为装好了。
    """
    blocks: list[str] = []
    autoip_cfg: launch_deploy.AutoipDeploy | None = None
    windows = req.image_key.startswith("windows") or "windows" in (req.image_key or "")

    if agent_token:
        if windows:
            raise launch_deploy.DeployError("Windows 实例不支持自动换 IP 探测器")
        autoip_cfg = launch_deploy.parse_autoip(
            body.get("autoip") or {}, _report_url(), agent_token
        )
        blocks.append(launch_deploy.render_autoip_block(autoip_cfg))

    if body.get("deploy_ddns"):
        if windows:
            raise launch_deploy.DeployError("Windows 实例不支持 DDNS 更新器")
        ddns_cfg = launch_deploy.parse_ddns(body.get("ddns") or {}, req.count)
        blocks.append(launch_deploy.render_ddns_block(ddns_cfg))

    return blocks, autoip_cfg


def _create_agent_rule(
    account_id: int,
    region: str,
    instance_id: str,
    cfg: launch_deploy.AutoipDeploy,
) -> None:
    """给刚开好的实例建一条 agent 模式规则，共用这一批的上报凭证。"""
    rule_id = store.save_ip_rule(
        account_id=account_id,
        region=region,
        instance_id=instance_id,
        enabled=1,
        strategy=cfg.strategy,
        probe_mode="agent",
        agent_target=cfg.target,
        agent_interval_sec=cfg.interval_sec,
        agent_fail_threshold=cfg.fail_threshold,
    )
    store.save_agent_token_hash(rule_id, cfg.token)


# ---------------- 换 IP API ----------------


@app.post("/api/change-ip")
async def api_change_ip(request: Request, _: None = Guard):
    body = await request.json()
    account_id = int(body["account_id"])
    region = body["region"]
    instance_id = body["instance_id"]
    strategy = body.get("strategy", "eip")
    creds = store.credentials(account_id, region)
    rule = ipchange.IpRule(
        allow_cidrs=[c for c in (body.get("allow_cidrs") or []) if c.strip()],
        deny_cidrs=[c for c in (body.get("deny_cidrs") or []) if c.strip()],
        max_attempts=int(body.get("max_attempts", 1)),
    )

    def job(progress: Any) -> dict[str, Any]:
        try:
            result = ipchange.change_ip(
                creds, region, instance_id, strategy, rule, progress
            )
        finally:
            cache.drop(*ec2_instances_key(account_id, region))
        store.log(
            "change-ip",
            instance_id,
            True,
            f"{result.old_ip} → {result.new_ip}（{result.strategy}, {result.attempts} 次）",
        )
        return {
            "instance_id": result.instance_id,
            "old_ip": result.old_ip,
            "new_ip": result.new_ip,
            "strategy": result.strategy,
            "attempts": result.attempts,
            "released": result.released,
        }

    task_id = manager.submit("change-ip", f"换 IP {instance_id}", job)
    return {"ok": True, "task_id": task_id}


@app.get("/api/addresses")
def api_addresses(account_id: int, region: str, _: None = Guard):
    creds = store.credentials(account_id, region)
    try:
        return {"ok": True, "addresses": ipchange.list_addresses(creds, region)}
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.post("/api/addresses/release-idle")
async def api_release_idle(request: Request, _: None = Guard):
    body = await request.json()
    creds = store.credentials(int(body["account_id"]), body["region"])
    try:
        freed = ipchange.release_idle(creds, body["region"])
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    store.log("release-eip", body["region"], True, f"释放 {len(freed)} 个空闲弹性 IP")
    return {"ok": True, "released": freed}


# ---------------- 脚本模板 API ----------------


@app.post("/api/scripts")
def api_save_script(
    name: str = Form(...),
    body: str = Form(""),
    packages: str = Form(""),
    _: None = Guard,
):
    pkgs = [p.strip() for p in packages.replace(",", " ").split() if p.strip()]
    try:
        render(ScriptOptions(custom_script=body, packages=pkgs))
    except ScriptError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    script_id = store.save_script(name.strip(), body, pkgs)
    return {"ok": True, "id": script_id}


@app.delete("/api/scripts/{script_id}")
def api_delete_script(script_id: int, _: None = Guard):
    store.delete_script(script_id)
    return {"ok": True}


@app.post("/api/scripts/preview")
async def api_preview_script(request: Request, _: None = Guard):
    body = await request.json()
    try:
        text = render(
            ScriptOptions(
                custom_script=body.get("body", ""),
                root_password=body.get("root_password") or None,
                hostname=body.get("hostname") or None,
                packages=[p for p in (body.get("packages") or []) if p.strip()],
            )
        )
    except ScriptError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    return {"ok": True, "rendered": text}


# ---------------- 自动换 IP 规则 API ----------------


@app.post("/api/ip-rules")
async def api_save_rule(request: Request, _: None = Guard):
    body = await request.json()
    rule_id = store.save_ip_rule(
        account_id=int(body["account_id"]),
        region=body["region"],
        instance_id=body["instance_id"],
        enabled=1 if body.get("enabled", True) else 0,
        strategy=body.get("strategy", "eip"),
        check_mode=body.get("check_mode", "tcp"),
        check_port=int(body.get("check_port", 22)),
        interval_sec=int(body.get("interval_sec", 300)),
        fail_threshold=int(body.get("fail_threshold", 3)),
        allow_cidrs=[c.strip() for c in (body.get("allow_cidrs") or []) if c.strip()],
        deny_cidrs=[c.strip() for c in (body.get("deny_cidrs") or []) if c.strip()],
        max_attempts=int(body.get("max_attempts", 3)),
        probe_mode="agent" if body.get("probe_mode") == "agent" else "local",
        agent_target=(body.get("agent_target") or "").strip(),
        agent_interval_sec=int(body.get("agent_interval_sec") or 60),
        agent_fail_threshold=int(body.get("agent_fail_threshold") or 3),
    )
    return {"ok": True, "id": rule_id}


@app.delete("/api/ip-rules/{rule_id}")
def api_delete_rule(rule_id: int, _: None = Guard):
    store.delete_ip_rule(rule_id)
    return {"ok": True}


@app.post("/api/ip-rules/run-now")
def api_run_rules_now(_: None = Guard):
    results = run_once(store)
    return {"ok": True, "results": results}


def _report_url() -> str:
    """实例要往哪个地址上报。

    优先用显式配置的 AWS_HELPER_REPORT_URL —— 自动探测出来的是面板的出站 IP，
    在 NAT 或多网卡环境下未必是实例能连到的那个地址。
    """
    if REPORT_PUBLIC_URL:
        return REPORT_PUBLIC_URL.rstrip("/") + "/report"
    ip = ddns.detect_ip(4)
    if not ip:
        raise RuntimeError(
            "探测不到面板的公网 IPv4，无法拼出上报地址。"
            "请设置环境变量 AWS_HELPER_REPORT_URL，例如 http://面板地址:8766"
        )
    return f"http://{ip}:{REPORT_PORT}/report"


@app.post("/api/ip-rules/{rule_id}/guard-script")
def api_guard_script(rule_id: int, _: None = Guard):
    """生成装在实例上的探测脚本，顺带发一个新的上报凭证。

    每次生成都换凭证：脚本里带着明文凭证，重新生成通常意味着上一份可能
    已经泄露或作废了。旧脚本会立刻失效，这是有意的。
    """
    rule = store.ip_rule(rule_id)
    if rule is None:
        return JSONResponse({"ok": False, "error": "规则不存在"}, status_code=404)

    try:
        url = _report_url()
    except RuntimeError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    token = store.issue_agent_token(rule_id)
    try:
        script = guard_script.render_script(
            guard_script.GuardRequest(
                instance_id=rule["instance_id"],
                report_url=url,
                token=token,
                target=rule["agent_target"] or guard_script.DEFAULT_TARGET,
                interval_sec=int(rule["agent_interval_sec"]),
                fail_threshold=int(rule["agent_fail_threshold"]),
            )
        )
    except guard_script.GuardScriptError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    host, port = guard_script.parse_target(
        rule["agent_target"] or guard_script.DEFAULT_TARGET
    )
    store.log("autoip", rule["instance_id"], True, "生成实例探测脚本，已换发上报凭证")
    return {
        "ok": True,
        "script": script,
        "report_url": url,
        "target": f"{host}:{port}",
        "service_name": guard_script.SERVICE_NAME,
    }


@app.get("/api/ip-rules/{rule_id}/agent-status")
def api_agent_status(rule_id: int, _: None = Guard):
    """查实例探测器的部署状态，并给出可操作的排查方向。

    探测正常时脚本不上报（这是设计要求），所以「有没有部署好」只能靠心跳
    判断。心跳间隔是探测间隔的 10 倍，宽限到 3 倍心跳周期才算失联 ——
    实例重启、网络抖动都会漏掉一两次。
    """
    rule = store.ip_rule(rule_id)
    if rule is None:
        return JSONResponse({"ok": False, "error": "规则不存在"}, status_code=404)

    now = int(time.time())
    last_seen = int(rule["agent_last_seen"])
    interval = int(rule["agent_interval_sec"]) or 60
    heartbeat = interval * 10
    grace = heartbeat * 3

    hints: list[str] = []
    if rule["probe_mode"] != "agent":
        state = "disabled"
        summary = "这条规则用面板自己探测，没有实例侧探测器"
    elif not rule["agent_deployed"]:
        state = "not_deployed"
        summary = "还没生成过部署脚本"
        hints.append("点「生成部署脚本」拿到脚本，复制到实例上以 root 执行")
    elif last_seen == 0:
        state = "not_deployed"
        summary = "已生成脚本，但面板从未收到这台实例的上报"
        hints.append(f"确认脚本已在实例上执行：systemctl status {guard_script.SERVICE_NAME}")
        hints.append(f"确认实例能连到面板的上报端口 {REPORT_PORT}（安全组、防火墙）")
        hints.append("在实例上手动跑一次看输出：" + guard_script.INSTALL_PATH)
    elif now - last_seen > grace:
        state = "stale"
        summary = f"最后一次上报在 {now - last_seen} 秒前，超过 {grace} 秒宽限，可能已失联"
        hints.append(f"看实例上的日志：journalctl -u {guard_script.SERVICE_NAME} -n 50")
        hints.append("实例可能已关机、脚本被卸载，或出网到面板的链路断了")
    else:
        state = "ok"
        summary = f"正常，最后一次上报在 {now - last_seen} 秒前"

    return {
        "ok": True,
        "state": state,
        "summary": summary,
        "hints": hints,
        "probe_mode": rule["probe_mode"],
        "deployed": bool(rule["agent_deployed"]),
        "instance_id": rule["instance_id"],
        "target": rule["agent_target"] or guard_script.DEFAULT_TARGET,
        "interval_sec": interval,
        "fail_threshold": int(rule["agent_fail_threshold"]),
        "last_seen": last_seen,
        "last_seen_ago": (now - last_seen) if last_seen else None,
        "last_report": int(rule["agent_last_report"]),
        "last_report_ago": (
            now - int(rule["agent_last_report"]) if int(rule["agent_last_report"]) else None
        ),
        "last_detail": rule["agent_last_detail"],
        "report_port": REPORT_PORT,
        "report_port_running": report_server.running,
    }


@app.post("/api/probe")
async def api_probe(request: Request, _: None = Guard):
    body = await request.json()
    result = probe(body.get("ip", ""), body.get("mode", "tcp"), int(body.get("port", 22)))
    return {"ok": result.ok, "detail": result.detail}


@app.post("/api/monitor/{action}")
def api_monitor(action: str, _: None = Guard):
    if action == "start":
        monitor.start()
    elif action == "stop":
        monitor.stop()
    else:
        raise HTTPException(400, "action 只能是 start / stop")
    return {"ok": True, "running": monitor.running}


# ---------------- 任务与日志 ----------------


@app.get("/api/tasks/{task_id}")
def api_task(task_id: str, _: None = Guard):
    snap = manager.get(task_id)
    if snap is None:
        raise HTTPException(404, "任务不存在")
    return {"ok": True, "task": snap}


@app.get("/api/tasks")
def api_tasks(_: None = Guard):
    return {"ok": True, "tasks": manager.recent()}


@app.get("/api/logs")
def api_logs(limit: int = 100, _: None = Guard):
    return {"ok": True, "logs": store.list_logs(limit)}


@app.get("/api/keypairs/{account_id}/{region}/{key_name}")
def api_keypair(account_id: int, region: str, key_name: str, _: None = Guard):
    """下载私钥文件。

    必须回纯文本而不是 JSON —— JSON 会把换行转成字面量 \\n，浏览器里看到的和
    复制出来的都是一行带 \\n 的字符串，ssh 直接拒绝（invalid format）。
    带 Content-Disposition 让浏览器存成 .pem 文件而不是在页面里渲染。
    """
    key = store.get_private_key(account_id, region, key_name)
    if key is None:
        raise HTTPException(404, "没有保存该密钥的私钥")

    # OpenSSH 要求文件以换行结尾，缺了会报 invalid format
    if not key.endswith("\n"):
        key += "\n"

    filename = f"{key_name}.pem".replace('"', "")
    return PlainTextResponse(
        key,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": __version__, "monitor": monitor.running}
