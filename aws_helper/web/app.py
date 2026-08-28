"""FastAPI Web 面板。

安全说明：默认绑定 127.0.0.1，登录密码经 PBKDF2 哈希存库，会话令牌只存摘要。
首次启动会生成随机初始密码并打印到控制台，登录后可在用户面板自行修改；
忘记密码用 `python3 -m aws_helper.cli reset-password` 重置。
若要对外暴露，务必放到 HTTPS 反代之后 —— 这个面板持有你的 AWS 凭据。
"""

from __future__ import annotations

import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__, auth
from ..autoip import Monitor, probe, run_once
from ..core import aws, bedrock, ipchange, launch, lightsail
from ..core.userdata import ScriptOptions, ScriptError, render
from ..store import Store
from ..tasks import manager

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

store = Store()
monitor = Monitor(store)

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
    yield
    monitor.stop()


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
    try:
        types = aws.list_instance_types(creds, region, arch)
    except Exception as exc:
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
        },
    )


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
        {**_page_ctx("bd-models"), "bedrock_regions": bedrock.REGIONS},
    )


@app.get("/bedrock/playground", response_class=HTMLResponse)
def bedrock_play_page(request: Request, _: None = Guard):
    return templates.TemplateResponse(
        request,
        "bedrock_play.html",
        {**_page_ctx("bd-play"), "bedrock_regions": bedrock.REGIONS},
    )


# ---------------- Lightsail API ----------------


@app.get("/api/lightsail/catalog")
def api_ls_catalog(account_id: int, region: str, _: None = Guard):
    """Lightsail 的套餐与蓝图。区域支持范围比 EC2 窄，要单独校验。"""
    creds = store.credentials(account_id, region)
    try:
        regions = lightsail.available_regions(creds, region)
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

    try:
        bundles = lightsail.list_bundles(creds, region)
        blueprints = lightsail.list_blueprints(creds, region)
    except lightsail.LightsailError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    return {
        "ok": True,
        "region": region,
        "supported_regions": regions,
        "bundles": bundles,
        "blueprints": blueprints,
    }


@app.get("/api/lightsail/instances")
def api_ls_instances(account_id: int, region: str, _: None = Guard):
    creds = store.credentials(account_id, region)
    try:
        return {
            "ok": True,
            "instances": lightsail.list_instances(creds, region),
            "static_ips": lightsail.list_static_ips(creds, region),
        }
    except lightsail.LightsailError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.post("/api/lightsail/create")
async def api_ls_create(request: Request, _: None = Guard):
    body = await request.json()
    account_id = int(body["account_id"])
    region = body["region"]
    creds = store.credentials(account_id, region)

    def job(progress: Any) -> dict[str, Any]:
        result = lightsail.create_instance(
            creds,
            region,
            name=str(body.get("name", "")).strip(),
            bundle_id=body.get("bundle_id", ""),
            blueprint_id=body.get("blueprint_id", ""),
            user_data=body.get("user_data", ""),
            progress=progress,
        )
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
    creds = store.credentials(int(body["account_id"]), body["region"])
    names = body.get("names") or []
    action = body["action"]
    try:
        result = lightsail.power(creds, body["region"], action, names)
    except lightsail.LightsailError as exc:
        store.log("lightsail", ",".join(names), False, f"{action} 失败: {exc}")
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    detail = f"{action} 完成"
    if result.get("released_static_ips"):
        detail += f"，释放静态 IP {len(result['released_static_ips'])} 个"
    store.log("lightsail", ",".join(names), not result["failed"], detail)
    return {"ok": True, **result}


# ---------------- Bedrock API ----------------


@app.get("/api/bedrock/models")
def api_bd_models(account_id: int, region: str, _: None = Guard):
    creds = store.credentials(account_id, region)
    try:
        return {"ok": True, **bedrock.list_models(creds, region)}
    except bedrock.BedrockError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


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
    store.log("account", str(account_id), True, "删除账号")
    return {"ok": True}


# ---------------- 实例 API ----------------


@app.get("/api/instances")
def api_instances(account_id: int, region: str, _: None = Guard):
    creds = store.credentials(account_id, region)
    try:
        items = launch.list_instances(creds, region)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    return {"ok": True, "instances": items}


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
            return result

        task_id = manager.submit("terminate", f"终止并清理 {len(ids)} 台实例", job)
        return {"ok": True, "task_id": task_id, "action": action}

    try:
        result = launch.power(creds, region, action, ids)
    except Exception as exc:
        store.log("power", ",".join(ids), False, f"{action} 失败: {exc}")
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
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

    # 提前校验脚本，避免开机跑到一半才报错
    try:
        render(
            ScriptOptions(
                custom_script=req.script,
                root_password=req.root_password,
                hostname=req.name,
                packages=req.packages,
            )
        )
    except ScriptError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    def job(progress: Any) -> dict[str, Any]:
        results = launch.launch(creds, req, progress)
        for res in results:
            if res.private_key:
                store.save_keypair(account_id, region, res.key_name, res.private_key)
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
            ]
        }

    task_id = manager.submit("launch", f"开机 {req.name} x{req.count}", job)
    return {"ok": True, "task_id": task_id}


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
        result = ipchange.change_ip(creds, region, instance_id, strategy, rule, progress)
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
    key = store.get_private_key(account_id, region, key_name)
    if key is None:
        raise HTTPException(404, "没有保存该密钥的私钥")
    return {"ok": True, "key_name": key_name, "private_key": key}


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": __version__, "monitor": monitor.running}
