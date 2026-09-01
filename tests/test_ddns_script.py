"""DDNS 一键脚本生成器。

最关键的性质：**生成的 bash 必须真的能跑**。所以这里不只比对字符串，
还会用 `bash -n` 检查外层脚本和内嵌的更新脚本两层语法，
并对着一个真实 HTTP 假 Cloudflare 实际执行一遍。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aws_helper.core import ddns_script
from aws_helper.core.ddns_script import ScriptError, ScriptRequest, render_script

TOKEN = "t" * 40
ZONE = "example.com"
HOST = "home.example.com"


def _req(**over) -> ScriptRequest:
    base = dict(zone=ZONE, hostname=HOST, token=TOKEN)
    base.update(over)
    return ScriptRequest(**base)


def _inner_updater(script: str) -> str:
    """把内嵌的更新脚本从 heredoc 里抽出来。"""
    match = re.search(r"<<'DDNS_UPDATER_EOF'\n(.*?)DDNS_UPDATER_EOF", script, re.S)
    assert match, "外层脚本里找不到内嵌的更新脚本"
    return match.group(1)


def _bash_ok(text: str, tmp_path, name: str) -> None:
    path = tmp_path / name
    path.write_text(text)
    proc = subprocess.run(
        ["bash", "-n", str(path)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, f"{name} 语法错误：{proc.stderr}"


# ---------- 参数校验 ----------


def test_rejects_hostname_outside_zone():
    with pytest.raises(ScriptError, match="不属于区域"):
        render_script(_req(hostname="home.other.com"))


def test_allows_apex_domain():
    """根域名本身也该能做 DDNS（hostname == zone）。"""
    script = render_script(_req(hostname=ZONE))
    assert f"DDNS_HOSTNAME={ZONE}" in script


def test_rejects_empty_fields():
    with pytest.raises(ScriptError, match="区域根域名"):
        render_script(_req(zone=""))
    with pytest.raises(ScriptError, match="主机名"):
        render_script(_req(hostname=""))
    with pytest.raises(ScriptError, match="API Token"):
        render_script(_req(token=""))


def test_rejects_bad_hostname_format():
    for bad in ("has space.com", "no-dot", "-lead.example.com", "under_score.example.com"):
        with pytest.raises(ScriptError):
            render_script(_req(hostname=bad, zone="example.com"))


def test_rejects_token_with_shell_metacharacters():
    """Token 里带 shell 元字符必须拒掉。

    Token 会被写进脚本，虽然用 shlex.quote 转义了，但这类值本身就是
    误粘贴（多复制了引号或换行），早点报错比生成一个诡异脚本好。
    """
    for bad in ("tok'; rm -rf /", "tok\nsecond", 'tok"quote', "tok$(whoami)", "tok`id`"):
        with pytest.raises(ScriptError, match="非法字符|长度异常"):
            render_script(_req(token=bad))


def test_rejects_both_families_off():
    with pytest.raises(ScriptError, match="至少要开启"):
        render_script(_req(want_ipv4=False, want_ipv6=False))


def test_rejects_unknown_provider():
    with pytest.raises(ScriptError, match="暂不支持"):
        render_script(_req(provider="route53"))


def test_rejects_unknown_schedule():
    with pytest.raises(ScriptError, match="未知的运行方式"):
        render_script(_req(schedule="upstart"))


def test_normalizes_case_and_trailing_dot():
    script = render_script(_req(zone="Example.COM.", hostname="Home.Example.COM."))
    assert f"DDNS_ZONE={ZONE}" in script
    assert f"DDNS_HOSTNAME={HOST}" in script


def test_interval_clamped():
    """间隔太小会把 Cloudflare 的限流额度烧光，太大就失去 DDNS 的意义。"""
    assert "OnUnitActiveSec=60s" in render_script(_req(interval_sec=1))
    assert "OnUnitActiveSec=86400s" in render_script(_req(interval_sec=999999))


def test_proxied_forces_auto_ttl():
    """开了代理的记录 TTL 不可改，传数字会被 Cloudflare 拒。"""
    script = render_script(_req(proxied=True, ttl=300))
    assert "DDNS_TTL=1" in script
    assert "DDNS_PROXIED=true" in script


# ---------- 生成结果 ----------


def test_generated_script_is_valid_bash(tmp_path):
    """外层部署脚本必须是合法 bash。"""
    _bash_ok(render_script(_req(want_ipv6=True)), tmp_path, "deploy.sh")


def test_embedded_updater_is_valid_bash(tmp_path):
    """内嵌的更新脚本也必须是合法 bash —— 它是真正反复执行的那个。"""
    script = render_script(_req(want_ipv6=True))
    _bash_ok(_inner_updater(script), tmp_path, "updater.sh")


@pytest.mark.parametrize("schedule", ["systemd", "cron"])
@pytest.mark.parametrize("v6", [False, True])
@pytest.mark.parametrize("proxied", [False, True])
def test_all_combinations_produce_valid_bash(tmp_path, schedule, v6, proxied):
    script = render_script(_req(schedule=schedule, want_ipv6=v6, proxied=proxied))
    name = f"{schedule}-{v6}-{proxied}"
    _bash_ok(script, tmp_path, f"deploy-{name}.sh")
    _bash_ok(_inner_updater(script), tmp_path, f"updater-{name}.sh")


def test_token_is_shell_quoted():
    """Token 写进配置文件时必须转义，否则特殊字符会破坏脚本。"""
    script = render_script(_req(token="a" * 40))
    assert f"CF_TOKEN={'a' * 40}" in script or f"CF_TOKEN='{'a' * 40}'" in script


def test_config_permissions_set_before_write():
    """先 chmod 600 再写内容，避免 Token 有一瞬间全局可读。"""
    script = render_script(_req())
    touch_at = script.index(f"touch {ddns_script.ENV_PATH}")
    chmod_at = script.index(f"chmod 600 {ddns_script.ENV_PATH}")
    write_at = script.index(f"cat > {ddns_script.ENV_PATH}")
    assert touch_at < chmod_at < write_at, "必须先建文件、收权限，再写入 Token"


def test_script_requires_root():
    assert 'id -u' in render_script(_req())


def test_script_uses_patch_not_put():
    """生成的脚本必须用 PATCH。

    PUT 是整条替换，漏传 proxied/ttl 会重置成默认值 —— 用户在控制台开的
    橙云会被静默关掉。这是 DDNS 实现最常见的坑。
    """
    updater = _inner_updater(render_script(_req()))
    assert "cf_call PATCH" in updater
    assert "cf_call PUT" not in updater


def test_script_skips_write_when_ip_unchanged():
    updater = _inner_updater(render_script(_req()))
    assert '[ "$cur" = "$ip" ]' in updater


def test_script_uses_separate_v6_sources():
    """v4/v6 探测点必须分开 —— api.ipify.org 只有 A 记录。"""
    updater = _inner_updater(render_script(_req(want_ipv6=True)))
    assert "api6.ipify.org" in updater
    assert "ipv6.icanhazip.com" in updater


def test_script_logs_to_stderr():
    """日志必须写 stderr。

    zone_id 之类的函数在 $(...) 里调用，日志写 stdout 会被命令替换吞掉，
    用户看不到任何错误信息。
    """
    updater = _inner_updater(render_script(_req()))
    assert re.search(r"log\(\)\s*\{[^}]*>&2", updater), "log() 必须重定向到 stderr"


def test_script_resolves_zone_once():
    """区域只解析一次，否则 Token 配错时 A 和 AAAA 会各报一遍同样的错。"""
    updater = _inner_updater(render_script(_req(want_ipv6=True)))
    assert updater.count("ZID=$(zone_id)") == 1


def test_missing_ipv6_does_not_fail_unit():
    """没有 v6 连通性不能让脚本以非 0 退出。

    systemd 会把非 0 当服务失败，日志里堆满红色 failed，而这只是
    机器没有 v6 —— 常态而非故障。
    """
    updater = _inner_updater(render_script(_req(want_ipv6=True)))
    v6_block = updater[updater.index('DDNS_WANT_IPV6'):]
    skip_line = [l for l in v6_block.splitlines() if "跳过 AAAA" in l]
    assert skip_line, "找不到跳过 AAAA 的分支"
    following = v6_block[v6_block.index(skip_line[0]):]
    assert "rc=1" not in following.split("fi")[0], "跳过 AAAA 不该设置失败退出码"


def test_cron_variant_dedupes_existing_line():
    """重复执行部署脚本不该让 cron 条目越堆越多。"""
    script = render_script(_req(schedule="cron"))
    assert "grep -vF" in script and "crontab -" in script


def test_systemd_variant_uses_timer_not_loop():
    """用 timer 而不是常驻循环 —— oneshot + timer 崩了会自己重来。"""
    script = render_script(_req(schedule="systemd"))
    assert "Type=oneshot" in script
    assert "OnUnitActiveSec=" in script
    assert f"{ddns_script.SERVICE_NAME}.timer" in script


def test_script_verifies_before_scheduling():
    """先跑一次校验再挂定时任务，不然会留下一个跑不通的定时任务。"""
    script = render_script(_req())
    verify_at = script.index("校验 Token 与区域")
    schedule_at = script.index("systemd 单元与定时器")
    assert verify_at < schedule_at


def test_script_mentions_token_sensitivity():
    script = render_script(_req())
    assert "Token" in script and "删除本文件" in script


def test_script_installs_curl_if_missing():
    """目标机器可能是精简系统，curl 都没有。"""
    script = render_script(_req())
    for mgr in ("apt-get", "dnf", "yum", "apk"):
        assert mgr in script, f"缺少 {mgr} 的安装分支"


def test_updater_falls_back_without_jq():
    """不能强制目标机器装 jq。"""
    updater = _inner_updater(render_script(_req()))
    assert "command -v jq" in updater
    assert "grep -o" in updater


# ---------- 真实执行 ----------


class _FakeCF(BaseHTTPRequestHandler):
    state: dict = {}

    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _auth(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        self.state["calls"].append(("GET", self.path))
        if not self._auth():
            return self._send(
                {"success": False, "errors": [{"code": 1000, "message": "Invalid API Token"}]},
                401,
            )
        if parsed.path.endswith("/zones"):
            if (query.get("name") or [""])[0] != ZONE:
                return self._send({"success": True, "errors": [], "result": []})
            return self._send(
                {"success": True, "errors": [], "result": [{"id": "zid-1", "name": ZONE}]}
            )
        if "/dns_records" in parsed.path:
            key = f"{(query.get('type') or [''])[0]}:{(query.get('name.exact') or [''])[0]}"
            rec = self.state["records"].get(key)
            if not rec:
                return self._send({"success": True, "errors": [], "result": []})
            return self._send({"success": True, "errors": [], "result": [rec]})
        return self._send({"success": False, "errors": [{"code": 7003}]}, 404)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_POST(self):
        body = self._body()
        self.state["calls"].append(("POST", self.path))
        self.state["bodies"].append(("POST", body))
        if not self._auth():
            return self._send({"success": False, "errors": [{"code": 1000}]}, 401)
        key = f"{body.get('type')}:{body.get('name')}"
        rec = {
            "id": f"rec-{len(self.state['records'])}",
            "name": body.get("name"),
            "type": body.get("type"),
            "content": body.get("content"),
            "ttl": body.get("ttl", 1),
            "proxied": bool(body.get("proxied")),
        }
        self.state["records"][key] = rec
        return self._send({"success": True, "errors": [], "result": rec})

    def do_PATCH(self):
        body = self._body()
        self.state["calls"].append(("PATCH", self.path))
        self.state["bodies"].append(("PATCH", body))
        if not self._auth():
            return self._send({"success": False, "errors": [{"code": 1000}]}, 401)
        rid = self.path.rstrip("/").split("/")[-1]
        for key, rec in self.state["records"].items():
            if rec["id"] == rid:
                rec["content"] = body.get("content", rec["content"])
                return self._send({"success": True, "errors": [], "result": rec})
        return self._send({"success": False, "errors": [{"code": 81044}]}, 404)

    def do_PUT(self):
        self.state["calls"].append(("PUT", self.path))
        self.state["bodies"].append(("PUT", self._body()))
        return self._send({"success": True, "errors": [], "result": {}})


@pytest.fixture
def live_cf():
    state = {"records": {}, "calls": [], "bodies": []}
    _FakeCF.state = state
    server = HTTPServer(("127.0.0.1", 0), _FakeCF)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield state, f"http://127.0.0.1:{port}/client/v4"
    finally:
        server.shutdown()
        server.server_close()


def _run_updater(tmp_path, api_base: str, *, v6: bool = False, token: str = TOKEN):
    """把生成的更新脚本对着假 Cloudflare 实跑一次。"""
    script = render_script(_req(want_ipv6=v6, token=token))
    updater = tmp_path / "updater.sh"
    updater.write_text(_inner_updater(script))

    env_file = tmp_path / "env"
    env_file.write_text(
        f"CF_TOKEN={token}\n"
        f"CF_API={api_base}\n"
        f"DDNS_ZONE={ZONE}\n"
        f"DDNS_HOSTNAME={HOST}\n"
        f"DDNS_WANT_IPV4=true\n"
        f"DDNS_WANT_IPV6={'true' if v6 else 'false'}\n"
        f"DDNS_PROXIED=false\n"
        f"DDNS_TTL=1\n"
        f"DDNS_STATE_DIR={tmp_path / 'state'}\n"
    )
    return subprocess.run(
        ["bash", str(updater)],
        capture_output=True,
        text=True,
        timeout=120,
        env={"DDNS_ENV_FILE": str(env_file), "PATH": "/usr/bin:/bin:/usr/local/bin"},
    )


@pytest.mark.skipif(shutil.which("curl") is None, reason="需要 curl")
def test_live_run_creates_record(tmp_path, live_cf):
    """真跑一次：记录不存在时应新建。"""
    state, api_base = live_cf
    proc = _run_updater(tmp_path, api_base)

    assert proc.returncode == 0, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "已新建" in proc.stderr
    assert [m for m, _ in state["bodies"]] == ["POST"]
    assert state["records"][f"A:{HOST}"]["content"]


@pytest.mark.skipif(shutil.which("curl") is None, reason="需要 curl")
def test_live_run_skips_when_unchanged(tmp_path, live_cf):
    """第二次跑不该产生任何写请求。"""
    state, api_base = live_cf
    _run_updater(tmp_path, api_base)
    writes_before = len(state["bodies"])

    proc = _run_updater(tmp_path, api_base)
    assert proc.returncode == 0
    assert "未变化" in proc.stderr
    assert len(state["bodies"]) == writes_before, "IP 未变化不该再写"


@pytest.mark.skipif(shutil.which("curl") is None, reason="需要 curl")
def test_live_run_patches_when_ip_changed(tmp_path, live_cf):
    """DNS 上的 IP 与本机不一致时走 PATCH，且不碰 proxied/ttl。"""
    state, api_base = live_cf
    _run_updater(tmp_path, api_base)
    record = state["records"][f"A:{HOST}"]
    record["content"] = "9.9.9.9"
    record["proxied"] = True
    record["ttl"] = 120

    proc = _run_updater(tmp_path, api_base)
    assert proc.returncode == 0
    assert "9.9.9.9 ->" in proc.stderr

    patches = [b for m, b in state["bodies"] if m == "PATCH"]
    assert patches, "应该发出 PATCH"
    assert set(patches[-1]) == {"content"}, f"PATCH 只该带 content，实际 {patches[-1]}"
    assert state["records"][f"A:{HOST}"]["proxied"] is True
    assert state["records"][f"A:{HOST}"]["ttl"] == 120


@pytest.mark.skipif(shutil.which("curl") is None, reason="需要 curl")
def test_live_run_reports_bad_token_on_stderr(tmp_path, live_cf):
    """Token 错误必须能看到原因，而不是静默失败。"""
    _, api_base = live_cf
    proc = _run_updater(tmp_path, api_base, token="w" * 40)

    assert proc.returncode != 0
    assert "Invalid API Token" in proc.stderr, f"看不到错误原因：{proc.stderr}"


@pytest.mark.skipif(shutil.which("curl") is None, reason="需要 curl")
def test_live_run_missing_config_fails_clearly(tmp_path):
    script = render_script(_req())
    updater = tmp_path / "u.sh"
    updater.write_text(_inner_updater(script))
    proc = subprocess.run(
        ["bash", str(updater)],
        capture_output=True,
        text=True,
        timeout=60,
        env={"DDNS_ENV_FILE": str(tmp_path / "nope.env"), "PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode != 0
    assert "读不到配置" in proc.stderr


# ---------- Account ID ----------


def test_script_omits_account_filter_when_absent(tmp_path):
    """不填 Account ID 时脚本不该带这个过滤 —— DNS 增删改本来不需要它。"""
    script = render_script(_req())
    assert "CF_ACCOUNT_ID=\n" in script
    updater = _inner_updater(script)
    # 变量为空时不拼进 query
    assert '[ -n "${CF_ACCOUNT_ID:-}" ]' in updater


def test_script_includes_account_filter_when_given(tmp_path):
    """过滤参数名是 account.id（点号），写成 account_id 不生效。"""
    acct = "a" * 32
    script = render_script(_req(account_id=acct))
    assert f"CF_ACCOUNT_ID={acct}" in script
    assert "account.id=${CF_ACCOUNT_ID}" in _inner_updater(script)
    _bash_ok(script, tmp_path, "acct.sh")
    _bash_ok(_inner_updater(script), tmp_path, "acct-inner.sh")


def test_script_rejects_malformed_account_id():
    """Account ID 是 32 位十六进制，别的一定是粘错了。"""
    for bad in ("not-hex", "a" * 31, "a" * 33, "A" * 32, "zzzz" * 8):
        with pytest.raises(ScriptError, match="32 位十六进制"):
            render_script(_req(account_id=bad))


def test_script_uses_ip_sb_first():
    """探测点用 ip.sb 打头，与面板托管那条路径保持一致。

    断言的是它在每个 set -- 列表里排第一，而不是出现次数 ——
    注释里也会提到这个域名。
    """
    updater = _inner_updater(render_script(_req(want_ipv6=True)))
    lists = [l.strip() for l in updater.splitlines() if l.strip().startswith("set -- ")]
    assert len(lists) == 2, f"应有 v4/v6 两个探测点列表，实际 {len(lists)}"
    for line in lists:
        assert line.startswith('set -- "https://ip.sb"'), f"ip.sb 不在首位: {line}"


@pytest.mark.skipif(shutil.which("curl") is None, reason="需要 curl")
def test_live_run_sends_account_filter(tmp_path, live_cf):
    """真跑一次，确认 account.id 真的进了请求 URL。"""
    state, api_base = live_cf
    acct = "b" * 32
    script = render_script(_req(account_id=acct))
    updater = tmp_path / "u.sh"
    updater.write_text(_inner_updater(script))

    env_file = tmp_path / "env"
    env_file.write_text(
        f"CF_TOKEN={TOKEN}\nCF_ACCOUNT_ID={acct}\nCF_API={api_base}\n"
        f"DDNS_ZONE={ZONE}\nDDNS_HOSTNAME={HOST}\n"
        f"DDNS_WANT_IPV4=true\nDDNS_WANT_IPV6=false\n"
        f"DDNS_PROXIED=false\nDDNS_TTL=1\nDDNS_STATE_DIR={tmp_path / 'state'}\n"
    )
    subprocess.run(
        ["bash", str(updater)],
        capture_output=True,
        text=True,
        timeout=120,
        env={"DDNS_ENV_FILE": str(env_file), "PATH": "/usr/bin:/bin:/usr/local/bin"},
    )

    zone_calls = [p for m, p in state["calls"] if m == "GET" and "zones" in p]
    assert zone_calls, "没有查 zone"
