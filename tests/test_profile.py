"""用户面板端到端：改密码、会话管理、登录锁定、CLI 重置。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aws_helper import auth, cli
from aws_helper.store import Store

from .test_web import TEST_PASSWORD, build_app, login

NEW_PASSWORD = "Br4nd!NewPass"


@pytest.fixture
def panel(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "panel")
    client = TestClient(app_module.app)
    login(client)
    return client, app_module


# ---------- 页面 ----------


def test_profile_page_renders(panel):
    c, _ = panel
    html = c.get("/profile").text
    assert "修改登录密码" in html
    assert "登录会话" in html
    assert "登录记录" in html
    assert "reset-password" in html


def test_nav_has_profile_link(panel):
    c, _ = panel
    assert 'href="/profile"' in c.get("/").text


def test_login_page_links_to_docs_not_cli(mock_ec2, monkeypatch, tmp_path):
    """登录页不能泄露运维细节。

    未登录的人看到 CLI 命令和数据路径没有意义，还等于告诉攻击者
    重置入口在哪。这里只放一个指向 GitHub 文档的「忘记密码？」链接。
    """
    app_module = build_app(monkeypatch, tmp_path / "loginpage")
    html = TestClient(app_module.app).get("/login").text

    assert "忘记密码？" in html
    assert "github.com" in html
    assert "reset-password" not in html
    assert "aws_helper.cli" not in html
    assert "启动日志" not in html


def test_login_error_page_keeps_docs_link(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "loginerr")
    c = TestClient(app_module.app)
    html = login(c, "wrong-password").text
    assert "忘记密码？" in html
    assert "github.com" in html


def test_docs_url_overridable(mock_ec2, monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_HELPER_DOCS_URL", "https://example.com/mydocs")
    app_module = build_app(monkeypatch, tmp_path / "docsurl")
    html = TestClient(app_module.app).get("/login").text
    assert "https://example.com/mydocs" in html


def test_profile_requires_login(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "anon")
    c = TestClient(app_module.app)
    resp = c.get("/profile", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["location"]


# ---------- 改密码 ----------


def _change(client, current, new, confirm=None):
    return client.post(
        "/api/profile/password",
        data={
            "current_password": current,
            "new_password": new,
            "confirm_password": confirm if confirm is not None else new,
        },
    )


def test_change_password_success(panel):
    c, app_module = panel
    resp = _change(c, TEST_PASSWORD, NEW_PASSWORD)
    assert resp.status_code == 200, resp.json()
    assert app_module.store.verify_login(NEW_PASSWORD)
    assert not app_module.store.verify_login(TEST_PASSWORD)


def test_change_password_keeps_current_session_alive(panel):
    """改密码的人不该把自己踢下线。"""
    c, _ = panel
    assert _change(c, TEST_PASSWORD, NEW_PASSWORD).status_code == 200
    assert c.get("/api/profile/sessions").status_code == 200


def test_change_password_kills_other_sessions(panel, monkeypatch, tmp_path):
    """另一台设备的登录必须立即失效。"""
    c, app_module = panel
    other = TestClient(app_module.app)
    login(other)
    assert other.get("/api/tasks").status_code == 200

    assert _change(c, TEST_PASSWORD, NEW_PASSWORD).status_code == 200
    assert other.get("/api/tasks").status_code == 401


def test_change_password_wrong_current(panel):
    c, app_module = panel
    resp = _change(c, "not-the-password", NEW_PASSWORD)
    assert resp.status_code == 400
    assert "当前密码不正确" in resp.json()["error"]
    assert app_module.store.verify_login(TEST_PASSWORD)


def test_change_password_mismatch(panel):
    c, app_module = panel
    resp = _change(c, TEST_PASSWORD, NEW_PASSWORD, "Different!Pass9")
    assert resp.status_code == 400
    assert "不一致" in resp.json()["error"]
    assert app_module.store.verify_login(TEST_PASSWORD)


def test_change_password_same_as_current(panel):
    c, _ = panel
    resp = _change(c, TEST_PASSWORD, TEST_PASSWORD)
    assert resp.status_code == 400
    assert "不能与当前密码相同" in resp.json()["error"]


@pytest.mark.parametrize("weak", ["short1!", "alllowercase123", "Password123"])
def test_change_password_rejects_weak(panel, weak):
    c, app_module = panel
    resp = _change(c, TEST_PASSWORD, weak)
    assert resp.status_code == 400
    assert app_module.store.verify_login(TEST_PASSWORD)


def test_change_password_requires_login(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "anon2")
    c = TestClient(app_module.app)
    assert _change(c, TEST_PASSWORD, NEW_PASSWORD).status_code == 401


def test_new_password_works_for_relogin(panel, mock_ec2):
    c, app_module = panel
    _change(c, TEST_PASSWORD, NEW_PASSWORD)

    fresh = TestClient(app_module.app)
    assert login(fresh, TEST_PASSWORD).status_code == 401
    assert login(fresh, NEW_PASSWORD).status_code == 302
    assert fresh.get("/api/tasks").status_code == 200


def test_change_logged(panel):
    c, app_module = panel
    _change(c, TEST_PASSWORD, NEW_PASSWORD)
    logs = app_module.store.list_logs()
    assert any(l["kind"] == "auth" and "修改登录密码" in l["detail"] for l in logs)


def test_wrong_current_password_recorded_in_history(panel):
    c, app_module = panel
    _change(c, "wrong", NEW_PASSWORD)
    history = app_module.store.list_login_history()
    assert any(h["ok"] == 0 and "旧密码错误" in h["detail"] for h in history)


# ---------- 会话 ----------


def test_session_list_marks_current(panel):
    c, app_module = panel
    other = TestClient(app_module.app)
    login(other)

    sessions = c.get("/api/profile/sessions").json()["sessions"]
    assert len(sessions) == 2
    assert sum(1 for s in sessions if s["current"]) == 1


def test_session_records_ip_and_agent(panel):
    c, _ = panel
    sessions = c.get("/api/profile/sessions").json()["sessions"]
    assert sessions[0]["ip"]
    assert sessions[0]["user_agent"]


def test_truncated_user_agent_has_full_value_in_title(panel):
    """被 ellipsis 截断的客户端列必须能悬停看到全文。

    单元格设了 max-width + text-overflow:ellipsis，User-Agent 普遍比它长
    （实测 870px 内容塞进 325px 格子）。没有 title 属性时全文就彻底不可读，
    审计"谁登录过"这件事直接失效。

    「登录会话」和「登录记录」两张表各自断言 —— 两处渲染同一个 User-Agent，
    整页搜索会让其中一处漏掉 title 也照样通过。
    """
    c, _ = panel
    long_agent = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "HeadlessChrome/141.0.0.0 Safari/537.36"
    )
    other = TestClient(c.app, headers={"user-agent": long_agent})
    login(other)

    html = c.get("/profile").text
    sessions_html, _, history_html = html.partition("<h2>登录记录</h2>")
    assert long_agent in sessions_html and long_agent in history_html, "两张表都应出现该 User-Agent"

    for name, part in (("登录会话", sessions_html), ("登录记录", history_html)):
        assert f'title="{long_agent}"' in part, f"「{name}」表的 User-Agent 单元格缺少 title，全文无法查看"


def test_revoke_other_session(panel):
    c, app_module = panel
    other = TestClient(app_module.app)
    login(other)
    assert other.get("/api/tasks").status_code == 200

    target = [
        s for s in c.get("/api/profile/sessions").json()["sessions"] if not s["current"]
    ][0]
    assert c.request("DELETE", f"/api/profile/sessions/{target['id']}").status_code == 200
    assert other.get("/api/tasks").status_code == 401


def test_cannot_revoke_current_session(panel):
    c, _ = panel
    current = [
        s for s in c.get("/api/profile/sessions").json()["sessions"] if s["current"]
    ][0]
    resp = c.request("DELETE", f"/api/profile/sessions/{current['id']}")
    assert resp.status_code == 400
    assert "当前会话" in resp.json()["error"]
    assert c.get("/api/tasks").status_code == 200


def test_revoke_missing_session_404(panel):
    c, _ = panel
    assert c.request("DELETE", "/api/profile/sessions/nonexistent").status_code == 404


def test_revoke_others_keeps_current(panel):
    c, app_module = panel
    a = TestClient(app_module.app)
    b = TestClient(app_module.app)
    login(a)
    login(b)

    resp = c.post("/api/profile/sessions/revoke-others")
    assert resp.json()["removed"] == 2
    assert c.get("/api/tasks").status_code == 200
    assert a.get("/api/tasks").status_code == 401
    assert b.get("/api/tasks").status_code == 401


def test_logout_revokes_only_own_session(panel):
    c, app_module = panel
    other = TestClient(app_module.app)
    login(other)

    c.post("/logout", follow_redirects=False)
    assert c.get("/api/tasks").status_code == 401
    assert other.get("/api/tasks").status_code == 200


def test_stale_cookie_rejected_after_db_wipe(panel):
    """光有签名 Cookie 不够，令牌必须在库里还存在。"""
    c, app_module = panel
    assert c.get("/api/tasks").status_code == 200
    app_module.store.clear_sessions()
    assert c.get("/api/tasks").status_code == 401


def test_expired_session_rejected(panel, monkeypatch):
    c, app_module = panel
    monkeypatch.setattr(app_module, "SESSION_TTL", -1)
    fresh = TestClient(app_module.app)
    login(fresh)
    assert fresh.get("/api/tasks").status_code == 401


# ---------- 登录锁定 ----------


def test_lockout_after_repeated_failures(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "lock")
    c = TestClient(app_module.app)

    for _ in range(auth.FAIL_LIMIT):
        assert login(c, "wrong").status_code == 401

    resp = login(c, "wrong")
    assert resp.status_code == 429
    assert "分钟后再试" in resp.text

    # 锁定期内即使密码正确也不放行
    assert login(c, TEST_PASSWORD).status_code == 429


def test_failure_counter_resets_on_success(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "reset")
    c = TestClient(app_module.app)

    for _ in range(auth.FAIL_LIMIT - 1):
        login(c, "wrong")
    assert login(c, TEST_PASSWORD).status_code == 302

    for _ in range(auth.FAIL_LIMIT - 1):
        assert login(c, "wrong").status_code == 401


def test_login_error_shows_remaining_attempts(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "hint")
    c = TestClient(app_module.app)
    assert "还可尝试" in login(c, "wrong").text


def test_login_history_records_both_outcomes(panel):
    c, app_module = panel
    other = TestClient(app_module.app)
    login(other, "wrong")

    history = c.get("/api/profile/login-history").json()["history"]
    assert any(h["ok"] == 1 for h in history)
    assert any(h["ok"] == 0 and "密码错误" in h["detail"] for h in history)


# ---------- 首次启动初始化 ----------


def test_bootstrap_generates_password(mock_ec2, monkeypatch, tmp_path):
    monkeypatch.delenv("AWS_HELPER_PASSWORD", raising=False)
    monkeypatch.setenv("AWS_HELPER_DATA", str(tmp_path / "boot"))

    import importlib

    from aws_helper.web import app as app_module

    importlib.reload(app_module)
    assert not app_module.store.has_password()

    initial = app_module._bootstrap_password()
    assert initial
    auth.validate_strength(initial)
    assert app_module.store.verify_login(initial)


def test_bootstrap_uses_env_password(mock_ec2, monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_HELPER_PASSWORD", "Env!Passw0rd")
    monkeypatch.setenv("AWS_HELPER_DATA", str(tmp_path / "boot2"))

    import importlib

    from aws_helper.web import app as app_module

    importlib.reload(app_module)
    assert app_module._bootstrap_password() == "Env!Passw0rd"
    assert app_module.store.verify_login("Env!Passw0rd")


def test_env_password_does_not_override_stored(mock_ec2, monkeypatch, tmp_path):
    """面板里改过密码后，重启不能被环境变量覆盖回去。"""
    data_dir = tmp_path / "boot3"
    monkeypatch.setenv("AWS_HELPER_PASSWORD", "Env!Passw0rd")
    app_module = build_app(monkeypatch, data_dir, password="Chan9ed!Pass")

    assert app_module._bootstrap_password() is None
    assert app_module.store.verify_login("Chan9ed!Pass")
    assert not app_module.store.verify_login("Env!Passw0rd")


# ---------- CLI ----------


def test_cli_reset_generates_password(tmp_path, capsys):
    data_dir = tmp_path / "cli1"
    assert cli.main(["--data-dir", str(data_dir), "reset-password"]) == 0
    out = capsys.readouterr().out
    assert "新密码" in out

    password = out.split("新密码:")[1].strip().splitlines()[0]
    store = Store(data_dir)
    try:
        assert store.verify_login(password)
    finally:
        store.close()


def test_cli_reset_with_explicit_password(tmp_path):
    data_dir = tmp_path / "cli2"
    code = cli.main(
        ["--data-dir", str(data_dir), "reset-password", "--password", "Cli!Passw0rd"]
    )
    assert code == 0
    store = Store(data_dir)
    try:
        assert store.verify_login("Cli!Passw0rd")
    finally:
        store.close()


def test_cli_rejects_weak_password(tmp_path, capsys):
    data_dir = tmp_path / "cli3"
    code = cli.main(
        ["--data-dir", str(data_dir), "reset-password", "--password", "weak"]
    )
    assert code == 2
    assert "--force" in capsys.readouterr().err
    store = Store(data_dir)
    try:
        assert not store.has_password()
    finally:
        store.close()


def test_cli_force_accepts_weak_password(tmp_path):
    data_dir = tmp_path / "cli4"
    code = cli.main(
        [
            "--data-dir",
            str(data_dir),
            "reset-password",
            "--password",
            "weak",
            "--force",
        ]
    )
    assert code == 0
    store = Store(data_dir)
    try:
        assert store.verify_login("weak")
    finally:
        store.close()


def test_cli_reset_invalidates_sessions(tmp_path):
    """CLI 重置后所有登录会话必须失效。"""
    data_dir = tmp_path / "cli5"
    store = Store(data_dir)
    store.set_password(TEST_PASSWORD, validate=False)
    token = store.create_session()
    assert store.touch_session(token)
    store.close()

    assert cli.main(["--data-dir", str(data_dir), "reset-password"]) == 0

    store = Store(data_dir)
    try:
        assert not store.touch_session(token)
    finally:
        store.close()


def test_cli_reset_recovers_locked_out_user(mock_ec2, monkeypatch, tmp_path):
    """密码全忘 + 已被锁定时，CLI 重置后能重新登录。"""
    data_dir = tmp_path / "cli6"
    app_module = build_app(monkeypatch, data_dir)
    c = TestClient(app_module.app)
    for _ in range(auth.FAIL_LIMIT + 1):
        login(c, "wrong")
    assert login(c, TEST_PASSWORD).status_code == 429

    assert (
        cli.main(
            ["--data-dir", str(data_dir), "reset-password", "--password", "Rec0ver!Pass"]
        )
        == 0
    )

    fresh_app = build_app(monkeypatch, data_dir, password="Rec0ver!Pass")
    fresh = TestClient(fresh_app.app)
    fresh.headers["x-forwarded-for"] = "203.0.113.9"
    assert login(fresh, "Rec0ver!Pass").status_code == 302


def test_cli_status_output(tmp_path, capsys):
    data_dir = tmp_path / "cli7"
    store = Store(data_dir)
    store.set_password(TEST_PASSWORD, validate=False)
    store.create_session(ip="10.0.0.1", user_agent="Chrome")
    store.record_login(True, "10.0.0.1", "Chrome", "登录成功")
    store.close()

    assert cli.main(["--data-dir", str(data_dir), "status"]) == 0
    out = capsys.readouterr().out
    assert "已设置密码  : 是" in out
    assert "活跃会话    : 1" in out
    assert "10.0.0.1" in out


def test_cli_logout_all(tmp_path, capsys):
    data_dir = tmp_path / "cli8"
    store = Store(data_dir)
    store.set_password(TEST_PASSWORD, validate=False)
    t1 = store.create_session()
    store.create_session()
    store.close()

    assert cli.main(["--data-dir", str(data_dir), "logout-all"]) == 0
    assert "已下线 2 个会话" in capsys.readouterr().out

    store = Store(data_dir)
    try:
        assert not store.touch_session(t1)
    finally:
        store.close()


def test_cli_requires_subcommand(capsys):
    with pytest.raises(SystemExit):
        cli.main([])
