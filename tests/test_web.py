"""Web 端点测试：鉴权、开机、换 IP、脚本、规则。"""

from __future__ import annotations

import time
from html import escape

import pytest
from fastapi.testclient import TestClient


TEST_PASSWORD = "Test!Passw0rd"


def build_app(monkeypatch, data_dir, password=TEST_PASSWORD):
    """重载 web app 并写入登录密码。

    TestClient 默认不触发 lifespan，首次启动的密码初始化不会跑，
    所以测试必须自己把密码写进库。
    """
    monkeypatch.setenv("AWS_HELPER_DATA", str(data_dir))

    import importlib

    from aws_helper.web import app as app_module

    importlib.reload(app_module)
    app_module.store.set_password(password, validate=False)
    return app_module


def login(client, password=TEST_PASSWORD):
    return client.post(
        "/login", data={"password": password}, follow_redirects=False
    )


@pytest.fixture
def client(mock_ec2, ubuntu_ami, monkeypatch, tmp_path):
    """构造带 moto 后端的测试客户端，并预置一个账号。"""
    app_module = build_app(monkeypatch, tmp_path / "web")
    c = TestClient(app_module.app)
    login(c)
    account_id = app_module.store.add_account("t", "testing", "testing", "us-east-1")
    return c, account_id, app_module


def wait_task(client, task_id, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get(f"/api/tasks/{task_id}").json()
        task = data["task"]
        if task["status"] != "running":
            return task
        time.sleep(0.4)
    raise AssertionError("任务超时")


def test_requires_login(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "w2")
    c = TestClient(app_module.app)

    assert c.get("/api/tasks").status_code == 401
    resp = c.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["location"]


def test_wrong_password_rejected(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "w3")
    c = TestClient(app_module.app)
    assert login(c, "wrong-password").status_code == 401
    assert c.get("/api/tasks").status_code == 401


def test_pages_render(client):
    c, _, _ = client
    for path, marker in [
        ("/", "实例列表"),
        ("/launch", "一键开机"),
        ("/scripts", "开机脚本"),
        ("/autoip", "自动换 IP"),
        ("/accounts", "添加 AWS 账号"),
    ]:
        resp = c.get(path)
        assert resp.status_code == 200, path
        assert marker in resp.text, path


def test_healthz(client):
    c, _, _ = client
    body = c.get("/healthz").json()
    assert body["ok"] is True


def test_launch_endpoint_creates_instance(client):
    c, aid, _ = client
    resp = c.post(
        "/api/launch",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "name": "web-node",
            "script": "echo WEB_MARKER",
            "root_password": "pw",
        },
    )
    assert resp.status_code == 200
    task = wait_task(c, resp.json()["task_id"])
    assert task["status"] == "done", task
    inst = task["result"]["instances"][0]
    assert inst["instance_id"].startswith("i-")
    assert inst["public_ip"]
    assert inst["state"] == "running"


def test_launch_requires_name(client):
    c, aid, _ = client
    resp = c.post(
        "/api/launch", json={"account_id": aid, "region": "us-east-1", "name": "  "}
    )
    assert resp.status_code == 400
    assert "名称" in resp.json()["error"]


def test_launch_rejects_bad_script_synchronously(client):
    """脚本非法要在 HTTP 响应里直接报错，而不是丢进后台任务再失败。"""
    c, aid, _ = client
    resp = c.post(
        "/api/launch",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "name": "x",
            "script": "#!/bin/bash\necho hi",
        },
    )
    assert resp.status_code == 400
    assert "#!/bin/bash" in resp.json()["error"]


def test_instances_and_power_flow(client):
    c, aid, _ = client
    launched = wait_task(
        c,
        c.post(
            "/api/launch",
            json={"account_id": aid, "region": "us-east-1", "name": "flow"},
        ).json()["task_id"],
    )
    iid = launched["result"]["instances"][0]["instance_id"]

    listed = c.get(f"/api/instances?account_id={aid}&region=us-east-1").json()
    assert any(i["instance_id"] == iid for i in listed["instances"])

    resp = c.post(
        "/api/instances/power",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "action": "stop",
            "instance_ids": [iid],
        },
    )
    assert resp.status_code == 200

    again = c.get(f"/api/instances?account_id={aid}&region=us-east-1").json()
    state = [i for i in again["instances"] if i["instance_id"] == iid][0]["state"]
    assert state == "stopped"


def test_power_rejects_empty_list(client):
    c, aid, _ = client
    resp = c.post(
        "/api/instances/power",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "action": "stop",
            "instance_ids": [],
        },
    )
    assert resp.status_code == 400


def test_change_ip_endpoint(client):
    c, aid, _ = client
    launched = wait_task(
        c,
        c.post(
            "/api/launch",
            json={"account_id": aid, "region": "us-east-1", "name": "ipnode"},
        ).json()["task_id"],
    )
    inst = launched["result"]["instances"][0]

    resp = c.post(
        "/api/change-ip",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "instance_id": inst["instance_id"],
            "strategy": "eip",
        },
    )
    task = wait_task(c, resp.json()["task_id"])
    assert task["status"] == "done", task
    assert task["result"]["new_ip"] != inst["public_ip"]


def test_change_ip_reports_error_in_task(client):
    c, aid, _ = client
    resp = c.post(
        "/api/change-ip",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "instance_id": "i-00000000000000000",
        },
    )
    task = wait_task(c, resp.json()["task_id"])
    assert task["status"] == "error"
    assert "找不到实例" in task["error"]


def test_script_crud(client):
    c, _, _ = client
    resp = c.post(
        "/api/scripts",
        data={"name": "tpl-a", "body": "echo hi", "packages": "curl vim"},
    )
    assert resp.status_code == 200
    sid = resp.json()["id"]

    assert "tpl-a" in c.get("/scripts").text
    assert c.request("DELETE", f"/api/scripts/{sid}").status_code == 200
    assert "tpl-a" not in c.get("/scripts").text


def test_truncated_script_preview_has_full_body_in_title(client):
    """被 ellipsis 截断的脚本预览列必须能悬停看到全文。

    单元格设了 max-width:420px + text-overflow:ellipsis，且模板只渲染 body[:90]。
    没有 title 属性时长脚本的后半段在页面上彻底不可见 —— 想确认某个模板到底
    装了什么，只能点「载入」把它灌进表单，绕一大圈。
    """
    c, _, _ = client
    long_body = "\n".join(f"echo 第{i}步-verify-long-script-line" for i in range(1, 21))
    resp = c.post(
        "/api/scripts",
        data={"name": "tpl-long", "body": long_body, "packages": "curl"},
    )
    assert resp.status_code == 200

    html = c.get("/scripts").text
    assert "tpl-long" in html
    assert f'title="{escape(long_body)}"' in html, "截断的脚本预览单元格缺少完整 body 的 title"


def test_script_preview(client):
    c, _, _ = client
    resp = c.post(
        "/api/scripts/preview",
        json={"body": "echo PREVIEW", "root_password": "pw", "hostname": "h1"},
    )
    text = resp.json()["rendered"]
    assert text.startswith("#!/bin/bash")
    assert "echo PREVIEW" in text
    assert "chpasswd" in text


def test_script_preview_rejects_shebang(client):
    c, _, _ = client
    resp = c.post("/api/scripts/preview", json={"body": "#!/bin/sh\nls"})
    assert resp.status_code == 400


def test_ip_rule_crud(client):
    c, aid, _ = client
    resp = c.post(
        "/api/ip-rules",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "instance_id": "i-abc",
            "strategy": "eip",
            "check_port": 22,
            "fail_threshold": 2,
            "deny_cidrs": ["52.0.0.0/8"],
        },
    )
    assert resp.status_code == 200
    rid = resp.json()["id"]
    assert "i-abc" in c.get("/autoip").text
    assert c.request("DELETE", f"/api/ip-rules/{rid}").status_code == 200
    assert "i-abc" not in c.get("/autoip").text


def test_monitor_toggle(client):
    c, _, _ = client
    assert c.post("/api/monitor/stop").json()["running"] is False
    assert c.post("/api/monitor/start").json()["running"] is True
    assert c.post("/api/monitor/bogus").status_code == 400


def test_probe_endpoint_reports_unreachable(client):
    c, _, _ = client
    body = c.post("/api/probe", json={"ip": "203.0.113.1", "port": 9}).json()
    assert body["ok"] is False


def test_addresses_and_release_idle(client):
    c, aid, app_module = client
    from aws_helper.core import aws

    session = aws.ec2(app_module.store.credentials(aid, "us-east-1"))
    session.allocate_address(Domain="vpc")

    listed = c.get(f"/api/addresses?account_id={aid}&region=us-east-1").json()
    assert len(listed["addresses"]) == 1
    assert listed["addresses"][0]["idle"] is True

    freed = c.post(
        "/api/addresses/release-idle", json={"account_id": aid, "region": "us-east-1"}
    ).json()
    assert len(freed["released"]) == 1


def test_keypair_download_after_launch(client):
    """私钥必须以纯文本下发，且换行是真换行。

    早先返回 JSON，浏览器里看到的是 "-----BEGIN...\\nMIIE..."，
    用户复制出来的 \\n 是两个字符而不是换行，ssh -i 直接报 invalid format。
    """
    c, aid, _ = client
    task = wait_task(
        c,
        c.post(
            "/api/launch",
            json={"account_id": aid, "region": "us-east-1", "name": "keynode"},
        ).json()["task_id"],
    )
    key_name = task["result"]["instances"][0]["key_name"]
    resp = c.get(f"/api/keypairs/{aid}/us-east-1/{key_name}")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert f'filename="{key_name}.pem"' in resp.headers["content-disposition"]

    body = resp.text
    assert "PRIVATE KEY" in body
    assert "\\n" not in body, "私钥里出现了字面量 \\n，ssh 无法使用"
    assert body.count("\n") >= 2, "私钥应该有真实换行"
    assert body.endswith("\n"), "OpenSSH 要求私钥文件以换行结尾"
    assert body.lstrip().startswith("-----BEGIN"), "不能被 JSON 包裹"


def test_keypair_missing_returns_404(client):
    c, aid, _ = client
    assert c.get(f"/api/keypairs/{aid}/us-east-1/nope").status_code == 404


def test_logs_recorded(client):
    c, aid, _ = client
    wait_task(
        c,
        c.post(
            "/api/launch",
            json={"account_id": aid, "region": "us-east-1", "name": "logged"},
        ).json()["task_id"],
    )
    logs = c.get("/api/logs").json()["logs"]
    assert any(l["kind"] == "launch" and l["ok"] == 1 for l in logs)


def test_account_add_rejects_bad_credentials(client, monkeypatch):
    c, _, app_module = client

    def boom(*a, **k):
        raise RuntimeError("InvalidClientTokenId")

    monkeypatch.setattr(app_module.aws, "verify", boom)
    resp = c.post(
        "/api/accounts",
        data={
            "label": "bad",
            "access_key": "AKIABAD",
            "secret_key": "x",
            "region": "us-east-1",
        },
    )
    assert resp.status_code == 400
    assert "校验失败" in resp.json()["error"]


def test_logout_clears_session(client):
    c, _, _ = client
    c.post("/logout", follow_redirects=False)
    assert c.get("/api/tasks").status_code == 401


# ---------- 账号编辑与代理 ----------


@pytest.fixture
def server_client(monkeypatch, tmp_path):
    """真实 HTTP 后端的测试客户端。

    proxy 相关测试必须用它 —— moto 的 mock_aws 在 botocore 层拦截调用，
    根本不产生 socket 流量，代理永远不会被拨号，测出来的"通过"是假的。
    """
    from moto.server import ThreadedMotoServer

    from tests.test_proxy import _lan_ip

    host = _lan_ip()
    server = ThreadedMotoServer(ip_address=host, port=0, verbose=False)
    server.start()
    _, port = server.get_host_and_port()

    monkeypatch.setenv("AWS_HELPER_ENDPOINT_URL", f"http://{host}:{port}")

    app_module = build_app(monkeypatch, tmp_path / "srv")
    c = TestClient(app_module.app)
    login(c)
    account_id = app_module.store.add_account("t", "testing", "testing", "us-east-1")
    yield c, account_id, app_module
    server.stop()


def test_add_account_with_proxy_via_api(server_client):
    c, _, app_module = server_client
    from tests.socks_server import Socks5Server

    with Socks5Server() as proxy:
        resp = c.post(
            "/api/accounts",
            data={
                "label": "with-proxy",
                "access_key": "testing",
                "secret_key": "testing",
                "region": "us-east-1",
                "proxy": proxy.url,
            },
        )
        assert resp.status_code == 200, resp.json()
        acct = [a for a in app_module.store.list_accounts() if a.label == "with-proxy"][0]
        assert acct.proxy == proxy.url
        assert proxy.targets, "添加账号时的校验请求应经过代理"


def test_add_account_rejects_bad_proxy(client):
    c, _, _ = client
    resp = c.post(
        "/api/accounts",
        data={
            "label": "bad-proxy",
            "access_key": "testing",
            "secret_key": "testing",
            "region": "us-east-1",
            "proxy": "ftp://1.2.3.4:21",
        },
    )
    assert resp.status_code == 400
    assert "不支持的代理协议" in resp.json()["error"]


def test_add_account_unreachable_proxy_reports_hint(server_client):
    c, _, _ = server_client
    resp = c.post(
        "/api/accounts",
        data={
            "label": "dead-proxy",
            "access_key": "testing",
            "secret_key": "testing",
            "region": "us-east-1",
            "proxy": "socks5h://127.0.0.1:1",
        },
    )
    assert resp.status_code == 400
    assert "无法连接到代理" in resp.json()["error"]


def test_get_account_returns_editable_fields(client):
    c, aid, _ = client
    body = c.get(f"/api/accounts/{aid}").json()["account"]
    assert body["id"] == aid
    assert body["access_key"] == "testing"
    assert body["region"] == "us-east-1"
    assert body["proxy"] == ""


def test_get_missing_account_404(client):
    c, _, _ = client
    assert c.get("/api/accounts/9999").status_code == 404


def test_update_account_label_and_region(client):
    c, aid, app_module = client
    resp = c.put(
        f"/api/accounts/{aid}",
        data={
            "label": "renamed",
            "access_key": "testing",
            "secret_key": "",
            "region": "ap-northeast-1",
            "proxy": "",
            "note": "改过了",
        },
    )
    assert resp.status_code == 200, resp.json()
    acct = app_module.store.get_account(aid)
    assert acct.label == "renamed"
    assert acct.region == "ap-northeast-1"
    assert acct.note == "改过了"


def test_update_keeps_secret_when_blank(client):
    c, aid, app_module = client
    before = app_module.store.credentials(aid).secret_key
    c.put(
        f"/api/accounts/{aid}",
        data={
            "label": "same",
            "access_key": "testing",
            "secret_key": "",
            "region": "us-east-1",
            "proxy": "",
        },
    )
    assert app_module.store.credentials(aid).secret_key == before


def test_update_adds_and_clears_proxy(server_client):
    c, aid, app_module = server_client
    from tests.socks_server import Socks5Server

    with Socks5Server() as proxy:
        resp = c.put(
            f"/api/accounts/{aid}",
            data={
                "label": "t",
                "access_key": "testing",
                "secret_key": "",
                "region": "us-east-1",
                "proxy": proxy.url,
            },
        )
        assert resp.status_code == 200, resp.json()
        assert app_module.store.get_account(aid).proxy == proxy.url
        assert proxy.targets

    resp = c.put(
        f"/api/accounts/{aid}",
        data={
            "label": "t",
            "access_key": "testing",
            "secret_key": "",
            "region": "us-east-1",
            "proxy": "",
        },
    )
    assert resp.status_code == 200
    assert app_module.store.get_account(aid).proxy is None


def test_update_requires_label(client):
    c, aid, _ = client
    resp = c.put(
        f"/api/accounts/{aid}",
        data={"label": "  ", "access_key": "testing", "secret_key": "", "proxy": ""},
    )
    assert resp.status_code == 400


def test_update_missing_account_404(client):
    c, _, _ = client
    resp = c.put(
        "/api/accounts/9999",
        data={"label": "x", "access_key": "testing", "secret_key": "", "proxy": ""},
    )
    assert resp.status_code == 404


def test_test_proxy_endpoint_success(server_client):
    c, aid, _ = server_client
    from tests.socks_server import Socks5Server

    with Socks5Server() as proxy:
        resp = c.post(
            "/api/accounts/test-proxy",
            json={"account_id": aid, "proxy": proxy.url, "region": "us-east-1"},
        )
        assert resp.status_code == 200, resp.json()
        body = resp.json()
        assert body["regions"] > 0
        assert body["elapsed_ms"] >= 0
        assert proxy.targets


def test_test_proxy_masks_password_in_response(server_client):
    c, aid, _ = server_client
    from tests.socks_server import Socks5Server

    with Socks5Server(username="u", password="topsecret") as proxy:
        body = c.post(
            "/api/accounts/test-proxy",
            json={"account_id": aid, "proxy": proxy.url},
        ).json()
        assert "topsecret" not in body["proxy"]


def test_test_proxy_reports_unreachable(server_client):
    c, aid, _ = server_client
    resp = c.post(
        "/api/accounts/test-proxy",
        json={"account_id": aid, "proxy": "socks5h://127.0.0.1:1"},
    )
    assert resp.status_code == 400
    assert "无法连接到代理" in resp.json()["error"]


def test_test_proxy_requires_proxy_value(client):
    c, aid, _ = client
    resp = c.post("/api/accounts/test-proxy", json={"account_id": aid, "proxy": ""})
    assert resp.status_code == 400


def test_test_proxy_for_new_account_needs_keys(client):
    c, _, _ = client
    resp = c.post(
        "/api/accounts/test-proxy", json={"proxy": "socks5h://127.0.0.1:1080"}
    )
    assert resp.status_code == 400
    assert "Access Key" in resp.json()["error"]


def test_accounts_page_shows_proxy_and_edit_button(client):
    c, aid, app_module = client
    app_module.store.update_account(aid, proxy="socks5h://u:pw@5.5.5.5:1080")
    html = c.get("/accounts").text
    assert "5.5.5.5" in html
    assert "pw@" not in html
    assert "编辑" in html
    assert "测试代理连通性" in html
