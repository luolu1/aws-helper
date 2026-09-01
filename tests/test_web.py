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


def test_reinstall_preflight_endpoint(client):
    """重装预检要能给出保留/清空清单，页面靠它显示。"""
    c, aid, _ = client
    task = wait_task(
        c,
        c.post(
            "/api/launch",
            json={"account_id": aid, "region": "us-east-1", "name": "ri-node"},
        ).json()["task_id"],
    )
    iid = task["result"]["instances"][0]["instance_id"]

    body = c.get(
        f"/api/instances/reinstall-preflight?account_id={aid}"
        f"&region=us-east-1&instance_id={iid}"
    ).json()

    assert body["ok"] is True
    assert body["root_device_type"] == "ebs"
    assert body["private_ip"]
    assert body["problems"] == []


def test_reinstall_preflight_rejects_arch_mismatch(client):
    """预检必须在点确认之前挡住架构不匹配。"""
    import boto3

    c, aid, _ = client
    task = wait_task(
        c,
        c.post(
            "/api/launch",
            json={"account_id": aid, "region": "us-east-1", "name": "ri-arch"},
        ).json()["task_id"],
    )
    iid = task["result"]["instances"][0]["instance_id"]

    ec2 = boto3.client("ec2", region_name="us-east-1")
    images = ec2.describe_images(Owners=["amazon"])["Images"]
    arm = next((i for i in images if i.get("Architecture") == "arm64"), None)
    if arm is None:
        pytest.skip("moto 镜像里没有 arm64")

    body = c.get(
        f"/api/instances/reinstall-preflight?account_id={aid}"
        f"&region=us-east-1&instance_id={iid}&image_id={arm['ImageId']}"
    ).json()

    assert body["ok"] is False
    assert any("不匹配" in p for p in body["problems"])


def test_reinstall_requires_login(mock_ec2, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    app_module = build_app(monkeypatch, tmp_path / "ri-anon")
    c = TestClient(app_module.app)
    assert c.get("/api/instances/reinstall-preflight?account_id=1&region=us-east-1&instance_id=i-1").status_code == 401
    assert c.post("/api/instances/reinstall", json={}).status_code == 401


def test_reinstall_invalidates_instance_cache(client):
    """根卷换了实例的镜像 id 会变，缓存必须作废。"""
    from unittest.mock import patch

    c, aid, app_module = client
    with patch.object(app_module.reinstall, "reinstall") as fake:
        fake.return_value = {
            "instance_id": "i-1",
            "task_id": "rrvt-1",
            "state": "succeeded",
            "image_id": "ami-new",
            "image_label": "",
            "deleted_old_volume": True,
            "elapsed_sec": 12,
            "private_ip": "10.0.0.5",
            "public_ip": "1.2.3.4",
            "kept_volumes": [],
        }
        app_module.cache.fetch(
            app_module.ec2_instances_key(aid, "us-east-1"), 60, lambda: ["stale"]
        )
        assert app_module.cache.size() >= 1
        wait_task(
            c,
            c.post(
                "/api/instances/reinstall",
                json={"account_id": aid, "region": "us-east-1", "instance_id": "i-1"},
            ).json()["task_id"],
        )

    assert app_module.cache.size() == 0, "重装后必须清掉实例缓存"


def test_launch_with_password_records_credentials(client):
    """设了 root 密码开机，必须把密码记下来。

    密码只存在于 user-data 里，开完机关掉页面就再也找不回来 ——
    这是用户报的问题：创建的实例要记录好 root 密码。
    """
    c, aid, app_module = client
    wait_task(
        c,
        c.post(
            "/api/launch",
            json={
                "account_id": aid,
                "region": "us-east-1",
                "name": "pw-node",
                "root_password": "Str0ng!Pass1",
            },
        ).json()["task_id"],
    )

    rows = app_module.store.list_instance_creds(aid, "us-east-1")
    assert len(rows) == 1
    row = rows[0]
    assert row["auth_method"] == "password"
    assert row["login_user"] == "root"
    assert row["has_password"] is True
    assert "password_blob" not in row, "列表接口不能回传密文"


def test_launch_without_password_records_key(client):
    """没设密码就是密钥登录，记下用户名和密钥名。"""
    c, aid, app_module = client
    task = wait_task(
        c,
        c.post(
            "/api/launch",
            json={"account_id": aid, "region": "us-east-1", "name": "key-node"},
        ).json()["task_id"],
    )
    inst = task["result"]["instances"][0]

    row = app_module.store.instance_creds(aid, "us-east-1", inst["instance_id"])
    assert row["auth_method"] == "key"
    assert row["login_user"] == inst["ssh_user"]
    assert row["key_name"] == inst["key_name"]
    assert row["has_password"] is False


def test_creds_endpoint_hides_password(client):
    """列表接口只说有没有密码，不回明文。"""
    c, aid, _ = client
    wait_task(
        c,
        c.post(
            "/api/launch",
            json={
                "account_id": aid,
                "region": "us-east-1",
                "name": "secret-node",
                "root_password": "Str0ng!Pass1",
            },
        ).json()["task_id"],
    )

    body = c.get(f"/api/instances/creds?account_id={aid}&region=us-east-1").text
    assert "Str0ng!Pass1" not in body, "凭据列表泄漏了密码明文"
    assert '"has_password":true' in body.replace(" ", "")


def test_password_endpoint_returns_plaintext_and_audits(client):
    """点「查看」才给明文，并且要留审计日志。"""
    c, aid, app_module = client
    task = wait_task(
        c,
        c.post(
            "/api/launch",
            json={
                "account_id": aid,
                "region": "us-east-1",
                "name": "view-node",
                "root_password": "Str0ng!Pass1",
            },
        ).json()["task_id"],
    )
    iid = task["result"]["instances"][0]["instance_id"]

    body = c.get(
        f"/api/instances/{iid}/password?account_id={aid}&region=us-east-1"
    ).json()
    assert body["password"] == "Str0ng!Pass1"

    kinds = [log["kind"] for log in app_module.store.list_logs(50)]
    assert "creds" in kinds, "查看密码要留审计记录"


def test_password_endpoint_404_for_key_auth(client):
    c, aid, _ = client
    task = wait_task(
        c,
        c.post(
            "/api/launch",
            json={"account_id": aid, "region": "us-east-1", "name": "nokey-pw"},
        ).json()["task_id"],
    )
    iid = task["result"]["instances"][0]["instance_id"]
    assert (
        c.get(f"/api/instances/{iid}/password?account_id={aid}&region=us-east-1").status_code
        == 404
    )


def test_creds_require_login(mock_ec2, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    app_module = build_app(monkeypatch, tmp_path / "creds-anon")
    c = TestClient(app_module.app)
    assert c.get("/api/instances/creds?account_id=1&region=us-east-1").status_code == 401
    assert (
        c.get("/api/instances/i-1/password?account_id=1&region=us-east-1").status_code
        == 401
    )


def test_terminate_removes_credentials(client):
    """实例终止后不该留着它的密码 —— AWS 会复用实例 ID。"""
    c, aid, app_module = client
    task = wait_task(
        c,
        c.post(
            "/api/launch",
            json={
                "account_id": aid,
                "region": "us-east-1",
                "name": "doomed",
                "root_password": "Str0ng!Pass1",
            },
        ).json()["task_id"],
    )
    iid = task["result"]["instances"][0]["instance_id"]
    assert app_module.store.instance_creds(aid, "us-east-1", iid) is not None

    wait_task(
        c,
        c.post(
            "/api/instances/power",
            json={
                "account_id": aid,
                "region": "us-east-1",
                "action": "terminate",
                "instance_ids": [iid],
                "cleanup": False,
            },
        ).json()["task_id"],
    )

    assert app_module.store.instance_creds(aid, "us-east-1", iid) is None


def test_instances_page_shows_login_column():
    """实例面板要有「登录方式」列，否则记了也看不到。"""
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    assert "<th>登录方式</th>" in html
    assert "function credCell" in html
    assert "showPassword" in html
    assert 'colspan="8"' not in html, "加了一列，空态的 colspan 也要跟着改"
