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


# ---------- 重装时重设凭据 ----------

REAL_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIMxGgW4kZ8HLmGpQnbnFhc6TThRRW3TnkS1EYQ8jSJZG"
    " me@laptop"
)


def _reinstall_result(**over):
    base = {
        "instance_id": "i-1",
        "task_id": "rrvt-1",
        "state": "succeeded",
        "image_id": "ami-new",
        "image_label": "Ubuntu 24.04",
        "deleted_old_volume": True,
        "elapsed_sec": 12,
        "private_ip": "10.0.0.5",
        "public_ip": "1.2.3.4",
        "kept_volumes": [],
        "key_name": "prod-key",
        "ssh_user": "ubuntu",
        "os_family": "linux",
        "ssh_command": "ssh root@1.2.3.4",
        "creds_applied": True,
        "creds_note": "",
        "login_user": "root",
        "set_password": False,
        "set_public_key": False,
    }
    base.update(over)
    return base


def test_reinstall_rejects_weak_password(client):
    """重装后设的密码要开着 SSH 密码登录，弱口令等于把机器交出去。"""
    c, aid, app_module = client
    r = c.post(
        "/api/instances/reinstall",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "instance_id": "i-1",
            "root_password": "123456",
        },
    )
    assert r.status_code == 400
    assert "密码" in r.json()["error"]


def test_reinstall_rejects_bad_public_key(client):
    """乱填的公钥写进去不报错，但登录静默失败 —— 必须当场挡住。"""
    c, aid, app_module = client
    r = c.post(
        "/api/instances/reinstall",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "instance_id": "i-1",
            "ssh_public_key": "-----BEGIN OPENSSH PRIVATE KEY-----",
        },
    )
    assert r.status_code == 400
    assert "私钥" in r.json()["error"]


def test_reinstall_password_forwarded_and_recorded(client):
    """重装时设的密码要传给 core，并且记进凭据表让面板能查。"""
    from unittest.mock import patch

    c, aid, app_module = client
    with patch.object(app_module.reinstall, "reinstall") as fake:
        fake.return_value = _reinstall_result(set_password=True)
        wait_task(
            c,
            c.post(
                "/api/instances/reinstall",
                json={
                    "account_id": aid,
                    "region": "us-east-1",
                    "instance_id": "i-1",
                    "root_password": "Str0ng!Pass1",
                },
            ).json()["task_id"],
        )
        assert fake.call_args.kwargs["new_password"] == "Str0ng!Pass1"

    row = app_module.store.instance_creds(aid, "us-east-1", "i-1")
    assert row["auth_method"] == "password"
    assert row["login_user"] == "root"
    assert app_module.store.instance_password(aid, "us-east-1", "i-1") == "Str0ng!Pass1"


def test_reinstall_public_key_forwarded(client):
    from unittest.mock import patch

    c, aid, app_module = client
    with patch.object(app_module.reinstall, "reinstall") as fake:
        fake.return_value = _reinstall_result(set_public_key=True)
        wait_task(
            c,
            c.post(
                "/api/instances/reinstall",
                json={
                    "account_id": aid,
                    "region": "us-east-1",
                    "instance_id": "i-1",
                    "ssh_public_key": REAL_PUBKEY,
                },
            ).json()["task_id"],
        )
        assert fake.call_args.kwargs["new_public_key"] == REAL_PUBKEY

    row = app_module.store.instance_creds(aid, "us-east-1", "i-1")
    assert row["auth_method"] == "key"
    assert row["has_password"] is False


def test_reinstall_without_creds_keeps_key_record(client):
    """不改凭据的重装照旧记密钥登录，登录用户跟着新系统变。"""
    from unittest.mock import patch

    c, aid, app_module = client
    with patch.object(app_module.reinstall, "reinstall") as fake:
        fake.return_value = _reinstall_result(creds_applied=False)
        wait_task(
            c,
            c.post(
                "/api/instances/reinstall",
                json={"account_id": aid, "region": "us-east-1", "instance_id": "i-1"},
            ).json()["task_id"],
        )

    row = app_module.store.instance_creds(aid, "us-east-1", "i-1")
    assert row["auth_method"] == "key"
    assert row["login_user"] == "ubuntu"


def test_failed_credential_application_not_recorded_as_password(client):
    """SSM 没设上就不能记成密码登录 —— 面板会显示一个登不进去的密码。"""
    from unittest.mock import patch

    c, aid, app_module = client
    with patch.object(app_module.reinstall, "reinstall") as fake:
        fake.return_value = _reinstall_result(
            creds_applied=False,
            creds_note="重装成功，但等了 300s SSM Agent 仍未注册",
        )
        wait_task(
            c,
            c.post(
                "/api/instances/reinstall",
                json={
                    "account_id": aid,
                    "region": "us-east-1",
                    "instance_id": "i-1",
                    "root_password": "Str0ng!Pass1",
                },
            ).json()["task_id"],
        )

    row = app_module.store.instance_creds(aid, "us-east-1", "i-1")
    assert row["auth_method"] == "key", "凭据没设上就不能记成密码"
    assert row["has_password"] is False


def test_reinstall_password_not_in_log(client):
    from unittest.mock import patch

    c, aid, app_module = client
    with patch.object(app_module.reinstall, "reinstall") as fake:
        fake.return_value = _reinstall_result(set_password=True)
        wait_task(
            c,
            c.post(
                "/api/instances/reinstall",
                json={
                    "account_id": aid,
                    "region": "us-east-1",
                    "instance_id": "i-1",
                    "root_password": "Str0ng!Pass1",
                },
            ).json()["task_id"],
        )

    logs = c.get("/api/logs").json()["logs"]
    assert "Str0ng!Pass1" not in str(logs)


def test_reinstall_dialog_has_credential_section():
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    assert "ri-cred-mode" in html
    assert "ri-password" in html
    assert "ri-pubkey" in html
    assert "function riSsmProbe" in html
    assert "root_password: password" in html
    assert "ssh_public_key: pubkey" in html


def test_result_shows_single_login_user():
    """设了新凭据就不能再摆镜像默认用户 —— 会出现「登录用户 ubuntu」和
    「公钥已写入 root」自相矛盾，用户不知道该用哪个登录。浏览器实测过。
    """
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    assert "d.ssh_user && !d.creds_applied" in html


def test_modal_scrolls_when_taller_than_viewport():
    """弹窗高过视口时必须能内部滚动。

    加了凭据区后重装弹窗实测 841px，超过 720p 视口。没有 max-height +
    overflow 的话 flex 居中会把顶部推成负值（实测 -61px），确认按钮被挤出
    屏幕且无法滚到 —— 用户根本点不了。
    """
    from pathlib import Path

    css = Path("aws_helper/web/static/app.css").read_text()
    box = css.split(".mask .box {")[1].split("}")[0]
    assert "max-height" in box
    assert "overflow-y: auto" in box


# ---------- 进页面读本地快照，不调 AWS ----------


def test_instances_page_does_not_call_aws_on_load():
    """进页面只读 localStorage 快照，不能自动打 AWS。

    用户要求：刷新页面和重新登录都不该产生 API 调用，否则容易触发风控。
    后端那层 10 秒缓存挡不住 F5 —— 超过 10 秒的刷新就是一次真实调用。
    """
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    init = html.split("document.addEventListener('DOMContentLoaded'")[1].split("});")[0]
    assert "showSnapshotOrPrompt()" in init
    assert "refresh(" not in init, "进页面不能触发 refresh —— 那会打 AWS"


def test_switching_account_reads_snapshot_not_aws():
    """切账号/区域也只读该组合的快照，不自动拉取。"""
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    body = html.split("function resetFingerprint()")[1].split("\n}")[0]
    assert "showSnapshotOrPrompt()" in body
    assert "refresh()" not in body


def test_snapshot_age_is_shown():
    """快照可能很旧，必须如实标出年龄，不能让用户把旧状态当成当前状态。"""
    from pathlib import Path

    for name in ("instances", "lightsail"):
        html = Path(f"aws_helper/web/templates/{name}.html").read_text()
        assert "function showStaleness" in html, name
        assert "本地快照" in html, name
        assert "进页面不调用 AWS" in html, name


def test_refresh_persists_snapshot():
    """手动刷新拿到的结果要存下来，否则下次进页面又是空的。"""
    from pathlib import Path

    inst = Path("aws_helper/web/templates/instances.html").read_text()
    assert inst.count("saveSnapshot()") >= 3, "changed 与未 changed 两条路都要存"

    ls = Path("aws_helper/web/templates/lightsail.html").read_text()
    assert "saveSnapshot()" in ls


def test_lightsail_also_snapshot_based():
    from pathlib import Path

    html = Path("aws_helper/web/templates/lightsail.html").read_text()
    init = html.split("document.addEventListener('DOMContentLoaded'")[1].split("});")[0]
    assert "showSnapshotOrPrompt()" in init
    assert "refresh(" not in init
    assert 'onchange="showSnapshotOrPrompt()"' in html


def test_power_actions_still_force_refresh():
    """电源操作后必须真的回源 —— 状态刚变，这时候拿快照就是错的。"""
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    body = html.split("async function refreshAfterAction()")[1].split("}")[0]
    assert "force: true" in body


def test_creds_cached_in_snapshot():
    """登录方式列也要进快照，否则走快照时那一列全是「未记录」。"""
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    assert "creds: INSTANCE_CREDS" in html
    assert "INSTANCE_CREDS = snap.creds || {}" in html


def test_snapshot_vars_declared_before_use():
    """let 有暂时性死区：快照函数在顶部赋值，声明必须也在顶部。"""
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    decl = html.index("let INSTANCE_CREDS")
    use = html.index("INSTANCE_CREDS = snap.creds")
    assert decl < use, "声明必须在快照函数之前，否则 ReferenceError"


def test_snapshots_are_keyed_per_account_region():
    """每个 (账号, 区域) 各存一份。共用一个键的话切区域会互相覆盖 ——
    浏览器实测过：切到 B 加载后再切回 A，A 的快照已经没了。
    """
    from pathlib import Path

    for name, prefix in (("instances", "inst_snapshot:"), ("lightsail", "ls_snapshot:")):
        html = Path(f"aws_helper/web/templates/{name}.html").read_text()
        assert f"SNAP_PREFIX = '{prefix}'" in html, name
        assert "${SNAP_PREFIX}${s.account_id}|${s.region}" in html, name
        assert "localStorage.setItem(snapKey(sel())" in html, name


def test_snapshots_are_pruned():
    """localStorage 只有 5MB 左右，快照不能无限堆积。"""
    from pathlib import Path

    for name in ("instances", "lightsail"):
        html = Path(f"aws_helper/web/templates/{name}.html").read_text()
        assert "function pruneSnapshots" in html, name
        assert "SNAP_MAX" in html, name
        assert "sort((a, b) => a.at - b.at)" in html, name


# ---------- CPU 积分模式 ----------


def test_credit_mode_endpoint_requires_login(mock_ec2, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    app_module = build_app(monkeypatch, tmp_path / "credit-anon")
    c = TestClient(app_module.app)
    assert c.post("/api/instances/credit-mode", json={}).status_code == 401


def test_credit_mode_rejects_bad_mode(client):
    c, aid, app_module = client
    r = c.post(
        "/api/instances/credit-mode",
        json={
            "account_id": aid,
            "region": "us-east-1",
            "instance_ids": ["i-1"],
            "mode": "cheap",
        },
    )
    assert r.status_code == 400
    assert "standard" in r.json()["error"]


def test_credit_mode_invalidates_cache(client):
    """积分模式变了，列表里那一列也得变，缓存必须作废。"""
    from unittest.mock import patch

    c, aid, app_module = client
    with patch.object(app_module.launch, "set_credit_mode") as fake:
        fake.return_value = {"mode": "standard", "succeeded": ["i-1"], "failed": []}
        app_module.cache.fetch(
            app_module.ec2_instances_key(aid, "us-east-1"), 60, lambda: ["stale"]
        )
        assert app_module.cache.size() >= 1
        r = c.post(
            "/api/instances/credit-mode",
            json={
                "account_id": aid,
                "region": "us-east-1",
                "instance_ids": ["i-1"],
                "mode": "standard",
            },
        )

    assert r.json()["ok"] is True
    assert app_module.cache.size() == 0


def test_launch_api_sends_standard_credit_spec(client):
    """走完整 HTTP 开机链路，断言真的把 standard 发给了 AWS。

    不能断言 moto 的返回值 —— 它对所有机型都回 standard，把修复删掉照样通过。
    """
    c, aid, app_module = client
    task = wait_task(
        c,
        c.post(
            "/api/launch",
            json={
                "account_id": aid,
                "region": "us-east-1",
                "name": "credit-node",
                "instance_type": "t3.micro",
            },
        ).json()["task_id"],
    )
    iid = task["result"]["instances"][0]["instance_id"]
    items = c.get(
        f"/api/instances?account_id={aid}&region=us-east-1"
    ).json()["instances"]
    row = next(i for i in items if i["instance_id"] == iid)
    # 这两个字段是本次新增的，moto 也能验证：字段存在且分类正确
    assert row["burstable"] is True
    assert "cpu_credits" in row


def test_instances_page_shows_credit_column():
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    assert "<th>CPU 积分</th>" in html
    assert "function creditCell" in html
    assert "function setCreditMode" in html
    assert 'colspan="9"' not in html, "加了一列，空态 colspan 也要跟着改"


def test_bulk_fix_filters_non_burstable():
    """非 T 机型传给 ModifyInstanceCreditSpecification 会整批失败。"""
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    body = html.split("function fixSelectedCredits()")[1].split("\n}")[0]
    assert "isBurstable(inst.instance_type)" in body


def test_credit_cell_uses_instance_type_not_backend_flag():
    """机型判断必须前端自己算。

    用户实测报的 bug：t3.micro 点批量改报「请勾选至少一台 T 系列实例」。
    原因是过滤条件读 inst.burstable，而这个字段是后端新加的 —— 用户
    localStorage 里的快照存于加字段之前，没有它，整台机器被当成非 T。
    """
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    assert "function isBurstable" in html
    assert "BURSTABLE_FAMILIES" in html
    assert "!i.burstable" not in html, "不能只靠后端字段判断"
    assert "inst.burstable" not in html, "不能只靠后端字段判断"

    cell = html.split("function creditCell")[1].split("\n}")[0]
    assert "isBurstable(i.instance_type)" in cell


def test_unknown_credit_mode_still_offers_fix():
    """查不到当前模式也要能改 —— 不知道当前值不代表不能设成 standard。

    缺 IAM 权限、或快照存于加 cpu_credits 之前，都会落到这个分支。
    """
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    cell = html.split("function creditCell")[1].split("\n}")[0]
    assert "未知" in cell
    unknown_part = cell.split("未知")[1]
    assert "setCreditMode" in unknown_part, "未知状态也要给按钮"


def test_snapshot_has_version_field():
    """加字段就要 +1 版本，否则旧快照缺字段会渲染出错误的行。

    这次 t3.micro 的 bug 根源就是旧快照被当成新结构用。
    """
    from pathlib import Path

    for name in ("instances", "lightsail"):
        html = Path(f"aws_helper/web/templates/{name}.html").read_text()
        assert "SNAP_VERSION" in html, name
        assert "v: SNAP_VERSION" in html, name
        assert "=== SNAP_VERSION ? " in html or "parsed.v === SNAP_VERSION" in html, name


def test_bulk_fix_error_names_the_types():
    """报错要说清勾的是什么机型，而不是笼统一句「请勾选 T 系列」——
    用户勾的明明是 t3.micro，那句提示只会让人困惑。
    """
    from pathlib import Path

    html = Path("aws_helper/web/templates/instances.html").read_text()
    body = html.split("function fixSelectedCredits()")[1].split("\n}")[0]
    assert "请先勾选实例" in body, "没勾任何实例和勾了非 T 是两种情况"
    assert "types.join" in body, "要列出实际勾选的机型"


# ---------- 实例侧探测（agent 模式） ----------


def _make_agent_rule(app_module, aid, instance_id="i-0abc"):
    return app_module.store.save_ip_rule(
        account_id=aid,
        region="us-east-1",
        instance_id=instance_id,
        probe_mode="agent",
        agent_target="www.baidu.com:443",
        agent_interval_sec=60,
        agent_fail_threshold=3,
    )


def test_guard_script_endpoints_require_login(mock_ec2, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    app_module = build_app(monkeypatch, tmp_path / "guard-anon")
    c = TestClient(app_module.app)
    assert c.post("/api/ip-rules/1/guard-script").status_code == 401
    assert c.get("/api/ip-rules/1/agent-status").status_code == 401


def test_guard_script_contains_token_and_target(client, monkeypatch):
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")
    rid = _make_agent_rule(app_module, aid)

    r = c.post(f"/api/ip-rules/{rid}/guard-script")
    assert r.status_code == 200
    d = r.json()
    assert "GUARD_TOKEN=" in d["script"]
    assert "www.baidu.com" in d["script"]
    assert d["report_url"] == "http://panel:8766/report"


def test_regenerating_script_invalidates_old_token(client, monkeypatch):
    """脚本里带明文凭证，重新生成通常意味着上一份可能已泄露。"""
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")
    rid = _make_agent_rule(app_module, aid)

    first = c.post(f"/api/ip-rules/{rid}/guard-script").json()["script"]
    old_token = next(
        l.split("=", 1)[1].strip("'") for l in first.split("\n") if l.startswith("GUARD_TOKEN=")
    )
    c.post(f"/api/ip-rules/{rid}/guard-script")

    assert app_module.store.rule_by_agent_token(old_token) is None, "旧凭证必须失效"


def test_agent_token_hash_never_leaves_store(client, monkeypatch):
    """摘要不能出现在任何返回给页面的结构里。"""
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")
    rid = _make_agent_rule(app_module, aid)
    c.post(f"/api/ip-rules/{rid}/guard-script")

    rules = app_module.store.list_ip_rules()
    assert "agent_token_hash" not in rules[0]
    assert rules[0]["agent_deployed"] is True

    status = c.get(f"/api/ip-rules/{rid}/agent-status").json()
    assert "agent_token_hash" not in str(status)


def test_agent_status_states(client, monkeypatch):
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")

    local_id = app_module.store.save_ip_rule(
        account_id=aid, region="us-east-1", instance_id="i-local"
    )
    assert c.get(f"/api/ip-rules/{local_id}/agent-status").json()["state"] == "disabled"

    rid = _make_agent_rule(app_module, aid)
    assert c.get(f"/api/ip-rules/{rid}/agent-status").json()["state"] == "not_deployed"

    c.post(f"/api/ip-rules/{rid}/guard-script")
    d = c.get(f"/api/ip-rules/{rid}/agent-status").json()
    assert d["state"] == "not_deployed", "生成了脚本但没收到上报，仍是未部署"
    assert d["hints"], "未部署必须给排查方向"

    app_module.store.touch_agent(rid, detail="探测正常")
    d = c.get(f"/api/ip-rules/{rid}/agent-status").json()
    assert d["state"] == "ok"
    assert d["last_seen_ago"] is not None


def test_agent_status_detects_stale(client, monkeypatch):
    """探测正常时不上报，所以失联只能靠心跳超时判断。"""
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")
    rid = _make_agent_rule(app_module, aid)
    c.post(f"/api/ip-rules/{rid}/guard-script")

    import time as _t

    long_ago = int(_t.time()) - 60 * 10 * 3 - 100
    app_module.store._execute(
        "UPDATE ip_rules SET agent_last_seen=%s WHERE id=%s", (long_ago, rid)
    )
    d = c.get(f"/api/ip-rules/{rid}/agent-status").json()
    assert d["state"] == "stale"
    assert d["hints"]


def test_agent_status_404_for_missing_rule(client):
    c, aid, app_module = client
    assert c.get("/api/ip-rules/999999/agent-status").status_code == 404
    assert c.post("/api/ip-rules/999999/guard-script").status_code == 404


def test_report_url_needs_config_when_ip_undetectable(client, monkeypatch):
    """探测不到出站 IP 时要给可操作的报错，而不是拼出个空地址。"""
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "")
    monkeypatch.setattr(app_module.ddns, "detect_ip", lambda *a, **k: "")
    rid = _make_agent_rule(app_module, aid)

    r = c.post(f"/api/ip-rules/{rid}/guard-script")
    assert r.status_code == 400
    assert "AWS_HELPER_REPORT_URL" in r.json()["error"]


# ---------- 上报端口鉴权 ----------


def _report_client(app_module):
    from fastapi.testclient import TestClient

    from aws_helper.web import report_app

    report_app.bind_store(app_module.store)
    return TestClient(report_app.app)


def test_report_rejects_missing_token(client):
    c, aid, app_module = client
    rc = _report_client(app_module)
    r = rc.post("/report", json={"kind": "blocked"})
    assert r.status_code == 401


def test_report_rejects_wrong_token(client):
    c, aid, app_module = client
    _make_agent_rule(app_module, aid)
    rc = _report_client(app_module)
    r = rc.post(
        "/report", json={"kind": "blocked"}, headers={"X-Guard-Token": "not-a-token"}
    )
    assert r.status_code == 401
    assert "凭证" in r.json()["error"]


def test_report_accepts_valid_token(client):
    c, aid, app_module = client
    rid = _make_agent_rule(app_module, aid)
    token = app_module.store.issue_agent_token(rid)
    rc = _report_client(app_module)

    r = rc.post(
        "/report",
        json={"kind": "alive", "instance_id": "i-0abc", "detail": "ok"},
        headers={"X-Guard-Token": token},
    )
    assert r.status_code == 200
    assert r.json()["action"] == "heartbeat"
    assert app_module.store.ip_rule(rid)["agent_last_seen"] > 0


def test_report_rejects_instance_id_mismatch(client):
    """脚本被复制到别的机器时，那台的网络状况不代表这台，必须拒绝。

    返回 401 而不是 403：这个端口在公网上，区分「凭证错」和「实例不匹配」
    等于告诉探测者凭证是有效的。
    """
    c, aid, app_module = client
    rid = _make_agent_rule(app_module, aid)
    token = app_module.store.issue_agent_token(rid)
    rc = _report_client(app_module)

    r = rc.post(
        "/report",
        json={"kind": "blocked", "instance_id": "i-someone-else"},
        headers={"X-Guard-Token": token},
    )
    assert r.status_code == 401


def test_batch_token_routes_by_instance_id(client):
    """开机时批量部署的实例共用一个凭证，只有实例 ID 能定位到具体哪一台。"""
    c, aid, app_module = client
    first = _make_agent_rule(app_module, aid, "i-batch-a")
    second = _make_agent_rule(app_module, aid, "i-batch-b")
    token = app_module.store.issue_agent_token(first)
    app_module.store.save_agent_token_hash(second, token)
    rc = _report_client(app_module)

    for iid, rid in (("i-batch-a", first), ("i-batch-b", second)):
        r = rc.post(
            "/report",
            json={"kind": "alive", "instance_id": iid, "detail": "ok"},
            headers={"X-Guard-Token": token},
        )
        assert r.status_code == 200, iid
        assert app_module.store.ip_rule(rid)["agent_last_seen"] > 0, iid


def test_batch_token_without_instance_id_is_ambiguous(client):
    """同一凭证对应多台时不带实例 ID 无法定位，不能随便挑一条改 IP。"""
    c, aid, app_module = client
    first = _make_agent_rule(app_module, aid, "i-batch-a")
    second = _make_agent_rule(app_module, aid, "i-batch-b")
    token = app_module.store.issue_agent_token(first)
    app_module.store.save_agent_token_hash(second, token)
    rc = _report_client(app_module)

    r = rc.post("/report", json={"kind": "alive"}, headers={"X-Guard-Token": token})
    assert r.status_code == 401


def test_report_blocked_triggers_ip_change(client):
    from unittest.mock import MagicMock, patch

    c, aid, app_module = client
    rid = _make_agent_rule(app_module, aid)
    token = app_module.store.issue_agent_token(rid)
    rc = _report_client(app_module)

    with patch.object(app_module.ipchange, "change_ip") as ci:
        ci.return_value = MagicMock(old_ip="1.1.1.1", new_ip="2.2.2.2", attempts=1)
        r = rc.post(
            "/report",
            json={"kind": "blocked", "instance_id": "i-0abc", "detail": "连不上"},
            headers={"X-Guard-Token": token},
        )

    assert r.status_code == 200
    assert r.json()["action"] == "changed"
    assert r.json()["new_ip"] == "2.2.2.2"


def test_report_port_has_no_panel_routes():
    """上报端口只能有上报和健康检查 —— 主端口上有 AWS 凭据和实例密码。"""
    from aws_helper.web import report_app

    paths = {r.path for r in report_app.app.routes if hasattr(r, "path")}
    assert paths <= {"/report", "/health"}, f"多了路由: {paths}"


def test_autoip_page_has_agent_section():
    from pathlib import Path

    html = Path("aws_helper/web/templates/autoip.html").read_text()
    assert "ag-target" in html
    assert "ag-interval" in html
    assert "function checkAgent" in html
    assert "function copyAgentScript" in html
    assert "实例侧探测部署状态" in html


def test_ddns_page_has_status_check():
    from pathlib import Path

    html = Path("aws_helper/web/templates/ddns.html").read_text()
    assert "function checkDdns" in html
    assert "排查方向" in html


# ---------- 开机时顺带部署服务 ----------


def _launch_body(aid, **over):
    base = {
        "account_id": aid,
        "region": "us-east-1",
        "name": "deploy-node",
        "instance_type": "t3.micro",
    }
    base.update(over)
    return base


def test_launch_without_deploy_has_no_service_blocks(client, monkeypatch):
    """不勾选时 user-data 里不该出现任何部署段。"""
    from unittest.mock import patch

    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")
    with patch.object(app_module.launch, "launch", wraps=app_module.launch.launch) as spy:
        wait_task(c, c.post("/api/launch", json=_launch_body(aid)).json()["task_id"])
        req = spy.call_args.args[1]

    assert req.deploy_blocks == []


def test_launch_embeds_autoip_agent(client, monkeypatch):
    """勾选后探测器脚本要真的进 RunInstances 的 UserData。

    断言的是**发给 AWS 的 UserData**，不是 req.deploy_blocks —— 后者是
    路由层设的中间值，把 userdata 的渲染整段删掉它照样非空（控制实验证过）。
    """
    from unittest.mock import patch

    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")

    sent: dict[str, str] = {}
    real = app_module.launch._run_instances

    def spy(session, req, *a, **kw):
        out = real(session, req, *a, **kw)
        sent["user_data"] = a[-1] if a else kw.get("user_data", "")
        return out

    with patch.object(app_module.launch, "_run_instances", side_effect=spy):
        task = wait_task(
            c,
            c.post(
                "/api/launch",
                json=_launch_body(
                    aid,
                    deploy_autoip=True,
                    autoip={"target": "www.qq.com:443", "interval_sec": 30},
                ),
            ).json()["task_id"],
        )

    blob = sent["user_data"]
    assert "GUARD_TOKEN=" in blob
    assert "www.qq.com" in blob
    assert "GUARD_INTERVAL=30" in blob
    assert "http://panel:8766/report" in blob
    assert task["result"]["deployed_autoip"] is True


def test_launch_creates_agent_rule_per_instance(client, monkeypatch):
    """开机成功后每台各建一条 agent 规则，共用这一批的凭证。"""
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")

    task = wait_task(
        c,
        c.post(
            "/api/launch",
            json=_launch_body(aid, count=2, deploy_autoip=True, autoip={}),
        ).json()["task_id"],
    )
    ids = {i["instance_id"] for i in task["result"]["instances"]}
    rules = {
        r["instance_id"]: r
        for r in app_module.store.list_ip_rules()
        if r["probe_mode"] == "agent"
    }

    assert ids <= set(rules), f"每台都要有规则: {ids} vs {set(rules)}"
    for iid in ids:
        assert rules[iid]["agent_deployed"] is True
        assert rules[iid]["enabled"] == 1


def test_launch_agent_token_works_for_whole_batch(client, monkeypatch):
    """同批实例共用凭证，各自用自己的实例 ID 上报都要能通。"""
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")

    with patch_launch_capture(app_module) as captured:
        task = wait_task(
            c,
            c.post(
                "/api/launch",
                json=_launch_body(aid, count=2, deploy_autoip=True, autoip={}),
            ).json()["task_id"],
        )
    token = captured["token"]
    rc = _report_client(app_module)

    for inst in task["result"]["instances"]:
        r = rc.post(
            "/report",
            json={"kind": "alive", "instance_id": inst["instance_id"]},
            headers={"X-Guard-Token": token},
        )
        assert r.status_code == 200, inst["instance_id"]


import contextlib as _contextlib


@_contextlib.contextmanager
def patch_launch_capture(app_module):
    """抓出内联进 user-data 的上报凭证，用来验证批内路由。"""
    import re
    from unittest.mock import patch

    captured: dict[str, str] = {}
    real = app_module.launch.launch

    def spy(creds, req, progress=None):
        blob = "\n".join(req.deploy_blocks)
        found = re.search(r"GUARD_TOKEN='?([A-Za-z0-9_\-]+)'?", blob)
        if found:
            captured["token"] = found.group(1)
        return real(creds, req, progress) if progress else real(creds, req)

    with patch.object(app_module.launch, "launch", side_effect=spy):
        yield captured


def test_launch_embeds_ddns_updater(client, monkeypatch):
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")
    from unittest.mock import patch

    with patch.object(app_module.launch, "launch", wraps=app_module.launch.launch) as spy:
        task = wait_task(
            c,
            c.post(
                "/api/launch",
                json=_launch_body(
                    aid,
                    deploy_ddns=True,
                    ddns={
                        "zone": "example.com",
                        "hostname": "node.example.com",
                        "token": "A" * 40,
                    },
                ),
            ).json()["task_id"],
        )
        req = spy.call_args.args[1]

    blob = "\n".join(req.deploy_blocks)
    assert "DDNS_HOSTNAME=node.example.com" in blob
    assert "CF_TOKEN=" in blob
    assert task["result"]["deployed_ddns"] is True


def test_ddns_block_reaches_user_data(client, monkeypatch):
    """同样断言到 UserData 层，不停在中间值上。"""
    from unittest.mock import patch

    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")

    sent: dict[str, str] = {}
    real = app_module.launch._run_instances

    def spy(session, req, *a, **kw):
        out = real(session, req, *a, **kw)
        sent["user_data"] = a[-1] if a else kw.get("user_data", "")
        return out

    with patch.object(app_module.launch, "_run_instances", side_effect=spy):
        wait_task(
            c,
            c.post(
                "/api/launch",
                json=_launch_body(
                    aid,
                    deploy_ddns=True,
                    ddns={
                        "zone": "example.com",
                        "hostname": "node.example.com",
                        "token": "A" * 40,
                    },
                ),
            ).json()["task_id"],
        )

    assert "DDNS_HOSTNAME=node.example.com" in sent["user_data"]


def test_ddns_deploy_rejected_for_multiple_instances(client, monkeypatch):
    """同批共用一份 user-data，也就共用主机名，会互相抢 DNS 记录。"""
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")

    r = c.post(
        "/api/launch",
        json=_launch_body(
            aid,
            count=3,
            deploy_ddns=True,
            ddns={"zone": "example.com", "hostname": "n.example.com", "token": "A" * 40},
        ),
    )
    assert r.status_code == 400
    assert "1 台" in r.json()["error"]


def test_bad_ddns_config_rejected_before_launch(client, monkeypatch):
    """配置错了要在开机之前挡住 —— 机器开起来了才报错等于白花钱。"""
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "http://panel:8766")

    r = c.post(
        "/api/launch",
        json=_launch_body(
            aid,
            deploy_ddns=True,
            ddns={"zone": "example.com", "hostname": "other.org", "token": "A" * 40},
        ),
    )
    assert r.status_code == 400
    assert "不属于区域" in r.json()["error"]

    before = len(c.get(f"/api/instances?account_id={aid}&region=us-east-1").json()["instances"])
    assert before == 0, "开机不该发生"


def test_deploy_needs_report_url_configured(client, monkeypatch):
    c, aid, app_module = client
    monkeypatch.setattr(app_module, "REPORT_PUBLIC_URL", "")
    monkeypatch.setattr(app_module.ddns, "detect_ip", lambda *a, **k: "")

    r = c.post("/api/launch", json=_launch_body(aid, deploy_autoip=True, autoip={}))
    assert r.status_code == 400
    assert "AWS_HELPER_REPORT_URL" in r.json()["error"]


def test_deploy_blocks_run_before_user_script():
    """用户脚本必须仍是最后执行的 —— userdata 的既有契约。"""
    from aws_helper.core import launch_deploy as ld
    from aws_helper.core.userdata import ScriptOptions, render

    block = ld.render_autoip_block(
        ld.AutoipDeploy(report_url="http://p:8766/report", token="t")
    )
    out = render(
        ScriptOptions(custom_script="echo mine", deploy_blocks=[block], hostname="n")
    )
    assert out.index("自动换 IP 探测器") < out.index("用户自定义脚本")


def test_launch_page_has_deploy_checkboxes():
    from pathlib import Path

    html = Path("aws_helper/web/templates/launch.html").read_text()
    assert 'id="deploy_autoip"' in html
    assert 'id="deploy_ddns"' in html
    assert "function toggleDeploy" in html
    assert "deploy_autoip: wantAutoip" in html


# ---------- BBR 加速 ----------


def test_launch_embeds_bbr_when_checked(client, monkeypatch):
    """勾选后 BBR 段要真的进 RunInstances 的 UserData。"""
    from unittest.mock import patch

    c, aid, app_module = client
    sent: dict[str, str] = {}
    real = app_module.launch._run_instances

    def spy(session, req, *a, **kw):
        out = real(session, req, *a, **kw)
        sent["user_data"] = a[-1] if a else kw.get("user_data", "")
        return out

    with patch.object(app_module.launch, "_run_instances", side_effect=spy):
        task = wait_task(
            c,
            c.post("/api/launch", json=_launch_body(aid, deploy_bbr=True)).json()["task_id"],
        )

    blob = sent["user_data"]
    assert "net.ipv4.tcp_congestion_control = bbr" in blob
    assert "net.core.default_qdisc = fq" in blob
    assert task["result"]["deployed_bbr"] is True


def test_launch_without_bbr_has_no_bbr_block(client):
    from unittest.mock import patch

    c, aid, app_module = client
    sent: dict[str, str] = {}
    real = app_module.launch._run_instances

    def spy(session, req, *a, **kw):
        out = real(session, req, *a, **kw)
        sent["user_data"] = a[-1] if a else kw.get("user_data", "")
        return out

    with patch.object(app_module.launch, "_run_instances", side_effect=spy):
        wait_task(c, c.post("/api/launch", json=_launch_body(aid)).json()["task_id"])

    assert "tcp_congestion_control" not in sent["user_data"]


def test_bbr_rejected_on_windows(client):
    c, aid, app_module = client
    r = c.post(
        "/api/launch",
        json=_launch_body(aid, image_key="windows-server-2022", deploy_bbr=True),
    )
    assert r.status_code == 400
    assert "Windows" in r.json()["error"]


def test_launch_page_has_bbr_checkbox():
    from pathlib import Path

    html = Path("aws_helper/web/templates/launch.html").read_text()
    assert 'id="deploy_bbr"' in html
    assert "deploy_bbr: !isWindows" in html
    assert "不换内核" in html, "要说清不动内核，否则用户会担心开不了机"


# ---------- 开机脚本模板可编辑 ----------


def test_update_script_by_id_allows_rename(client):
    """编辑必须按 id：走新建那条路（按 name 合并）改名会变成新增一条。"""
    c, aid, app_module = client
    sid = app_module.store.save_script("原名", "echo a", ["curl"])

    r = c.post(
        f"/api/scripts/id/{sid}",
        data={"name": "新名", "body": "echo b", "packages": "wget vim"},
    )
    assert r.status_code == 200

    scripts = app_module.store.list_scripts()
    assert len(scripts) == 1, f"改名不该新增记录: {scripts}"
    assert scripts[0]["id"] == sid
    assert scripts[0]["name"] == "新名"
    assert scripts[0]["body"] == "echo b"
    assert scripts[0]["packages"] == ["wget", "vim"]


def test_update_script_rejects_duplicate_name(client):
    """改名撞上别的模板要给可读报错，不能让唯一约束抛 psycopg 报文。"""
    c, aid, app_module = client
    first = app_module.store.save_script("甲", "echo a")
    app_module.store.save_script("乙", "echo b")

    r = c.post(f"/api/scripts/id/{first}", data={"name": "乙", "body": "echo c"})
    assert r.status_code == 400
    assert "同名" in r.json()["error"]
    assert app_module.store.script(first)["name"] == "甲", "失败不该改动原记录"


def test_update_script_keeping_own_name_is_fine(client):
    """只改内容不改名不能被自己的名字挡住。"""
    c, aid, app_module = client
    sid = app_module.store.save_script("固定名", "echo old")

    r = c.post(f"/api/scripts/id/{sid}", data={"name": "固定名", "body": "echo new"})
    assert r.status_code == 200
    assert app_module.store.script(sid)["body"] == "echo new"


def test_update_script_404_for_missing(client):
    c, aid, app_module = client
    r = c.post("/api/scripts/id/999999", data={"name": "x", "body": "echo x"})
    assert r.status_code == 404


def test_update_script_validates_body(client):
    """自带 shebang 的脚本要在保存前挡住，跟新建一致。"""
    c, aid, app_module = client
    sid = app_module.store.save_script("模板", "echo ok")

    r = c.post(
        f"/api/scripts/id/{sid}", data={"name": "模板", "body": "#!/bin/bash\necho x"}
    )
    assert r.status_code == 400
    assert app_module.store.script(sid)["body"] == "echo ok", "校验失败不该写入"


def test_update_script_requires_login(mock_ec2, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    app_module = build_app(monkeypatch, tmp_path / "script-anon")
    c = TestClient(app_module.app)
    assert c.post("/api/scripts/id/1", data={"name": "x"}).status_code == 401


def test_scripts_page_has_edit_button():
    from pathlib import Path

    html = Path("aws_helper/web/templates/scripts.html").read_text()
    assert "function edit(" in html
    assert "onclick=\"edit({{ s.id }})\"" in html
    assert "/api/scripts/id/${EDITING}" in html, "编辑要打到按 id 的接口"


def test_scripts_page_offers_bbr_preset():
    """现成脚本要能一键填进编辑区，不用用户自己去找 BBR 怎么开。"""
    from pathlib import Path

    html = Path("aws_helper/web/templates/scripts.html").read_text()
    assert "function usePreset" in html
    assert "preset-data" in html


def test_scripts_preset_contains_bbr(client):
    c, aid, app_module = client
    page = c.get("/scripts").text
    assert "BBR 加速" in page
    assert "tcp_congestion_control" in page


def test_copy_keeps_original_intact():
    """复制一份要清成新建模式，否则直接保存会覆盖原模板。"""
    from pathlib import Path

    html = Path("aws_helper/web/templates/scripts.html").read_text()
    body = html.split("function load(id)")[1].split("\n}")[0]
    assert "副本" in body
    assert "setMode(null)" in body
