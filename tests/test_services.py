"""三类服务划分：EC2 / Lightsail / Bedrock。"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from aws_helper.core import aws, bedrock, lightsail

from .test_web import build_app, login


@pytest.fixture
def panel(mock_ec2, ubuntu_ami, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "svc")
    client = TestClient(app_module.app)
    login(client)
    account_id = app_module.store.add_account("t", "testing", "testing", "us-east-1")
    return client, account_id, app_module


# ---------- 导航分栏 ----------


@pytest.mark.parametrize(
    "path,label",
    [
        ("/", "实例"),
        ("/launch", "一键开机"),
        ("/scripts", "开机脚本"),
        ("/autoip", "自动换 IP"),
        ("/lightsail", "轻量实例"),
        ("/lightsail/create", "创建实例"),
        ("/bedrock", "模型清单"),
        ("/bedrock/playground", "调用测试"),
        ("/accounts", "账号 / 日志"),
        ("/profile", "用户面板"),
    ],
)
def test_current_page_highlighted_in_sidebar(panel, path, label):
    """当前页在侧边栏要高亮，否则用户不知道自己在哪一栏。"""
    import re

    c, _, _ = panel
    html = c.get(path).text
    pattern = re.compile(
        r'<a href="[^"]*"\s+class="[^"]*\bon\b[^"]*">' + re.escape(label) + r"</a>"
    )
    assert pattern.search(html), f"{path} 的「{label}」未高亮"


def test_sidebar_groups_three_services(panel):
    """三个服务作为大类分组标题，功能作为子项挂在下面。"""
    c, _, _ = panel
    html = c.get("/").text

    for title in ("EC2", "Lightsail", "Bedrock", "通用"):
        assert f'class="nav-group-title">{title}' in html, title

    assert html.count('class="nav-group"') == 4


def test_sidebar_shows_all_entries_on_every_page(panel):
    """侧边栏是全局目录，任何页面都能直接跳到其他服务。

    原来的二级导航只显示当前服务的子项，跨服务要先点主栏再点子项。
    """
    c, _, _ = panel
    entries = [
        "实例", "一键开机", "开机脚本", "自动换 IP",
        "轻量实例", "创建实例",
        "模型清单", "调用测试",
        "账号 / 日志", "用户面板",
    ]
    for path in ("/", "/lightsail", "/bedrock", "/accounts"):
        html = c.get(path).text
        for entry in entries:
            assert f">{entry}</a>" in html, f"{path} 缺少 {entry}"


def test_layout_uses_sidebar_not_topnav(panel):
    """布局要是左侧目录 + 右侧内容，旧的顶部服务栏和二级导航条应已移除。"""
    c, _, _ = panel
    html = c.get("/").text

    assert 'class="layout"' in html
    assert 'class="sidebar"' in html
    assert 'class="subnav"' not in html
    assert 'class="svc ' not in html


def test_sidebar_collapsible_on_narrow_screen(panel):
    c, _, _ = panel
    html = c.get("/").text
    assert "menu-toggle" in html
    assert "toggleSidebar" in html


def test_service_pages_require_login(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "anon-svc")
    c = TestClient(app_module.app)
    for path in ("/lightsail", "/lightsail/create", "/bedrock", "/bedrock/playground"):
        resp = c.get(path, follow_redirects=False)
        assert resp.status_code == 302, path


# ---------- Lightsail ----------


def test_lightsail_bundles_parsed():
    """套餐要带出流量额度 —— Lightsail 是打包定价，流量是关键差异项。"""
    fake = {
        "bundles": [
            {
                "bundleId": "nano_3_1", "price": 5.0, "cpuCount": 2,
                "ramSizeInGb": 0.5, "diskSizeInGb": 20,
                "transferPerMonthInGb": 512, "isActive": True,
            },
            {
                "bundleId": "nano_win_3_1", "price": 9.5, "cpuCount": 2,
                "ramSizeInGb": 0.5, "diskSizeInGb": 30,
                "transferPerMonthInGb": 512, "isActive": True,
            },
        ]
    }
    with patch.object(lightsail, "client") as factory:
        factory.return_value.get_bundles.return_value = fake
        out = lightsail.list_bundles(
            aws.Credentials("a", "b", "us-east-1"), "us-east-1"
        )

    assert len(out) == 2
    linux = [b for b in out if b["platform"] == "linux"][0]
    assert linux["transfer_gb"] == 512
    assert "512 GB 流量" in linux["label"]
    # Linux 排在 Windows 前面，价格升序
    assert out[0]["platform"] == "linux"


def test_lightsail_detects_windows_bundles():
    """Windows 套餐要能识别出来，否则会配错蓝图。"""
    fake = {"bundles": [
        {"bundleId": "nano_win_3_1", "price": 9.5, "cpuCount": 2,
         "ramSizeInGb": 0.5, "diskSizeInGb": 30, "transferPerMonthInGb": 512},
    ]}
    with patch.object(lightsail, "client") as factory:
        factory.return_value.get_bundles.return_value = fake
        out = lightsail.list_bundles(aws.Credentials("a", "b", "us-east-1"), "us-east-1")
    assert out[0]["platform"] == "windows"


def test_lightsail_blueprints_split_os_and_app():
    fake = {"blueprints": [
        {"blueprintId": "ubuntu_24_04", "name": "Ubuntu", "version": "24.04",
         "type": "os", "platform": "LINUX_UNIX", "isActive": True},
        {"blueprintId": "wordpress", "name": "WordPress", "version": "6",
         "type": "app", "platform": "LINUX_UNIX", "isActive": True},
        {"blueprintId": "windows_server_2022", "name": "Windows Server 2022",
         "version": "", "type": "os", "platform": "WINDOWS", "isActive": True},
    ]}
    with patch.object(lightsail, "client") as factory:
        factory.return_value.get_blueprints.return_value = fake
        out = lightsail.list_blueprints(
            aws.Credentials("a", "b", "us-east-1"), "us-east-1"
        )

    assert len(out["os"]) == 2
    assert len(out["app"]) == 1
    win = [b for b in out["os"] if b["platform"] == "windows"]
    assert win, "Windows 蓝图的 platform 要小写归一"


def test_lightsail_delete_releases_static_ips():
    """删除实例要释放静态 IP —— 未附加的静态 IP 按月计费。"""
    calls: list[str] = []

    class Session:
        def get_static_ips(self):
            return {"staticIps": [
                {"name": "sip-1", "ipAddress": "1.2.3.4",
                 "attachedTo": "web", "isAttached": True},
                {"name": "sip-2", "ipAddress": "5.6.7.8",
                 "attachedTo": "other", "isAttached": True},
            ]}

        def detach_static_ip(self, staticIpName):
            calls.append(f"detach:{staticIpName}")

        def release_static_ip(self, staticIpName):
            calls.append(f"release:{staticIpName}")

        def delete_instance(self, instanceName):
            calls.append(f"delete:{instanceName}")

    with patch.object(lightsail, "client", return_value=Session()):
        result = lightsail.power(
            aws.Credentials("a", "b", "us-east-1"), "us-east-1", "delete", ["web"]
        )

    assert "1.2.3.4" in result["released_static_ips"]
    assert "release:sip-1" in calls
    # 别的实例的静态 IP 不能动
    assert "release:sip-2" not in calls


def test_lightsail_rejects_unknown_action():
    with pytest.raises(lightsail.LightsailError, match="不支持的操作"):
        lightsail.power(
            aws.Credentials("a", "b", "us-east-1"), "us-east-1", "explode", ["x"]
        )


def test_lightsail_create_validates_input():
    creds = aws.Credentials("a", "b", "us-east-1")
    with pytest.raises(lightsail.LightsailError, match="名称必填"):
        lightsail.create_instance(creds, "us-east-1", "  ", "nano_3_1", "ubuntu_24_04")
    with pytest.raises(lightsail.LightsailError, match="请选择套餐"):
        lightsail.create_instance(creds, "us-east-1", "n", "", "ubuntu_24_04")
    with pytest.raises(lightsail.LightsailError, match="请选择蓝图"):
        lightsail.create_instance(creds, "us-east-1", "n", "nano_3_1", "")


def test_lightsail_catalog_rejects_unsupported_region(panel):
    """Lightsail 支持的区域比 EC2 少，选到不支持的要明确提示。"""
    c, aid, _ = panel
    with patch.object(
        lightsail, "available_regions", return_value=["us-east-1", "eu-west-1"]
    ):
        resp = c.get(f"/api/lightsail/catalog?account_id={aid}&region=ap-east-1")
    assert resp.status_code == 400
    assert "不支持 Lightsail" in resp.json()["error"]


def test_lightsail_static_ip_marks_idle():
    fake = {"staticIps": [
        {"name": "a", "ipAddress": "1.1.1.1", "attachedTo": "web", "isAttached": True},
        {"name": "b", "ipAddress": "2.2.2.2", "isAttached": False},
    ]}
    with patch.object(lightsail, "client") as factory:
        factory.return_value.get_static_ips.return_value = fake
        out = lightsail.list_static_ips(
            aws.Credentials("a", "b", "us-east-1"), "us-east-1"
        )
    assert out[0]["idle"] is False
    assert out[1]["idle"] is True


# ---------- Bedrock ----------


def test_bedrock_regions_exclude_unavailable():
    """ap-east-1 实测没有 Bedrock 端点，不能列进去让用户选。"""
    assert "ap-east-1" not in bedrock.REGIONS
    assert "us-east-1" in bedrock.REGIONS


def test_bedrock_models_parsed():
    fake = {"modelSummaries": [
        {"modelId": "anthropic.claude-x", "modelName": "Claude",
         "providerName": "Anthropic", "inputModalities": ["TEXT"],
         "outputModalities": ["TEXT"], "responseStreamingSupported": True,
         "inferenceTypesSupported": ["ON_DEMAND"],
         "modelLifecycle": {"status": "ACTIVE"}},
        {"modelId": "old.model", "modelName": "Old", "providerName": "X",
         "inputModalities": ["TEXT"], "outputModalities": ["TEXT"],
         "inferenceTypesSupported": ["INFERENCE_PROFILE"],
         "modelLifecycle": {"status": "LEGACY"}},
    ]}
    with patch.object(bedrock, "control_client") as factory:
        factory.return_value.list_foundation_models.return_value = fake
        out = bedrock.list_models(aws.Credentials("a", "b", "us-east-1"), "us-east-1")

    assert out["total"] == 2
    assert out["by_provider"]["Anthropic"] == 1
    legacy = [m for m in out["models"] if m["legacy"]]
    assert len(legacy) == 1
    assert legacy[0]["model_id"] == "old.model"


def test_bedrock_missing_endpoint_gives_actionable_error():
    """区域没有 Bedrock 端点时要提示换区域，而不是抛原始网络错误。"""
    from botocore.exceptions import EndpointConnectionError

    with patch.object(bedrock, "control_client") as factory:
        factory.return_value.list_foundation_models.side_effect = (
            EndpointConnectionError(endpoint_url="https://bedrock.ap-east-1.amazonaws.com")
        )
        with pytest.raises(bedrock.BedrockError, match="没有 Bedrock 服务端点"):
            bedrock.list_models(aws.Credentials("a", "b", "ap-east-1"), "ap-east-1")


def test_bedrock_access_denied_names_permission():
    from botocore.exceptions import ClientError

    with patch.object(bedrock, "control_client") as factory:
        factory.return_value.list_foundation_models.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListFoundationModels",
        )
        with pytest.raises(bedrock.BedrockError, match="ListFoundationModels"):
            bedrock.list_models(aws.Credentials("a", "b", "us-east-1"), "us-east-1")


def test_bedrock_invoke_validates_input():
    creds = aws.Credentials("a", "b", "us-east-1")
    with pytest.raises(bedrock.BedrockError, match="请选择模型"):
        bedrock.invoke_text(creds, "us-east-1", "", "hi")
    with pytest.raises(bedrock.BedrockError, match="请输入提示词"):
        bedrock.invoke_text(creds, "us-east-1", "m", "   ")


def test_bedrock_invoke_parses_converse_response():
    fake = {
        "output": {"message": {"content": [{"text": "答案"}]}},
        "usage": {"inputTokens": 12, "outputTokens": 5},
        "stopReason": "end_turn",
        "metrics": {"latencyMs": 420},
    }
    with patch.object(bedrock, "runtime_client") as factory:
        factory.return_value.converse.return_value = fake
        out = bedrock.invoke_text(
            aws.Credentials("a", "b", "us-east-1"), "us-east-1", "m", "问题"
        )
    assert out["text"] == "答案"
    assert out["input_tokens"] == 12
    assert out["latency_ms"] == 420


def test_bedrock_model_access_error_is_actionable():
    """没申请模型访问权限时要指出去哪开通。"""
    from botocore.exceptions import ClientError

    with patch.object(bedrock, "runtime_client") as factory:
        factory.return_value.converse.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "Converse",
        )
        with pytest.raises(bedrock.BedrockError, match="模型访问"):
            bedrock.invoke_text(
                aws.Credentials("a", "b", "us-east-1"), "us-east-1", "m", "q"
            )


def test_bedrock_on_demand_error_explains_alternative():
    from botocore.exceptions import ClientError

    with patch.object(bedrock, "runtime_client") as factory:
        factory.return_value.converse.side_effect = ClientError(
            {"Error": {"Code": "ValidationException",
                       "Message": "not supported for on-demand throughput"}},
            "Converse",
        )
        with pytest.raises(bedrock.BedrockError, match="推理配置文件"):
            bedrock.invoke_text(
                aws.Credentials("a", "b", "us-east-1"), "us-east-1", "m", "q"
            )


def test_bedrock_probe_reports_unavailable():
    from botocore.exceptions import EndpointConnectionError

    with patch.object(bedrock, "control_client") as factory:
        factory.return_value.list_foundation_models.side_effect = (
            EndpointConnectionError(endpoint_url="https://x")
        )
        result = bedrock.probe(aws.Credentials("a", "b", "ap-east-1"), "ap-east-1")
    assert result["available"] is False
    assert result["checks"][0]["ok"] is False


def test_bedrock_probe_counts_on_demand():
    fake = {"modelSummaries": [
        {"modelId": "a", "providerName": "P", "outputModalities": ["TEXT"],
         "inferenceTypesSupported": ["ON_DEMAND"],
         "modelLifecycle": {"status": "ACTIVE"}},
        {"modelId": "b", "providerName": "P", "outputModalities": ["TEXT"],
         "inferenceTypesSupported": ["INFERENCE_PROFILE"],
         "modelLifecycle": {"status": "ACTIVE"}},
    ]}
    with patch.object(bedrock, "control_client") as factory:
        factory.return_value.list_foundation_models.return_value = fake
        result = bedrock.probe(aws.Credentials("a", "b", "us-east-1"), "us-east-1")

    assert result["available"] is True
    assert result["total"] == 2
    on_demand = [c for c in result["checks"] if c["name"] == "按需可调用模型"][0]
    assert "1 个" in on_demand["detail"]


def test_bedrock_endpoints_require_login(mock_ec2, monkeypatch, tmp_path):
    app_module = build_app(monkeypatch, tmp_path / "bd-anon")
    c = TestClient(app_module.app)
    assert c.get("/api/bedrock/models?account_id=1&region=us-east-1").status_code == 401
    assert c.get("/api/bedrock/probe?account_id=1&region=us-east-1").status_code == 401
