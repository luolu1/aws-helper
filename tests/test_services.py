"""三类服务划分：EC2 / Lightsail / Bedrock。"""

from __future__ import annotations

import re
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


def test_bedrock_regions_from_official_and_sdk():
    """区域清单要取官方文档与 SDK endpoint 数据的并集。

    只靠手写会随 AWS 开新区域过期；只靠 botocore 会滞后 ——
    实测 af-south-1 / eu-north-1 / ap-northeast-3 能返回模型清单，
    但当前 botocore 版本未收录。
    """
    regions = bedrock.supported_regions()

    assert len(regions) >= 30, f"官方文档有 30+ 商业区域，实际 {len(regions)}"
    for name in ("us-east-1", "us-west-2", "eu-central-1", "sa-east-1"):
        assert name in regions, name
    # botocore 未收录但实测可用的，不能漏
    for name in ("af-south-1", "eu-north-1", "ap-northeast-3"):
        assert name in regions, f"{name} 实测可用却未列出"


def test_bedrock_regions_exclude_hongkong():
    """香港没有 Bedrock 端点，列出来只会让用户选了报错。"""
    assert "ap-east-1" not in bedrock.supported_regions()


def test_bedrock_regions_exclude_govcloud():
    """GovCloud 需要单独准入流程，普通账号选了必然失败。"""
    assert not [r for r in bedrock.supported_regions() if r.startswith("us-gov-")]


def test_bedrock_regions_all_have_chinese_labels():
    for name, label in bedrock.supported_regions().items():
        assert label != name, f"{name} 缺中文名"
        assert any("\u4e00" <= ch <= "\u9fff" for ch in label), name


def test_bedrock_regions_survive_botocore_failure(monkeypatch):
    """botocore 取不到数据时要退回官方文档清单，不能返回空。"""
    import botocore.session

    def boom():
        raise RuntimeError("no endpoint data")

    monkeypatch.setattr(botocore.session, "get_session", boom)
    regions = bedrock.supported_regions()
    assert len(regions) >= 30
    assert "us-east-1" in regions


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
    """解析不到配置文件时要说清是「该区域没有对应配置文件」，而不是笼统报错。"""
    from botocore.exceptions import ClientError

    with patch.object(bedrock, "runtime_client") as runtime, patch.object(
        bedrock, "control_client"
    ) as control:
        runtime.return_value.converse.side_effect = ClientError(
            {"Error": {"Code": "ValidationException",
                       "Message": "Invocation of model ID m with on-demand throughput isn't supported."}},
            "Converse",
        )
        control.return_value.list_inference_profiles.return_value = {
            "inferenceProfileSummaries": []
        }
        with pytest.raises(bedrock.BedrockError, match="没有它对应的配置文件"):
            bedrock.invoke_text(
                aws.Credentials("a", "b", "sa-east-1"), "sa-east-1", "m", "q"
            )


def _profile_page(pairs, next_token=None):
    summaries = [
        {
            "inferenceProfileId": profile_id,
            "inferenceProfileArn": f"arn:aws:bedrock:us-east-1:1:inference-profile/{profile_id}",
            "type": "SYSTEM_DEFINED",
            "status": "ACTIVE",
            "models": [
                {"modelArn": f"arn:aws:bedrock:us-east-1::foundation-model/{base}"}
            ],
        }
        for profile_id, base in pairs
    ]
    page = {"inferenceProfileSummaries": summaries}
    if next_token:
        page["nextToken"] = next_token
    return page


OPUS = "anthropic.claude-opus-4-1-20250805-v1:0"


def test_inference_profiles_indexes_base_model_to_profile_ids():
    """list_inference_profiles 的 models[].modelArn 要正确切出基础模型 id。"""
    with patch.object(bedrock, "control_client") as control:
        control.return_value.list_inference_profiles.return_value = _profile_page(
            [(f"us.{OPUS}", OPUS), (f"global.{OPUS}", OPUS)]
        )
        index = bedrock.inference_profiles(aws.Credentials("a", "b", "us-east-1"), "us-east-1")

    assert index == {OPUS: [f"us.{OPUS}", f"global.{OPUS}"]}


def test_inference_profiles_follows_pagination():
    """配置文件清单是分页的，只读第一页会漏掉后面的模型。"""
    pages = [
        _profile_page([(f"us.{OPUS}", OPUS)], next_token="t1"),
        _profile_page([("us.meta.llama-x", "meta.llama-x")]),
    ]
    with patch.object(bedrock, "control_client") as control:
        control.return_value.list_inference_profiles.side_effect = pages
        index = bedrock.inference_profiles(aws.Credentials("a", "b", "us-east-1"), "us-east-1")

    assert set(index) == {OPUS, "meta.llama-x"}


def test_inference_profiles_requests_only_system_defined():
    """APPLICATION 类型是用户自建的计量配置文件，不该混进模型选择列表。"""
    with patch.object(bedrock, "control_client") as control:
        control.return_value.list_inference_profiles.return_value = _profile_page([])
        bedrock.inference_profiles(aws.Credentials("a", "b", "us-east-1"), "us-east-1")
        kwargs = control.return_value.list_inference_profiles.call_args.kwargs

    assert kwargs["typeEquals"] == "SYSTEM_DEFINED"


def test_inference_profiles_survives_missing_permission():
    """缺 ListInferenceProfiles 权限时返回空索引，不能让模型清单页整个挂掉。"""
    from botocore.exceptions import ClientError

    with patch.object(bedrock, "control_client") as control:
        control.return_value.list_inference_profiles.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
            "ListInferenceProfiles",
        )
        assert bedrock.inference_profiles(aws.Credentials("a", "b", "us-east-1"), "us-east-1") == {}


def test_inference_profiles_stops_on_repeated_token():
    """服务端回同一个 nextToken 时必须停下。

    照着 token 一直翻页会无限循环，把处理请求的线程钉死 —— 页面永远转圈。
    """
    page = _profile_page([(f"us.{OPUS}", OPUS)], next_token="same")
    with patch.object(bedrock, "control_client") as control:
        control.return_value.list_inference_profiles.return_value = page
        index = bedrock.inference_profiles(aws.Credentials("a", "b", "us-east-1"), "us-east-1")

    assert index == {OPUS: [f"us.{OPUS}"]}
    assert control.return_value.list_inference_profiles.call_count == 2


def test_inference_profiles_ignores_non_dict_response():
    """SDK 返回非字典（旧版本、被 mock 掉）时安全退出，而不是拿它当分页游标。"""
    with patch.object(bedrock, "control_client") as control:
        control.return_value.list_inference_profiles.return_value = None
        assert bedrock.inference_profiles(aws.Credentials("a", "b", "us-east-1"), "us-east-1") == {}


def test_resolve_invoke_id_prefers_caller_region_geo():
    """同一模型有多个配置文件时，优先用与调用区域同地理组的，避免绕远。"""
    index = {OPUS: [f"apac.{OPUS}", f"eu.{OPUS}", f"us.{OPUS}"]}
    model = {"model_id": OPUS, "inference_types": ["INFERENCE_PROFILE"]}

    assert bedrock.resolve_invoke_id(model, "us-west-2", index) == f"us.{OPUS}"
    assert bedrock.resolve_invoke_id(model, "eu-west-1", index) == f"eu.{OPUS}"
    assert bedrock.resolve_invoke_id(model, "ap-northeast-1", index) == f"apac.{OPUS}"


def test_resolve_invoke_id_falls_back_to_global_profile():
    """本地理组没有配置文件时用 global —— 它覆盖全部商业区域。"""
    index = {OPUS: [f"global.{OPUS}"]}
    model = {"model_id": OPUS, "inference_types": ["INFERENCE_PROFILE"]}

    assert bedrock.resolve_invoke_id(model, "sa-east-1", index) == f"global.{OPUS}"


def test_resolve_invoke_id_keeps_base_id_for_on_demand():
    model = {"model_id": "anthropic.claude-3-haiku", "inference_types": ["ON_DEMAND"]}
    assert (
        bedrock.resolve_invoke_id(model, "us-east-1", {})
        == "anthropic.claude-3-haiku"
    )


def test_resolve_invoke_id_guesses_prefix_without_index():
    """没有配置文件索引时按区域前缀猜一个。

    猜错只是 converse 报错；直接把模型藏起来不让测才是真的没法用。
    """
    model = {"model_id": OPUS, "inference_types": ["INFERENCE_PROFILE"]}
    assert bedrock.resolve_invoke_id(model, "us-east-1", {}) == f"us.{OPUS}"


def test_resolve_invoke_id_empty_when_region_has_no_geo():
    """南美等区域没有对应地理前缀，猜不出来就明确返回空，别编一个假 id。"""
    model = {"model_id": OPUS, "inference_types": ["INFERENCE_PROFILE"]}
    assert bedrock.resolve_invoke_id(model, "sa-east-1", {}) == ""


def test_list_models_marks_profile_only_model_invokable():
    """只支持推理配置文件的模型必须标成可调用，并带上配置文件 id。

    这是用户报的问题：Claude Opus 4/4.1 这类模型被过滤掉了，根本测不了。
    """
    fake = {"modelSummaries": [
        {"modelId": OPUS, "modelName": "Claude Opus 4.1",
         "providerName": "Anthropic", "inputModalities": ["TEXT"],
         "outputModalities": ["TEXT"], "responseStreamingSupported": True,
         "inferenceTypesSupported": ["INFERENCE_PROFILE"],
         "modelLifecycle": {"status": "ACTIVE"}},
    ]}
    with patch.object(bedrock, "control_client") as control:
        control.return_value.list_foundation_models.return_value = fake
        control.return_value.list_inference_profiles.return_value = _profile_page(
            [(f"us.{OPUS}", OPUS)]
        )
        out = bedrock.list_models(aws.Credentials("a", "b", "us-east-1"), "us-east-1")

    model = out["models"][0]
    assert model["invokable"] is True
    assert model["via_profile"] is True
    assert model["invoke_id"] == f"us.{OPUS}"


def test_list_models_skips_profile_lookup_when_all_on_demand():
    """全是按需模型时不该白调一次 ListInferenceProfiles。"""
    fake = {"modelSummaries": [
        {"modelId": "anthropic.claude-3-haiku", "modelName": "Haiku",
         "providerName": "Anthropic", "inputModalities": ["TEXT"],
         "outputModalities": ["TEXT"],
         "inferenceTypesSupported": ["ON_DEMAND"],
         "modelLifecycle": {"status": "ACTIVE"}},
    ]}
    with patch.object(bedrock, "control_client") as control:
        control.return_value.list_foundation_models.return_value = fake
        out = bedrock.list_models(aws.Credentials("a", "b", "us-east-1"), "us-east-1")
        assert control.return_value.list_inference_profiles.call_count == 0

    assert out["models"][0]["invoke_id"] == "anthropic.claude-3-haiku"
    assert out["models"][0]["via_profile"] is False


def test_invoke_retries_with_profile_id_on_on_demand_rejection():
    """用户粘贴裸的基础 id 时，自动换成配置文件 id 重试一次。"""
    from botocore.exceptions import ClientError

    ok = {
        "output": {"message": {"content": [{"text": "来自 Opus"}]}},
        "usage": {"inputTokens": 7, "outputTokens": 3},
        "stopReason": "end_turn",
        "metrics": {"latencyMs": 900},
    }
    rejection = ClientError(
        {"Error": {"Code": "ValidationException",
                   "Message": f"Invocation of model ID {OPUS} with on-demand "
                              "throughput isn't supported."}},
        "Converse",
    )
    with patch.object(bedrock, "runtime_client") as runtime, patch.object(
        bedrock, "control_client"
    ) as control:
        runtime.return_value.converse.side_effect = [rejection, ok]
        control.return_value.list_inference_profiles.return_value = _profile_page(
            [(f"us.{OPUS}", OPUS)]
        )
        out = bedrock.invoke_text(
            aws.Credentials("a", "b", "us-east-1"), "us-east-1", OPUS, "问题"
        )

    assert out["text"] == "来自 Opus"
    assert out["model_id"] == f"us.{OPUS}"
    assert out["requested_model_id"] == OPUS
    assert out["via_profile"] is True
    second_call = runtime.return_value.converse.call_args_list[1]
    assert second_call.kwargs["modelId"] == f"us.{OPUS}"


def test_invoke_retries_when_error_code_is_http_status():
    """botocore 有时把错误码报成 "400" 而不是 ValidationException。

    真机验证时就是这样：只按 code == "ValidationException" 判断会漏掉重试，
    用户拿裸 id 测 Opus 直接报错。所以以报文文案为主、错误码为辅。
    """
    from botocore.exceptions import ClientError

    ok = {
        "output": {"message": {"content": [{"text": "成功"}]}},
        "usage": {"inputTokens": 1, "outputTokens": 1},
        "stopReason": "end_turn",
        "metrics": {"latencyMs": 10},
    }
    rejection = ClientError(
        {"Error": {"Code": "400",
                   "Message": f"An error occurred (400) when calling the Converse "
                              f"operation: Invocation of model ID {OPUS} with "
                              "on-demand throughput isn't supported."}},
        "Converse",
    )
    with patch.object(bedrock, "runtime_client") as runtime, patch.object(
        bedrock, "control_client"
    ) as control:
        runtime.return_value.converse.side_effect = [rejection, ok]
        control.return_value.list_inference_profiles.return_value = _profile_page(
            [(f"us.{OPUS}", OPUS)]
        )
        out = bedrock.invoke_text(
            aws.Credentials("a", "b", "us-east-1"), "us-east-1", OPUS, "问题"
        )

    assert out["model_id"] == f"us.{OPUS}"
    assert out["via_profile"] is True


def test_invoke_reports_retry_failure_with_profile_id():
    """换配置文件后仍失败时，报错要带上实际用的那个 id，方便排查。"""
    from botocore.exceptions import ClientError

    rejection = ClientError(
        {"Error": {"Code": "ValidationException",
                   "Message": "with on-demand throughput isn't supported."}},
        "Converse",
    )
    denied = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "not subscribed"}},
        "Converse",
    )
    with patch.object(bedrock, "runtime_client") as runtime, patch.object(
        bedrock, "control_client"
    ) as control:
        runtime.return_value.converse.side_effect = [rejection, denied]
        control.return_value.list_inference_profiles.return_value = _profile_page(
            [(f"us.{OPUS}", OPUS)]
        )
        with pytest.raises(bedrock.BedrockError, match=f"us.{re.escape(OPUS)}"):
            bedrock.invoke_text(
                aws.Credentials("a", "b", "us-east-1"), "us-east-1", OPUS, "问题"
            )


def test_probe_reports_profile_only_models():
    """探测要说明有多少只支持配置文件的模型、解析到几个可调用。"""
    fake = {"modelSummaries": [
        {"modelId": OPUS, "modelName": "Opus", "providerName": "Anthropic",
         "inputModalities": ["TEXT"], "outputModalities": ["TEXT"],
         "inferenceTypesSupported": ["INFERENCE_PROFILE"],
         "modelLifecycle": {"status": "ACTIVE"}},
    ]}
    with patch.object(bedrock, "control_client") as control:
        control.return_value.list_foundation_models.return_value = fake
        control.return_value.list_inference_profiles.return_value = _profile_page(
            [(f"us.{OPUS}", OPUS)]
        )
        result = bedrock.probe(aws.Credentials("a", "b", "us-east-1"), "us-east-1")

    check = [c for c in result["checks"] if c["name"] == "推理配置文件"]
    assert check and check[0]["ok"] is True
    assert "1 个可直接调用" in check[0]["detail"]


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
