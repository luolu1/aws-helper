"""Bedrock：基础模型清单、访问状态、调用测试。

Bedrock 是纯 API 服务，没有实例概念 —— 不需要开机/换 IP/清理资源。
面板这一栏做的是：看有哪些模型、确认权限是否开通、试跑一次推理。

区域可用性差异很大（实测 us-east-1 有 121 个模型，ap-east-1 完全没有
Bedrock endpoint），所以区域选择要独立于 EC2。
"""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError, EndpointConnectionError

from . import aws

# Bedrock 未在所有区域开放，列出实测可用的主力区域
REGIONS: dict[str, str] = {
    "us-east-1": "美国东部（弗吉尼亚北部）",
    "us-west-2": "美国西部（俄勒冈）",
    "ap-northeast-1": "亚太（东京）",
    "ap-southeast-1": "亚太（新加坡）",
    "ap-southeast-2": "亚太（悉尼）",
    "ap-south-1": "亚太（孟买）",
    "eu-central-1": "欧洲（法兰克福）",
    "eu-west-1": "欧洲（爱尔兰）",
    "eu-west-3": "欧洲（巴黎）",
    "ca-central-1": "加拿大（中部）",
    "sa-east-1": "南美（圣保罗）",
}


class BedrockError(RuntimeError):
    """Bedrock 操作失败。"""


def control_client(creds: aws.Credentials, region: str) -> Any:
    return aws.client("bedrock", creds, region)


def runtime_client(creds: aws.Credentials, region: str) -> Any:
    return aws.client("bedrock-runtime", creds, region)


def list_models(creds: aws.Credentials, region: str) -> dict[str, Any]:
    """列出该区域的基础模型，按厂商分组。

    modelLifecycle.status 为 LEGACY 的模型 AWS 已计划下线，标出来避免
    用户选了之后突然不可用。
    """
    try:
        resp = control_client(creds, region).list_foundation_models()
    except EndpointConnectionError as exc:
        raise BedrockError(
            f"{region} 没有 Bedrock 服务端点，请换区域（如 us-east-1）"
        ) from exc
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "UnrecognizedClientException"):
            raise BedrockError(
                f"没有 Bedrock 权限（{code}），需要 bedrock:ListFoundationModels"
            ) from exc
        raise BedrockError(f"查询模型失败: {exc}") from exc

    models: list[dict[str, Any]] = []
    for item in resp.get("modelSummaries", []):
        lifecycle = (item.get("modelLifecycle") or {}).get("status", "")
        modalities = item.get("outputModalities") or []
        models.append(
            {
                "model_id": item.get("modelId", ""),
                "name": item.get("modelName", ""),
                "provider": item.get("providerName", ""),
                "input_modalities": item.get("inputModalities") or [],
                "output_modalities": modalities,
                "streaming": bool(item.get("responseStreamingSupported")),
                "inference_types": item.get("inferenceTypesSupported") or [],
                "lifecycle": lifecycle,
                "legacy": lifecycle == "LEGACY",
                "text_capable": "TEXT" in modalities,
            }
        )

    by_provider: dict[str, int] = {}
    for model in models:
        by_provider[model["provider"]] = by_provider.get(model["provider"], 0) + 1

    models.sort(key=lambda m: (m["provider"], m["model_id"]))
    return {
        "region": region,
        "models": models,
        "total": len(models),
        "by_provider": dict(sorted(by_provider.items(), key=lambda kv: -kv[1])),
    }


def invoke_text(
    creds: aws.Credentials,
    region: str,
    model_id: str,
    prompt: str,
    max_tokens: int = 256,
) -> dict[str, Any]:
    """用 Converse API 试跑一次文本推理。

    Converse 是 Bedrock 的统一入口，各厂商模型的请求体格式不同
    （Anthropic 要 anthropic_version、Amazon 要 inputText），
    用 Converse 就不必为每家维护一份 payload 模板。
    """
    if not model_id:
        raise BedrockError("请选择模型")
    if not prompt.strip():
        raise BedrockError("请输入提示词")

    try:
        resp = runtime_client(creds, region).converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": max_tokens},
        )
    except EndpointConnectionError as exc:
        raise BedrockError(f"{region} 没有 Bedrock 运行时端点") from exc
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        message = str(exc)
        if code == "AccessDeniedException":
            raise BedrockError(
                f"没有该模型的访问权限。需要在 Bedrock 控制台的"
                f"「模型访问」里为 {model_id} 申请开通"
            ) from exc
        if code == "ValidationException" and "on-demand" in message.lower():
            raise BedrockError(
                f"{model_id} 不支持按需调用，需要用推理配置文件（inference profile）"
                "或预置吞吐量"
            ) from exc
        raise BedrockError(f"调用失败（{code}）: {message[:200]}") from exc

    blocks = (resp.get("output") or {}).get("message", {}).get("content") or []
    text = "".join(block.get("text", "") for block in blocks)
    usage = resp.get("usage") or {}
    return {
        "model_id": model_id,
        "region": region,
        "text": text,
        "input_tokens": usage.get("inputTokens", 0),
        "output_tokens": usage.get("outputTokens", 0),
        "stop_reason": resp.get("stopReason", ""),
        "latency_ms": (resp.get("metrics") or {}).get("latencyMs", 0),
    }


def probe(creds: aws.Credentials, region: str) -> dict[str, Any]:
    """探测 Bedrock 在该区域是否可用、有多少模型、权限是否到位。"""
    result: dict[str, Any] = {"region": region, "available": False, "checks": []}

    def record(name: str, ok: bool, detail: str) -> None:
        result["checks"].append({"name": name, "ok": ok, "detail": detail})

    try:
        listing = list_models(creds, region)
    except BedrockError as exc:
        record("服务可用性", False, str(exc))
        return result

    result["available"] = True
    result["total"] = listing["total"]
    result["by_provider"] = listing["by_provider"]
    record("服务可用性", True, f"{listing['total']} 个基础模型")

    on_demand = [
        m for m in listing["models"] if "ON_DEMAND" in m["inference_types"]
    ]
    record(
        "按需可调用模型",
        bool(on_demand),
        f"{len(on_demand)} 个支持 ON_DEMAND"
        + ("" if on_demand else "，其余需推理配置文件或预置吞吐量"),
    )

    legacy = [m for m in listing["models"] if m["legacy"]]
    if legacy:
        record("模型生命周期", True, f"{len(legacy)} 个已标记 LEGACY，AWS 计划下线")

    return result


def format_payload_example(model_id: str, prompt: str = "你好") -> str:
    """给出 Converse API 的等价 CLI 命令，方便用户在别处复现。"""
    body = {
        "modelId": model_id,
        "messages": [{"role": "user", "content": [{"text": prompt}]}],
    }
    return "aws bedrock-runtime converse --cli-input-json '" + json.dumps(
        body, ensure_ascii=False
    ) + "'"
