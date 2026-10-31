"""DeepTeam simulator model 与凭据解析。"""

import inspect
import json
import os
from typing import Any, Dict

from core.weapon_plugins.models import WeaponPluginError


_PROVIDER_ENV = {
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GEMINI_API_KEY",
    "moonshotai": "MOONSHOT_API_KEY",
    "xai": "XAI_API_KEY",
    "ollama": "",
}


def global_model_settings() -> Dict[str, Any]:
    raw = os.environ.get("DEEPTEAM_MODEL_SETTINGS", "")
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
    return {
        "provider": os.environ.get("DEEPTEAM_MODEL_PROVIDER", ""),
        "model": os.environ.get("DEEPTEAM_SIMULATOR_MODEL", ""),
        "api_key": os.environ.get("DEEPTEAM_API_KEY", ""),
        "base_url": os.environ.get("DEEPTEAM_BASE_URL", ""),
    }


def resolve_simulator_model(generation: Dict[str, Any]):
    """按武器配置和环境构造 DeepEval 模型；未配置时保留原字符串行为。"""
    configured = global_model_settings()
    model = generation.get("simulator_model") or configured.get("model") or "gpt-4o-mini"
    if not isinstance(model, str):
        return model                 # DeepEvalBaseLLM 实例（本地测试/自定义模型）
    provider = str(
        generation.get("provider") or configured.get("provider") or ""
    ).strip().lower()
    if "/" in model and not provider:
        prefix, model = model.split("/", 1)
        provider = prefix
    explicit = bool(
        provider
        or generation.get("api_key")
        or generation.get("base_url")
        or configured.get("api_key")
        or configured.get("base_url")
    )
    if not explicit:
        return model                 # 由 DeepEval 使用其原生环境变量配置

    provider = provider or "openai"
    if provider not in _PROVIDER_ENV:
        raise WeaponPluginError(f"unsupported DeepTeam model provider: {provider}")
    api_key = str(
        generation.get("api_key")
        or configured.get("api_key")
        or os.environ.get(_PROVIDER_ENV[provider], "")
    ).strip()
    if provider != "ollama" and not api_key:
        raise WeaponPluginError(
            f"DeepTeam {provider} API key is not configured; open 配置 → DeepTeam 模型"
        )
    base_url = str(
        generation.get("base_url") or configured.get("base_url") or ""
    ).strip()
    try:
        from deepeval.models import (
            AnthropicModel,
            DeepSeekModel,
            GeminiModel,
            GPTModel,
            GrokModel,
            KimiModel,
            OllamaModel,
        )
    except ImportError as exc:
        raise WeaponPluginError("DeepEval model providers are unavailable") from exc
    classes = {
        "openai": GPTModel,
        "deepseek": DeepSeekModel,
        "anthropic": AnthropicModel,
        "google": GeminiModel,
        "moonshotai": KimiModel,
        "xai": GrokModel,
        "ollama": OllamaModel,
    }
    cls = classes[provider]
    signature = inspect.signature(cls)
    kwargs = {}
    for key, value in (("model", model), ("api_key", api_key), ("base_url", base_url)):
        if value and key in signature.parameters:
            kwargs[key] = value
    if base_url and "api_base" in signature.parameters:
        kwargs["api_base"] = base_url
    try:
        return cls(**kwargs)
    except Exception as exc:
        raise WeaponPluginError(
            f"cannot initialize DeepTeam model {provider}/{model}: {exc}"
        ) from exc
