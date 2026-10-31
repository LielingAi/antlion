import json
import sys
import types

import pytest

from services.config_agent import ConfigAgent, DEEPTEAM_SETTINGS_KEY
from weapon_packs.deepteam_bridge.model import resolve_simulator_model


class FakeProviderModel:
    def __init__(self, model, api_key=None, base_url=None):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url


@pytest.fixture
def provider_module(monkeypatch):
    module = types.ModuleType("deepeval.models")
    for name in (
        "AnthropicModel", "DeepSeekModel", "GeminiModel", "GPTModel",
        "GrokModel", "KimiModel", "OllamaModel",
    ):
        setattr(module, name, FakeProviderModel)
    monkeypatch.setitem(sys.modules, "deepeval.models", module)
    return module


def test_unconfigured_model_keeps_deepeval_string_behavior(monkeypatch):
    monkeypatch.delenv("DEEPTEAM_MODEL_SETTINGS", raising=False)
    assert resolve_simulator_model({"simulator_model": "gpt-4o-mini"}) == "gpt-4o-mini"


def test_openai_settings_construct_provider_with_credentials(monkeypatch, provider_module):
    monkeypatch.setenv("DEEPTEAM_MODEL_SETTINGS", json.dumps({
        "provider": "openai", "model": "gpt-test", "api_key": "secret",
        "base_url": "http://model.local",
    }))
    model = resolve_simulator_model({})
    assert isinstance(model, FakeProviderModel)
    assert model.model == "gpt-test"
    assert model.api_key == "secret"
    assert model.base_url == "http://model.local"


def test_missing_credentials_has_actionable_error(monkeypatch, provider_module):
    monkeypatch.setenv("DEEPTEAM_MODEL_SETTINGS", json.dumps({
        "provider": "openai", "model": "gpt-test", "api_key": "",
    }))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(Exception, match="配置 → DeepTeam 模型"):
        resolve_simulator_model({})


def test_provider_prefix_and_ollama(monkeypatch, provider_module):
    monkeypatch.delenv("DEEPTEAM_MODEL_SETTINGS", raising=False)
    model = resolve_simulator_model({"simulator_model": "ollama/qwen-test"})
    assert isinstance(model, FakeProviderModel)
    assert model.model == "qwen-test"
    assert model.api_key is None


def test_custom_model_instance_is_preserved(monkeypatch):
    instance = object()
    assert resolve_simulator_model({"simulator_model": instance}) is instance


def test_dashboard_masks_api_key_and_sensor_keeps_server_side_config(tmp_path):
    from core.testdb import TestDB
    from experiments.dashboard import _deepteam_settings, _masked_cfg

    db = TestDB(str(tmp_path / "config.sqlite"))
    db.set_setting("deepteam_api_key", "secret")
    db.set_setting("deepteam_model_provider", "deepseek")
    db.set_setting("deepteam_simulator_model", "deepseek-test")
    import experiments.dashboard as dashboard
    dashboard.DB = db
    masked = dashboard._masked_cfg()
    assert "deepteam_api_key" not in masked
    assert masked["deepteam_api_key_set"] is True
    assert dashboard._deepteam_settings()["api_key"] == "secret"


def test_config_agent_applies_credentials_and_redacts_status(monkeypatch):
    monkeypatch.delenv("DEEPTEAM_MODEL_SETTINGS", raising=False)
    payload = json.dumps({"provider": "openai", "model": "gpt-test", "api_key": "secret"})
    agent = ConfigAgent()
    applied = agent.apply({DEEPTEAM_SETTINGS_KEY: payload})
    assert applied[DEEPTEAM_SETTINGS_KEY] == "<redacted>"
    settings = json.loads(__import__("os").environ["DEEPTEAM_MODEL_SETTINGS"])
    assert settings["api_key"] == "secret"
