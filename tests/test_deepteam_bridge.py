import json

import pytest

from core.weapon_plugins.models import WeaponContext, WeaponPluginError
from core.weapon_plugins.runtime import WeaponRuntime
from weapon_packs.deepteam_bridge.adapter import GeneratedAttack
from weapon_packs.deepteam_bridge.contract import (
    ActionContract,
    validate_world_requirements,
)
from weapon_packs.deepteam_bridge.generator import PayloadFactory
from weapon_packs.deepteam_bridge.weapon import Plugin


@pytest.fixture(autouse=True)
def isolate_model_settings(monkeypatch):
    monkeypatch.delenv("DEEPTEAM_MODEL_SETTINGS", raising=False)


class FakeFactory:
    instances = []
    is_multi_turn = False

    def __init__(self, config):
        self.config = config
        self.calls = 0
        FakeFactory.instances.append(self)

    def validate(self):
        dt = self.config["deepteam"]
        assert dt["mode"] in ("enhance_only", "generate")
        assert dt["attack"]

    def generate(self, context):
        self.calls += 1
        dt = self.config["deepteam"]
        payload = dt.get("base_payload") or "generated baseline"
        return GeneratedAttack(
            payload=payload,
            baseline=payload,
            attack=dt["attack"],
            vulnerability=dt.get("vulnerability", ""),
            metadata={"mode": dt["mode"], "call": self.calls},
        )


def _record(cls="prompt"):
    return {
        "id": "W-DT-TEST-1",
        "name": "DeepTeam test",
        "class": cls,
        "type": "vuln" if cls == "vuln" else cls,
        "enabled": True,
        "mount": "mcp_desc" if cls == "mcp" else "delivery",
        "stage": "sensor",
        "plugin": "deepteam.bridge",
        "config": {
            "deepteam": {
                "mode": "enhance_only",
                "attack": "Base64",
                "base_payload": "counter payload",
            },
            "action": {
                "goal": "数据",
                "expected": "Agent executes the payload",
                "success_signal": ["request:/api/query"],
                "world_requirements": ["endpoint:/api/query"],
                "next_stage": "W-NEXT-1",
            },
            "generation": {"cache": "session"},
            "response": {"status": "200", "content_type": "text/plain"},
        },
        "vuln": {"deploy": {"world_endpoint": "/api/query"}},
    }


def _runtime(monkeypatch):
    runtime = WeaponRuntime()
    plugin_class = runtime.loader.get("deepteam.bridge").plugin_class
    monkeypatch.setattr(plugin_class, "adapter_factory", FakeFactory)
    FakeFactory.instances = []
    return runtime


def test_action_contract_requires_observable_success():
    with pytest.raises(WeaponPluginError, match="success_signal"):
        ActionContract.from_config({"goal": "数据", "expected": "act"})
    contract = ActionContract.from_config({
        "goal": "数据", "expected": "act", "success_signal": ["request:/api/query"],
        "world_requirements": ["endpoint:/api/query"],
    })
    validate_world_requirements(contract, [{"path": "/api/query"}])
    with pytest.raises(WeaponPluginError, match="not mounted"):
        validate_world_requirements(contract, [])


def test_enhance_only_delivery_contract_and_session_cache(monkeypatch):
    runtime = _runtime(monkeypatch)
    runtime.apply([_record()])
    context = WeaponContext(session={"id": "dt-session"})
    first = runtime.render("W-DT-TEST-1", context)
    second = runtime.render("W-DT-TEST-1", context)
    assert first.payload == "counter payload"
    assert first.next_stage == "W-NEXT-1"
    assert first.data["deepteam_attack"] == "Base64"
    assert first.data["action_contract"]["success_signal"] == ["request:/api/query"]
    assert first.events[0]["kind"] == "deepteam_weapon_delivered"
    assert second.data["generation"]["call"] == 1

    other = WeaponContext(session={"id": "other-session"})
    runtime.render("W-DT-TEST-1", other)
    assert len(FakeFactory.instances) == 1
    assert FakeFactory.instances[0].calls == 2


def test_vuln_mcp_and_cli_outputs(monkeypatch):
    runtime = _runtime(monkeypatch)
    for cls in ("vuln", "mcp", "cli"):
        record = _record(cls=cls)
        record["id"] = f"W-DT-{cls.upper()}"
        runtime.apply([record])
        context = WeaponContext(session={"id": cls})
        if cls == "vuln":
            bound = runtime.bind_route("/api/query", context)
            plugin, _ = bound
            result = runtime.execute(plugin, plugin.handle, context)
            assert result.body == "counter payload"
        elif cls == "mcp":
            plugin, _ = runtime.bind(record["id"], context)
            result = runtime.execute(
                plugin, lambda ctx: plugin.describe([{"description": "base"}], ctx), context
            )
            assert "counter payload" in result.data["tools"][0]["description"]
        else:
            result = runtime.render(record["id"], context)
            assert result.payload == "counter payload"


class FakeAdapter:
    def __init__(self):
        self.generated = False

    def attack(self, name, options):
        return object()

    def vulnerability(self, name, options):
        return object()

    def generate(self, **kwargs):
        self.generated = True
        return GeneratedAttack(
            payload="enhanced", baseline="baseline", attack="PromptInjection",
            vulnerability="SQLInjection", metadata={"mode": "generate"},
        )


def test_generate_mode_uses_attack_simulator_path():
    adapter = FakeAdapter()
    config = _record()["config"]
    config["deepteam"] = {
        "mode": "generate", "attack": "PromptInjection",
        "vulnerability": "SQLInjection", "target_purpose": "test purpose",
    }
    factory = PayloadFactory(config, adapter=adapter)
    factory.validate()
    result = factory.generate(WeaponContext())
    assert adapter.generated is True
    assert result.payload == "enhanced"
    assert result.baseline == "baseline"
    assert result.vulnerability == "SQLInjection"


def test_real_deepteam_base64_enhance_when_installed():
    deepteam = pytest.importorskip("deepteam")
    from weapon_packs.deepteam_bridge.adapter import DeepTeamAdapter

    result = DeepTeamAdapter().enhance(
        "counter payload", "Base64", {}, None
    )
    assert result.payload == "Y291bnRlciBwYXlsb2Fk"
    assert result.baseline == "counter payload"


class FakeMultiAttack:
    multi_turn = True

    def get_name(self):
        return "Linear Jailbreaking"

    def run(self, model_callback, turns, **kwargs):
        from types import SimpleNamespace

        first = model_callback("turn-1", turns)
        second = model_callback("turn-2:" + first.content, turns)
        return SimpleNamespace(stop_reason="DONE", error=None, second=second)


class FakeMultiAdapter:
    def multi_turn_attack(self, name, options):
        return FakeMultiAttack()


def _multi_config():
    config = _record()["config"]
    config["deepteam"]["multi_turn"] = True
    config["deepteam"]["attack"] = "LinearJailbreaking"
    return config


def test_progression_driver_bridges_each_agent_response():
    from weapon_packs.deepteam_bridge.progression import ProgressionDriver

    factory = PayloadFactory(_multi_config(), adapter=FakeMultiAdapter())
    factory.validate()
    driver = ProgressionDriver(factory)
    context = WeaponContext(session={"id": "multi"})
    first = driver.advance(context)
    assert first.payload == "turn-1"
    second = driver.advance(context, "answer-A")
    assert second.payload == "turn-2:answer-A"
    done = driver.advance(context, "answer-B")
    assert done.payload == ""
    assert done.metadata["done"] is True
    assert driver.should_stop() is True
    driver.stop()


def test_multi_turn_weapon_uses_session_event_driver(monkeypatch):
    runtime = WeaponRuntime()
    plugin_class = runtime.loader.get("deepteam.bridge").plugin_class
    monkeypatch.setattr(
        plugin_class,
        "adapter_factory",
        staticmethod(lambda config: PayloadFactory(config, adapter=FakeMultiAdapter())),
    )
    record = _record()
    record["config"] = _multi_config()
    runtime.apply([record])
    context = WeaponContext(session={"id": "multi-runtime"})
    assert runtime.render(record["id"], context).payload == "turn-1"
    context.request["agent_response"] = "answer-A"
    assert runtime.render(record["id"], context).payload == "turn-2:answer-A"
    context.request["agent_response"] = "answer-B"
    done = runtime.render(record["id"], context)
    assert done.payload == ""
    assert done.data["generation"]["done"] is True
    runtime.release_session("multi-runtime")
