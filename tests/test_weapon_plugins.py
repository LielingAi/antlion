import json
import time

from core.weapon_plugins.loader import PluginLoader
from core.weapon_plugins.models import WeaponContext
from core.weapon_plugins.runtime import WeaponRuntime


def _record(plugin="builtin.template_prompt", template="hello"):
    return {
        "id": "W-TEST-1",
        "enabled": True,
        "plugin": plugin,
        "config": {"template": template},
        "mount": "delivery",
        "stage": "sensor",
    }


def _write_pack(root, plugin_id="test.prompt", version="1.0.0", text="pack"):
    package = root / plugin_id
    package.mkdir(parents=True, exist_ok=True)
    (package / "weapon.json").write_text(json.dumps({
        "id": plugin_id,
        "name": "test prompt",
        "version": version,
        "api_version": 1,
        "class": "prompt",
        "mount": "delivery",
        "entrypoint": "weapon.py:Plugin",
        "config_schema": {"required": ["template"]},
    }), encoding="utf-8")
    (package / "weapon.py").write_text(
        "import time\n"
        "from core.weapon_plugins.base import PromptWeaponPlugin\n"
        "from core.weapon_plugins.models import WeaponResult\n"
        "class Plugin(PromptWeaponPlugin):\n"
        "    def render(self, context):\n"
        f"        return WeaponResult.prompt({text!r} + self.config['template'])\n",
        encoding="utf-8",
    )
    return package


def test_builtin_template_prompt_executes_with_structured_metadata():
    runtime = WeaponRuntime(loader=PluginLoader(plugin_dir="/nonexistent"))
    runtime.apply([_record(template=" scoped text ")])
    instance, _ = runtime.bind("W-TEST-1", WeaponContext())
    result = runtime.execute(instance, instance.render, WeaponContext())
    assert result.payload == " scoped text "
    assert result.data["weapon_id"] == "W-TEST-1"
    assert result.data["plugin_version"] == "1.0.0"
    assert result.data["ok"] is True


def test_invalid_config_does_not_block_other_weapons():
    runtime = WeaponRuntime(loader=PluginLoader(plugin_dir="/nonexistent"))
    invalid = _record()
    del invalid["config"]["template"]
    valid = _record()
    valid["id"] = "W-TEST-2"
    snapshot = runtime.apply([invalid, valid])
    assert "W-TEST-1" in snapshot.errors
    assert list(snapshot.records) == ["W-TEST-2"]


def test_dynamic_pack_discovery_and_execution(tmp_path):
    _write_pack(tmp_path)
    runtime = WeaponRuntime(loader=PluginLoader(str(tmp_path)))
    runtime.apply([_record(plugin="test.prompt", template="-v1")])
    instance, _ = runtime.bind("W-TEST-1", WeaponContext())
    result = runtime.execute(instance, instance.render, WeaponContext())
    assert result.payload == "pack-v1"


def test_broken_reload_keeps_last_working_definition(tmp_path):
    package = _write_pack(tmp_path)
    loader = PluginLoader(str(tmp_path))
    original = loader.get("test.prompt")
    (package / "weapon.py").write_text("not valid python !!!", encoding="utf-8")
    loader.reload()
    assert loader.get("test.prompt") == original
    assert "test.prompt" in loader.errors


def test_session_pins_plugin_version_across_hot_reload(tmp_path):
    package = _write_pack(tmp_path)
    runtime = WeaponRuntime(loader=PluginLoader(str(tmp_path)))
    runtime.apply([_record(plugin="test.prompt", template="-old")])
    old_session = WeaponContext(session={"id": "s-old"})
    instance, _ = runtime.bind("W-TEST-1", old_session)
    assert runtime.execute(instance, instance.render, old_session).payload == "pack-old"

    _write_pack(tmp_path, version="2.0.0", text="new-pack")
    runtime.reload_packages()
    pinned, _ = runtime.bind("W-TEST-1", old_session)
    assert runtime.execute(pinned, pinned.render, old_session).payload == "pack-old"

    new_session = WeaponContext(session={"id": "s-new"})
    current, _ = runtime.bind("W-TEST-1", new_session)
    assert runtime.execute(current, current.render, new_session).payload == "new-pack-old"
    runtime.release_session("s-old")


def test_plugin_timeout_returns_error_result(tmp_path):
    package = tmp_path / "test.slow"
    package.mkdir()
    (package / "weapon.json").write_text(json.dumps({
        "id": "test.slow", "name": "slow", "version": "1.0.0",
        "entrypoint": "weapon.py:Plugin",
    }), encoding="utf-8")
    (package / "weapon.py").write_text(
        "import time\n"
        "from core.weapon_plugins.base import PromptWeaponPlugin\n"
        "from core.weapon_plugins.models import WeaponResult\n"
        "class Plugin(PromptWeaponPlugin):\n"
        "    def render(self, context):\n"
        "        time.sleep(0.1)\n"
        "        return WeaponResult.prompt('late')\n",
        encoding="utf-8",
    )
    runtime = WeaponRuntime(loader=PluginLoader(str(tmp_path)), execution_timeout=0.01)
    runtime.apply([_record(plugin="test.slow")])
    instance, _ = runtime.bind("W-TEST-1", WeaponContext())
    started = time.monotonic()
    result = runtime.execute(instance, instance.render, WeaponContext())
    assert time.monotonic() - started < 0.08
    assert result.error == "plugin execution timeout"


def test_package_hash_mismatch_is_an_activation_error(tmp_path):
    _write_pack(tmp_path)
    runtime = WeaponRuntime(loader=PluginLoader(str(tmp_path)))
    record = _record(plugin="test.prompt")
    record["package_hash"] = "not-the-package-hash"
    snapshot = runtime.apply([record])
    assert "package hash mismatch" in snapshot.errors["W-TEST-1"]
    assert not snapshot.records


def test_arsenal_validation_test_fire_and_push_hash(tmp_path):
    from core.arsenal import Arsenal
    from core.testdb import TestDB

    ars = Arsenal(TestDB(str(tmp_path / "arsenal.sqlite")))
    weapon = ars.get("W-PROMPT-PROV-1")
    assert ars.validate(weapon) == ""
    fired = ars.test_fire(weapon["id"])
    assert fired["ok"] is True
    assert fired["result"]["payload"] == weapon["payload"]

    invalid = dict(weapon)
    invalid["config"] = {}
    assert "missing config key" in ars.validate(invalid)

    assert ars.set_enabled("VULN-TRAVERSAL-28413", True)
    pushed = json.loads(ars.push_payload())
    traversal = next(w for w in pushed if w["id"] == "VULN-TRAVERSAL-28413")
    assert traversal["plugin"] == "vuln.traversal"
    assert len(traversal["package_hash"]) == 64


def test_mcp_description_plugins_chain():
    from core.arsenal import sensor_cache
    from honeypots.mcp import MCPDecoyServer

    saved = json.dumps(sensor_cache().weapons, ensure_ascii=False)
    records = []
    for index in (1, 2):
        records.append({
            "id": f"W-MCP-{index}", "name": "mcp", "class": "mcp",
            "type": "mcp", "enabled": True, "mount": "mcp_desc",
            "stage": "sensor", "plugin": "builtin.static_mcp_description",
            "config": {"template": f"note-{index}"}, "payload": f"note-{index}",
        })
    try:
        sensor_cache().load_push(json.dumps(records))
        server = MCPDecoyServer(config_path="config/mcp_tools.json")
        tools = server.get_tools()
        assert tools
        for tool in tools:
            assert "note-1" in tool["description"]
            assert "note-2" in tool["description"]
            assert tool["description"].index("note-1") < tool["description"].index("note-2")
    finally:
        sensor_cache().load_push(saved)


def test_execution_telemetry_has_structured_fields(tmp_path, monkeypatch):
    from core.testdb import TestDB

    db_path = str(tmp_path / "telemetry.sqlite")
    monkeypatch.setenv("HONEYPOT_DB", db_path)
    runtime = WeaponRuntime(loader=PluginLoader(plugin_dir="/nonexistent"))
    runtime.apply([_record()])
    result = runtime.render("W-TEST-1", WeaponContext(session={"id": "telemetry-s1"}))
    assert result.error is None
    rows = TestDB(db_path).query(
        "SELECT session_id, detail FROM cm_actions WHERE kind='weapon_execution'"
    )
    assert len(rows) == 1
    assert rows[0]["session_id"] == "telemetry-s1"
    assert rows[0]["detail"].startswith("[weapon:W-TEST-1] ")
    payload = json.loads(rows[0]["detail"].split("] ", 1)[1])
    assert payload["plugin_version"] == "1.0.0"
    assert payload["mount"] == "delivery"
    assert payload["ok"] is True


def test_same_version_hot_fix_creates_new_instance_and_keeps_session_pin(tmp_path):
    _write_pack(tmp_path, version="1.0.0", text="before")
    loader = PluginLoader(str(tmp_path))
    runtime = WeaponRuntime(loader=loader)
    record = _record(plugin="test.prompt", template="-fix")
    record["package_hash"] = loader.get("test.prompt").package_hash
    runtime.apply([record])
    old_context = WeaponContext(session={"id": "before-fix"})
    assert runtime.render("W-TEST-1", old_context).payload == "before-fix"

    _write_pack(tmp_path, version="1.0.0", text="after")
    snapshot = runtime.reload_packages()
    assert not snapshot.errors
    assert runtime.render("W-TEST-1", old_context).payload == "before-fix"
    new_context = WeaponContext(session={"id": "after-fix"})
    assert runtime.render("W-TEST-1", new_context).payload == "after-fix"


def test_sensor_rejects_non_list_push_without_stale_weapons():
    from core.arsenal import SensorArsenal, sensor_cache
    from core.weapon_plugins.runtime import weapon_runtime

    saved = json.dumps(sensor_cache().weapons, ensure_ascii=False)
    try:
        arsenal = SensorArsenal()
        arsenal.load_push("{}")
        assert arsenal.weapons == []
        assert weapon_runtime().snapshot.records == {}
    finally:
        sensor_cache().load_push(saved)


def test_switching_plugin_implementation_replaces_instance():
    from core.weapon_plugins.builtin import TemplateCLIPlugin, TemplatePromptPlugin

    runtime = WeaponRuntime(loader=PluginLoader(plugin_dir="/nonexistent"))
    record = _record()
    runtime.apply([record])
    prompt, _ = runtime.bind("W-TEST-1", WeaponContext())
    assert isinstance(prompt, TemplatePromptPlugin)

    record["plugin"] = "builtin.template_cli"
    runtime.apply([record])
    cli, _ = runtime.bind("W-TEST-1", WeaponContext())
    assert isinstance(cli, TemplateCLIPlugin)
    assert cli is not prompt
