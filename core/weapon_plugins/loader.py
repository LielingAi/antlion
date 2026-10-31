"""发现 weapon.json 包并原子更新插件定义注册表。"""

import hashlib
import importlib.util
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Type

from core.weapon_plugins.base import WeaponPlugin
from core.weapon_plugins.builtin import (
    StaticMCPDescriptionPlugin,
    TemplateCLIPlugin,
    TemplateHTTPPlugin,
    TemplatePromptPlugin,
)
from core.weapon_plugins.models import WeaponManifest, WeaponPluginError


@dataclass(frozen=True)
class PluginDefinition:
    manifest: WeaponManifest
    plugin_class: Type[WeaponPlugin]
    package_dir: Optional[Path] = None
    package_hash: str = ""


class PluginLoader:
    """插件发现器；发现成功不代表武器已激活。"""

    def __init__(self, plugin_dir: str = None):
        self.plugin_dir = Path(plugin_dir) if plugin_dir else Path(__file__).parents[2] / "weapon_packs"
        self._definitions: Dict[str, PluginDefinition] = {}
        self._errors: Dict[str, str] = {}
        self._builtins: Dict[str, PluginDefinition] = {}
        self._register_builtins()
        self.reload()

    def _register(self, manifest: WeaponManifest, cls: Type[WeaponPlugin]) -> None:
        self._builtins[manifest.id] = PluginDefinition(manifest, cls)

    def _register_builtins(self) -> None:
        self._register(
            WeaponManifest(
                id="builtin.template_prompt",
                name="静态提示词模板",
                weapon_class="prompt",
                config_schema={
                    "required": ["template"],
                    "properties": {"template": {"type": "string"}},
                },
            ),
            TemplatePromptPlugin,
        )
        self._register(
            WeaponManifest(
                id="builtin.template_http",
                name="静态 HTTP 响应模板",
                weapon_class="vuln",
                config_schema={
                    "required": ["body"],
                    "properties": {
                        "body": {"type": "string"},
                        "status": {"type": "string"},
                        "content_type": {"type": "string"},
                        "headers": {"type": "object"},
                    },
                },
            ),
            TemplateHTTPPlugin,
        )
        self._register(
            WeaponManifest(
                id="builtin.template_cli",
                name="静态 CLI 阶段指令",
                weapon_class="cli",
                config_schema={
                    "required": ["template"],
                    "properties": {"template": {"type": "string"}},
                },
            ),
            TemplateCLIPlugin,
        )
        self._register(
            WeaponManifest(
                id="builtin.static_mcp_description",
                name="静态 MCP 工具描述",
                weapon_class="mcp",
                mount="mcp_desc",
                config_schema={
                    "required": ["template"],
                    "properties": {"template": {"type": "string"}},
                },
            ),
            StaticMCPDescriptionPlugin,
        )

    @staticmethod
    def _load_definition(path: Path) -> PluginDefinition:
        data = json.loads((path / "weapon.json").read_text(encoding="utf-8"))
        manifest = WeaponManifest.from_dict(data)
        entrypoint = manifest.entrypoint
        if not entrypoint or ":" not in entrypoint:
            raise WeaponPluginError(f"{manifest.id}: entrypoint must be file.py:Class")
        filename, class_name = entrypoint.split(":", 1)
        module_path = path / filename
        if not module_path.is_file():
            raise WeaponPluginError(f"{manifest.id}: missing entrypoint {filename}")
        module_name = f"weapon_pack_{manifest.id.replace('.', '_').replace('-', '_')}"
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise WeaponPluginError(f"{manifest.id}: cannot create import spec")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls = getattr(module, class_name, None)
        if (
            not isinstance(cls, type)
            or not issubclass(cls, WeaponPlugin)
            or cls is WeaponPlugin
        ):
            raise WeaponPluginError(
                f"{manifest.id}: {class_name} must inherit WeaponPlugin"
            )
        digest = hashlib.sha256()
        for file_path in sorted(path.rglob("*")):
            if not file_path.is_file() or "__pycache__" in file_path.parts:
                continue
            digest.update(str(file_path.relative_to(path)).encode("utf-8"))
            digest.update(file_path.read_bytes())
        return PluginDefinition(manifest, cls, path, digest.hexdigest())

    def reload(self) -> None:
        """构建全新定义表后替换；损坏包保留其上一次可用定义。"""
        discovered: Dict[str, PluginDefinition] = {}
        errors: Dict[str, str] = {}
        if self.plugin_dir.is_dir():
            for manifest_path in sorted(self.plugin_dir.glob("*/weapon.json")):
                package_id = manifest_path.parent.name
                try:
                    definition = self._load_definition(manifest_path.parent)
                    if (
                        definition.manifest.id in self._builtins
                        or definition.manifest.id in discovered
                    ):
                        raise WeaponPluginError(
                            f"duplicate plugin id {definition.manifest.id}"
                        )
                    discovered[definition.manifest.id] = definition
                except Exception as exc:
                    errors[package_id] = str(exc)
                    previous = next(
                        (
                            item
                            for item in self._definitions.values()
                            if item.package_dir == manifest_path.parent
                        ),
                        None,
                    )
                    if previous is not None:
                        discovered[previous.manifest.id] = previous
        self._definitions = discovered
        self._errors = errors

    def get(self, plugin_id: str) -> Optional[PluginDefinition]:
        return self._builtins.get(plugin_id) or self._definitions.get(plugin_id)

    def list(self) -> Dict[str, PluginDefinition]:
        return {**self._builtins, **self._definitions}

    @property
    def errors(self) -> Dict[str, str]:
        return dict(self._errors)
