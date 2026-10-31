"""CVE 插件目录：统一发现、框架/攻击族匹配和启停。"""

from typing import Dict, List, Optional

from core.weapon_plugins.base import CVEWeaponPlugin
from core.weapon_plugins.loader import PluginLoader
from core.weapon_plugins.runtime import weapon_runtime


class CVECatalog:
    """CVE 的非路由插件视图；启停只影响目录选择，不改 Arsenal 配置。"""

    def __init__(self, loader: PluginLoader = None):
        self.loader = loader or weapon_runtime().loader
        self._overrides: Dict[str, bool] = {}

    def _instances(self) -> List[CVEWeaponPlugin]:
        plugins = []
        for definition in self.loader.list().values():
            if not issubclass(definition.plugin_class, CVEWeaponPlugin):
                continue
            trigger = definition.manifest.trigger
            cve_id = str(trigger.get("cve_id") or definition.manifest.id)
            enabled = self._overrides.get(
                cve_id, bool(trigger.get("enabled", False))
            )
            record = {"id": cve_id, "enabled": enabled, "config": {}}
            plugins.append(definition.plugin_class(definition.manifest, record))
        return sorted(plugins, key=lambda plugin: plugin.cve_id)

    def list_plugins(self, enabled_only: bool = False) -> List[CVEWeaponPlugin]:
        return [p for p in self._instances() if p.enabled or not enabled_only]

    def get_loaded_plugins(self) -> List[CVEWeaponPlugin]:
        return self.list_plugins(enabled_only=False)

    def get_plugin(self, cve_id: str) -> Optional[CVEWeaponPlugin]:
        return next((p for p in self._instances() if p.cve_id == cve_id), None)

    def find_for_framework(
        self, agent_type: str, enabled_only: bool = True
    ) -> List[CVEWeaponPlugin]:
        return [
            p for p in self.list_plugins(enabled_only=enabled_only)
            if p.matches_framework(agent_type)
        ]

    def enable(self, cve_id: str) -> bool:
        if self.get_plugin(cve_id) is None:
            return False
        self._overrides[cve_id] = True
        return True

    def disable(self, cve_id: str) -> bool:
        if self.get_plugin(cve_id) is None:
            return False
        self._overrides[cve_id] = False
        return True

    def reload(self) -> bool:
        self.loader.reload()
        return True

    def stats(self) -> Dict:
        plugins = self._instances()
        return {
            "total": len(plugins),
            "enabled": sum(p.enabled for p in plugins),
            "disabled": sum(not p.enabled for p in plugins),
            "plugins": [p.info() for p in plugins],
            "errors": self.loader.errors,
        }
