"""武器插件生命周期与分能力接口。"""

from typing import Any, Dict

from core.weapon_plugins.models import (
    WeaponContext,
    WeaponManifest,
    WeaponPluginError,
    WeaponResult,
)


class WeaponPlugin:
    """所有武器插件的公共生命周期。

    插件实例对应一条 Arsenal 武器记录；manifest 描述实现，record 保存实例配置。
    """

    def __init__(self, manifest: WeaponManifest, record: Dict[str, Any]):
        self.manifest = manifest
        self.record = record
        self.config = record.get("config") or {}
        self.active = False

    @property
    def weapon_id(self) -> str:
        return str(self.record.get("id") or "")

    def validate(self) -> None:
        if not isinstance(self.config, dict):
            raise WeaponPluginError(f"{self.weapon_id}: config must be an object")
        schema = self.manifest.config_schema
        for key in schema.get("required", []):
            if key not in self.config:
                raise WeaponPluginError(
                    f"{self.weapon_id}: missing config key {key!r}"
                )
        properties = schema.get("properties", {})
        type_map = {
            "string": str,
            "object": dict,
            "array": list,
            "boolean": bool,
            "number": (int, float),
            "integer": int,
        }
        for key, expected in properties.items():
            if key not in self.config:
                continue
            expected_type = type_map.get(expected.get("type"))
            if expected_type and not isinstance(self.config[key], expected_type):
                raise WeaponPluginError(
                    f"{self.weapon_id}: config {key!r} must be {expected.get('type')}"
                )

    def activate(self, context: WeaponContext = None) -> None:
        self.active = True

    def deactivate(self) -> None:
        self.active = False

    def release_session(self, session_id: str) -> None:
        """会话销毁时释放插件持有的状态或后台资源。"""


class PromptWeaponPlugin(WeaponPlugin):
    def render(self, context: WeaponContext) -> WeaponResult:
        raise NotImplementedError


class VulnWeaponPlugin(WeaponPlugin):
    def handle(self, context: WeaponContext) -> WeaponResult:
        raise NotImplementedError

    def with_advisory(
        self, result: WeaponResult, context: WeaponContext
    ) -> WeaponResult:
        """为漏洞响应补充与世界其他信道互证的 CVE 指纹。"""
        vuln = self.record.get("vuln") or {}
        cve = str(vuln.get("cve_id") or "").strip()
        if not cve or result.body is None:
            return result
        if cve not in result.body:
            program = vuln.get("program") or "nexus-gateway module"
            version = vuln.get("affected_versions") or getattr(
                context.world, "gateway_version", "2.4.1"
            )
            result.body = (
                result.body.rstrip("\n")
                + f"\n<!-- advisory: {cve} ({program} {version}) -->\n"
            )
        result.headers["X-CVE-Advisory"] = cve
        return result


class MCPWeaponPlugin(WeaponPlugin):
    def describe(self, tools: list, context: WeaponContext) -> WeaponResult:
        raise NotImplementedError


class CLIWeaponPlugin(WeaponPlugin):
    def next_instruction(self, context: WeaponContext) -> WeaponResult:
        raise NotImplementedError


class CVEWeaponPlugin(WeaponPlugin):
    """CVE 载荷插件；匹配元数据由 manifest.trigger 声明。"""

    @property
    def cve_id(self) -> str:
        return str(self.manifest.trigger.get("cve_id") or self.weapon_id)

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def description(self) -> str:
        return str(self.manifest.trigger.get("description") or "")

    @property
    def target_frameworks(self) -> list:
        return list(self.manifest.trigger.get("frameworks") or [])

    @property
    def risk_level(self) -> int:
        return int(self.manifest.trigger.get("risk_level") or 5)

    @property
    def enabled(self) -> bool:
        return bool(self.record.get("enabled"))

    def matches_framework(self, agent_type: str) -> bool:
        agent = agent_type.lower()
        return any(framework.lower() in agent for framework in self.target_frameworks)

    def matches_families(self, families: list) -> bool:
        expected = set(self.manifest.trigger.get("families") or [])
        return bool(expected & set(families))

    def craft_payload(self, beacon_server: str, **kwargs) -> str:
        raise NotImplementedError

    def info(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "name": self.name,
            "description": self.description,
            "target_frameworks": self.target_frameworks,
            "risk_level": self.risk_level,
            "enabled": self.enabled,
            "plugin": self.manifest.id,
            "version": self.manifest.version,
        }
