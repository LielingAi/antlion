"""武器插件的公共数据模型。"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class WeaponPluginError(Exception):
    """插件清单、配置或执行错误。"""


@dataclass(frozen=True)
class WeaponManifest:
    """插件包 weapon.json 的已校验表示。"""

    id: str
    name: str
    version: str = "1.0.0"
    api_version: int = 1
    weapon_class: str = "prompt"
    mount: str = "delivery"
    stage: str = "sensor"
    entrypoint: str = ""
    config_schema: Dict[str, Any] = field(default_factory=dict)
    trigger: Dict[str, Any] = field(default_factory=dict)
    telemetry: Dict[str, Any] = field(default_factory=dict)
    world_constraints: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WeaponManifest":
        if not isinstance(data, dict):
            raise WeaponPluginError("manifest must be an object")
        plugin_id = str(data.get("id") or "").strip()
        name = str(data.get("name") or "").strip()
        if not plugin_id:
            raise WeaponPluginError("manifest id is required")
        if not name:
            raise WeaponPluginError(f"{plugin_id}: manifest name is required")
        api_version = data.get("api_version", 1)
        if api_version != 1:
            raise WeaponPluginError(
                f"{plugin_id}: unsupported api_version {api_version!r}"
            )
        version = str(data.get("version") or "").strip()
        if not version:
            raise WeaponPluginError(f"{plugin_id}: version is required")
        return cls(
            id=plugin_id,
            name=name,
            version=version,
            api_version=api_version,
            weapon_class=str(data.get("class") or "prompt"),
            mount=str(data.get("mount") or "delivery"),
            stage=str(data.get("stage") or "sensor"),
            entrypoint=str(data.get("entrypoint") or ""),
            config_schema=data.get("config_schema") or {},
            trigger=data.get("trigger") or {},
            telemetry=data.get("telemetry") or {},
            world_constraints=list(data.get("world_constraints") or []),
        )


@dataclass
class WeaponContext:
    """一次插件调用的现场数据；插件不接触 socket 或 HTTP writer。"""

    session: Dict[str, Any] = field(default_factory=dict)
    world: Any = None
    request: Dict[str, Any] = field(default_factory=dict)
    state: Dict[str, Any] = field(default_factory=dict)

    @property
    def session_id(self) -> str:
        return str(self.session.get("id") or self.request.get("session_id") or "-")


@dataclass
class WeaponResult:
    """插件结构化输出，由挂载点适配为 HTTP、MCP 或任务响应。"""

    payload: Optional[str] = None
    body: Optional[str] = None
    status: str = "200"
    content_type: str = "text/plain"
    headers: Dict[str, str] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    state: Optional[Dict[str, Any]] = None
    next_stage: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @classmethod
    def prompt(cls, payload: str, **kwargs) -> "WeaponResult":
        return cls(payload=payload, **kwargs)

    @classmethod
    def http(
        cls,
        body: str,
        status: str = "200",
        content_type: str = "text/plain",
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> "WeaponResult":
        return cls(
            body=body,
            status=status,
            content_type=content_type,
            headers=headers or {},
            **kwargs,
        )
