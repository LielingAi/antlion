"""统一武器插件协议与运行时。"""

from core.weapon_plugins.base import (
    CLIWeaponPlugin,
    CVEWeaponPlugin,
    MCPWeaponPlugin,
    PromptWeaponPlugin,
    VulnWeaponPlugin,
    WeaponPlugin,
)
from core.weapon_plugins.models import (
    WeaponContext,
    WeaponManifest,
    WeaponPluginError,
    WeaponResult,
)
from core.weapon_plugins.runtime import WeaponRuntime, weapon_runtime

__all__ = [
    "CLIWeaponPlugin",
    "CVEWeaponPlugin",
    "MCPWeaponPlugin",
    "PromptWeaponPlugin",
    "VulnWeaponPlugin",
    "WeaponContext",
    "WeaponManifest",
    "WeaponPlugin",
    "WeaponPluginError",
    "WeaponResult",
    "WeaponRuntime",
    "weapon_runtime",
]
