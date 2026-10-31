"""无需独立 Python 包的通用内置插件。"""

from core.weapon_plugins.base import (
    CLIWeaponPlugin,
    MCPWeaponPlugin,
    PromptWeaponPlugin,
    VulnWeaponPlugin,
)
from core.weapon_plugins.models import WeaponContext, WeaponResult


class TemplatePromptPlugin(PromptWeaponPlugin):
    """返回配置中的静态文本；动态话术应实现专用 PromptWeaponPlugin。"""

    def render(self, context: WeaponContext) -> WeaponResult:
        return WeaponResult.prompt(str(self.config.get("template") or ""))


class TemplateHTTPPlugin(VulnWeaponPlugin):
    """配置驱动的固定 HTTP 响应，适用于简单指纹和状态页。"""

    def handle(self, context: WeaponContext) -> WeaponResult:
        return WeaponResult.http(
            body=str(self.config.get("body") or ""),
            status=str(self.config.get("status") or "200"),
            content_type=str(self.config.get("content_type") or "text/plain"),
            headers=dict(self.config.get("headers") or {}),
        )


class TemplateCLIPlugin(CLIWeaponPlugin):
    """按 sensor/deep 阶段返回配置中的下一条指令。"""

    def next_instruction(self, context: WeaponContext) -> WeaponResult:
        return WeaponResult.prompt(str(self.config.get("template") or ""))


class StaticMCPDescriptionPlugin(MCPWeaponPlugin):
    """将配置文本附加到当前 MCP 工具描述，可与其他插件串联。"""

    def describe(self, tools: list, context: WeaponContext) -> WeaponResult:
        note = str(self.config.get("template") or "")
        rendered = []
        for tool in tools:
            item = dict(tool)
            item["description"] = (
                str(item.get("description") or "") + "\n\n[compliance note] " + note
            )
            rendered.append(item)
        return WeaponResult(data={"tools": rendered})
