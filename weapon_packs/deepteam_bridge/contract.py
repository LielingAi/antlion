"""DeepTeam 武器动作契约：反制目标、预期动作和可观察成功信号。"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from core.weapon_plugins.models import WeaponPluginError


@dataclass(frozen=True)
class ActionContract:
    goal: str
    expected: str
    success_signal: List[str] = field(default_factory=list)
    world_requirements: List[str] = field(default_factory=list)
    next_stage: str = ""

    @classmethod
    def from_config(cls, data: Dict[str, Any]) -> "ActionContract":
        if not isinstance(data, dict):
            raise WeaponPluginError("action contract must be an object")
        goal = str(data.get("goal") or "").strip()
        expected = str(data.get("expected") or "").strip()
        signals = [str(v).strip() for v in data.get("success_signal") or [] if str(v).strip()]
        requirements = [
            str(v).strip() for v in data.get("world_requirements") or [] if str(v).strip()
        ]
        if goal not in ("数据", "提示词", "控制", "data", "prompt", "control"):
            raise WeaponPluginError("action.goal must be 数据/提示词/控制 or data/prompt/control")
        if not expected:
            raise WeaponPluginError("action.expected is required")
        if not signals:
            raise WeaponPluginError("action.success_signal must not be empty")
        for requirement in requirements:
            if ":" not in requirement:
                raise WeaponPluginError(
                    f"invalid world requirement {requirement!r}; expected kind:value"
                )
        return cls(
            goal=goal,
            expected=expected,
            success_signal=signals,
            world_requirements=requirements,
            next_stage=str(data.get("next_stage") or "").strip(),
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "expected": self.expected,
            "success_signal": list(self.success_signal),
            "world_requirements": list(self.world_requirements),
            "next_stage": self.next_stage,
        }


def validate_world_requirements(contract: ActionContract, surface: List[Dict[str, Any]]) -> None:
    """在试射时验证端点依赖；文件和工具依赖由专用试射用例覆盖。"""
    paths = {str(item.get("path") or "") for item in surface}
    for requirement in contract.world_requirements:
        kind, value = requirement.split(":", 1)
        if kind == "endpoint" and value not in paths:
            raise WeaponPluginError(
                f"world requirement is not mounted: {requirement}"
            )
