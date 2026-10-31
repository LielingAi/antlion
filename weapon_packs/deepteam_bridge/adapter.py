"""DeepTeam 可选依赖适配：动态解析漏洞、攻击和 AttackSimulator。"""

import importlib
import inspect
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.weapon_plugins.models import WeaponPluginError


def _norm(name: str) -> str:
    return "".join(ch for ch in str(name or "").lower() if ch.isalnum())


@dataclass
class GeneratedAttack:
    payload: str
    baseline: str
    attack: str
    vulnerability: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class DeepTeamAdapter:
    def __init__(self):
        try:
            self.single_turn = importlib.import_module(
                "deepteam.attacks.single_turn"
            )
            self.multi_turn = importlib.import_module(
                "deepteam.attacks.multi_turn"
            )
            self.vulnerabilities = importlib.import_module(
                "deepteam.vulnerabilities"
            )
            simulator_module = importlib.import_module(
                "deepteam.attacks.attack_simulator.attack_simulator"
            )
            self.simulator_class = simulator_module.AttackSimulator
        except (ImportError, ModuleNotFoundError) as exc:
            raise WeaponPluginError(
                "DeepTeam is not installed; install requirements-deepteam.txt "
                "or build Docker with INSTALL_DEEPTEAM=1"
            ) from exc

    @staticmethod
    def _resolve(package, name: str, kind: str):
        target = _norm(name)
        for attr in dir(package):
            obj = getattr(package, attr)
            if not isinstance(obj, type):
                continue
            names = {_norm(attr), _norm(getattr(obj, "name", ""))}
            if target in names:
                return obj
        raise WeaponPluginError(f"unknown DeepTeam {kind}: {name}")

    def catalog(self) -> Dict[str, List[Dict[str, Any]]]:
        """构建器可用工艺目录，直接来自已安装的 DeepTeam 包。"""
        attacks = []
        for package, multi in ((self.single_turn, False), (self.multi_turn, True)):
            for attr in dir(package):
                obj = getattr(package, attr)
                if not isinstance(obj, type) or attr.startswith("Base"):
                    continue
                if attr in ("AttackParameter", "StopReason", "BehaviorShiftDetector"):
                    continue
                attacks.append({
                    "id": attr,
                    "name": getattr(obj, "name", attr),
                    "multi_turn": multi,
                })
        vulnerabilities = []
        for attr in dir(self.vulnerabilities):
            obj = getattr(self.vulnerabilities, attr)
            if not isinstance(obj, type) or attr.startswith("Base"):
                continue
            if attr in ("EvaluationExample", "CustomVulnerability"):
                continue
            vulnerabilities.append({"id": attr, "name": getattr(obj, "name", attr)})
        return {
            "attacks": sorted(attacks, key=lambda item: (item["multi_turn"], item["name"])),
            "vulnerabilities": sorted(vulnerabilities, key=lambda item: item["name"]),
        }

    def attack(self, name: str, options: Dict[str, Any] = None):
        cls = self._resolve(self.single_turn, name, "single-turn attack")
        return self._construct(cls, options or {})

    def multi_turn_attack(self, name: str, options: Dict[str, Any] = None):
        cls = self._resolve(self.multi_turn, name, "multi-turn attack")
        return self._construct(cls, options or {})

    def vulnerability(self, name: str, options: Dict[str, Any] = None):
        cls = self._resolve(self.vulnerabilities, name, "vulnerability")
        return self._construct(cls, options or {})

    @staticmethod
    def _construct(cls, options: Dict[str, Any]):
        signature = inspect.signature(cls)
        if any(p.kind == p.VAR_KEYWORD for p in signature.parameters.values()):
            return cls(**options)
        accepted = {key: value for key, value in options.items() if key in signature.parameters}
        return cls(**accepted)

    def enhance(
        self,
        payload: str,
        attack_name: str,
        attack_options: Dict[str, Any],
        simulator_model: Any,
        target_response: str = "",
    ) -> GeneratedAttack:
        attack = self.attack(attack_name, attack_options)
        kwargs = {"attack": payload}
        signature = inspect.signature(attack.enhance)
        if "simulator_model" in signature.parameters:
            kwargs["simulator_model"] = simulator_model
        if "model_callback" in signature.parameters:
            kwargs["model_callback"] = lambda input, turns=None: target_response
        enhanced = attack.enhance(**kwargs)
        if not isinstance(enhanced, str) or not enhanced:
            raise WeaponPluginError(f"{attack_name} returned no payload")
        return GeneratedAttack(
            payload=enhanced,
            baseline=payload,
            attack=attack.get_name(),
            vulnerability="",
            metadata={"mode": "enhance_only"},
        )

    def baseline(
        self,
        vulnerability_name: str,
        vulnerability_types: List[str],
        vulnerability_options: Dict[str, Any],
        simulator_model: Any,
        purpose: str,
    ) -> GeneratedAttack:
        options = dict(vulnerability_options)
        if vulnerability_types:
            options["types"] = vulnerability_types
        options.setdefault("simulator_model", simulator_model)
        options.setdefault("purpose", purpose)
        vulnerability = self.vulnerability(vulnerability_name, options)
        simulator = self.simulator_class(
            purpose=purpose,
            max_concurrent=1,
            simulator_model=simulator_model,
        )
        test_cases = simulator.simulate(
            attacks_per_vulnerability_type=1,
            vulnerabilities=[vulnerability],
            ignore_errors=False,
            attacks=None,
        )
        if not test_cases or test_cases[0].error or not test_cases[0].input:
            error = test_cases[0].error if test_cases else "no test case generated"
            raise WeaponPluginError(f"DeepTeam generation failed: {error}")
        return GeneratedAttack(
            payload=test_cases[0].input,
            baseline=test_cases[0].input,
            attack="",
            vulnerability=vulnerability.get_name(),
            metadata={
                "mode": "generate",
                "vulnerability_type": str(test_cases[0].vulnerability_type),
                "target_purpose": purpose,
            },
        )

    def generate(
        self,
        vulnerability_name: str,
        vulnerability_types: List[str],
        vulnerability_options: Dict[str, Any],
        attack_name: str,
        attack_options: Dict[str, Any],
        simulator_model: Any,
        purpose: str,
    ) -> GeneratedAttack:
        generated = self.baseline(
            vulnerability_name,
            vulnerability_types,
            vulnerability_options,
            simulator_model,
            purpose,
        )
        enhanced = self.enhance(
            generated.baseline,
            attack_name,
            attack_options,
            simulator_model,
        )
        enhanced.baseline = generated.baseline
        enhanced.vulnerability = generated.vulnerability
        enhanced.metadata.update(generated.metadata)
        return enhanced
