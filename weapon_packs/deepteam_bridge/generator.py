"""DeepTeam payload 的 enhance_only 与 generate 两种生成模式。"""

from typing import Any, Dict

from core.weapon_plugins.models import WeaponPluginError, WeaponContext
from weapon_packs.deepteam_bridge.adapter import DeepTeamAdapter, GeneratedAttack
from weapon_packs.deepteam_bridge.model import resolve_simulator_model


class PayloadFactory:
    def __init__(self, config: Dict[str, Any], adapter: DeepTeamAdapter = None):
        self.config = config
        self.dt = config.get("deepteam") or {}
        self.generation = config.get("generation") or {}
        self.adapter = adapter or DeepTeamAdapter()

    @property
    def mode(self) -> str:
        return str(self.dt.get("mode") or "enhance_only")

    @property
    def attack_name(self) -> str:
        return str(self.dt.get("attack") or "").strip()

    @property
    def simulator_model(self):
        return resolve_simulator_model(self.generation)

    @property
    def is_multi_turn(self) -> bool:
        return bool(self.dt.get("multi_turn"))

    @property
    def attack_options(self) -> Dict[str, Any]:
        return self.dt.get("attack_options") or {}

    def validate(self) -> None:
        if self.mode not in ("enhance_only", "generate"):
            raise WeaponPluginError("deepteam.mode must be enhance_only or generate")
        if not self.attack_name:
            raise WeaponPluginError("deepteam.attack is required")
        if self.is_multi_turn:
            self.adapter.multi_turn_attack(self.attack_name, self.attack_options)
        else:
            self.adapter.attack(self.attack_name, self.attack_options)
        if self.mode == "enhance_only":
            if not str(self.dt.get("base_payload") or "").strip():
                raise WeaponPluginError(
                    "deepteam.base_payload is required in enhance_only mode"
                )
            return
        vulnerability = str(self.dt.get("vulnerability") or "").strip()
        if not vulnerability:
            raise WeaponPluginError(
                "deepteam.vulnerability is required in generate mode"
            )
        options = dict(self.dt.get("vulnerability_options") or {})
        types = list(self.dt.get("vulnerability_types") or [])
        if types:
            options["types"] = types
        options.setdefault("simulator_model", self.simulator_model)
        options.setdefault("purpose", str(self.dt.get("target_purpose") or ""))
        self.adapter.vulnerability(vulnerability, options)

    def generate(self, context: WeaponContext) -> GeneratedAttack:
        if self.mode == "enhance_only":
            payload = str(self.dt["base_payload"])
            if self.is_multi_turn:
                attack = self.adapter.multi_turn_attack(
                    self.attack_name, self.attack_options
                )
                return GeneratedAttack(
                    payload=payload,
                    baseline=payload,
                    attack=attack.get_name(),
                    vulnerability="",
                    metadata={"mode": "enhance_only", "multi_turn": True},
                )
            return self.adapter.enhance(
                payload=payload,
                attack_name=self.attack_name,
                attack_options=self.attack_options,
                simulator_model=self.simulator_model,
                target_response=str(context.state.get("last_response") or ""),
            )
        if self.is_multi_turn:
            generated = self.adapter.baseline(
                str(self.dt["vulnerability"]),
                list(self.dt.get("vulnerability_types") or []),
                self.dt.get("vulnerability_options") or {},
                self.simulator_model,
                str(self.dt.get("target_purpose") or ""),
            )
            attack = self.adapter.multi_turn_attack(
                self.attack_name, self.attack_options
            )
            generated.attack = attack.get_name()
            generated.metadata["multi_turn"] = True
            return generated
        return self.adapter.generate(
            vulnerability_name=str(self.dt["vulnerability"]),
            vulnerability_types=list(self.dt.get("vulnerability_types") or []),
            vulnerability_options=self.dt.get("vulnerability_options") or {},
            attack_name=self.attack_name,
            attack_options=self.attack_options,
            simulator_model=self.simulator_model,
            purpose=str(self.dt.get("target_purpose") or ""),
        )
