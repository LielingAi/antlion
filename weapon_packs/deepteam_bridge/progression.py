"""将 DeepTeam 同步多轮攻击桥接为蜜罐事件驱动会话。

DeepTeam 在独立线程中运行；model_callback 把 payload 放入事件队列后等待
来访 Agent 的真实响应。每次 HTTP/任务交互只推进一轮，不重放或重新生成历史。
"""

import queue
import threading
from types import SimpleNamespace
from typing import Any, Dict

from core.weapon_plugins.models import WeaponContext, WeaponPluginError
from weapon_packs.deepteam_bridge.adapter import GeneratedAttack


_STOP = object()


class ProgressionDriver:
    def __init__(self, factory):
        self.factory = factory
        generation = factory.generation
        self.delivery_timeout = float(generation.get("delivery_timeout") or 30)
        self.agent_timeout = float(generation.get("agent_timeout") or 300)
        self._responses = queue.Queue(maxsize=1)
        self._events = queue.Queue()
        self._stop = threading.Event()
        self._thread = None
        self._baseline = None
        self._last_event = None
        self._turn = 0

    def _event(
        self,
        payload: str = "",
        done: bool = False,
        error: Exception = None,
        stop_reason: str = "",
    ) -> GeneratedAttack:
        baseline = self._baseline
        metadata: Dict[str, Any] = {
            "multi_turn": True,
            "turn": self._turn,
            "done": done,
            "stop_reason": stop_reason,
        }
        if error is not None:
            metadata["error"] = error
        return GeneratedAttack(
            payload=payload,
            baseline=baseline.baseline,
            attack=baseline.attack,
            vulnerability=baseline.vulnerability,
            metadata=metadata,
        )

    def _callback(self, attack_input, turns=None):
        if self._stop.is_set():
            raise WeaponPluginError("progression stopped")
        self._turn += 1
        self._events.put(self._event(payload=str(attack_input)))
        try:
            response = self._responses.get(timeout=self.agent_timeout)
        except queue.Empty as exc:
            raise WeaponPluginError("waiting for agent response timed out") from exc
        if response is _STOP:
            raise WeaponPluginError("progression stopped")
        return SimpleNamespace(role="assistant", content=str(response))

    def _run(self):
        try:
            attack = self.factory.adapter.multi_turn_attack(
                self.factory.attack_name, self.factory.attack_options
            )
            result = attack.run(
                model_callback=self._callback,
                turns=[SimpleNamespace(role="user", content=self._baseline.payload)],
                vulnerability=self._baseline.vulnerability,
                vulnerability_type=self._baseline.metadata.get("vulnerability_type", ""),
                simulator_model=self.factory.simulator_model,
            )
            reason = getattr(result, "stop_reason", "")
            reason = getattr(reason, "value", str(reason))
            error = getattr(result, "error", None)
            self._events.put(self._event(done=True, error=error, stop_reason=reason))
        except Exception as exc:
            self._events.put(self._event(done=True, error=exc, stop_reason="SIMULATION_ERROR"))

    def _next_event(self) -> GeneratedAttack:
        try:
            event = self._events.get(timeout=self.delivery_timeout)
        except queue.Empty as exc:
            raise WeaponPluginError("waiting for DeepTeam progression timed out") from exc
        self._last_event = event
        if event.metadata.get("error"):
            raise event.metadata["error"]
        return event

    def advance(self, context: WeaponContext, agent_response: str = "") -> GeneratedAttack:
        if self._thread is None:
            self._baseline = self.factory.generate(context)
            self._thread = threading.Thread(
                target=self._run,
                name=f"deepteam-progression-{context.session_id}",
                daemon=True,
            )
            self._thread.start()
            return self._next_event()
        if agent_response:
            self._responses.put(agent_response)
        elif self._last_event is not None:
            return self._last_event
        return self._next_event()

    def should_stop(self) -> bool:
        return bool(self._last_event and self._last_event.metadata.get("done"))

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            try:
                self._responses.put_nowait(_STOP)
            except queue.Full:
                pass
            self._thread.join(timeout=1)
