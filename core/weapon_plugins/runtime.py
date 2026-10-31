"""武器实例运行时：原子应用配置、会话版本固定和结构化执行。"""

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.weapon_plugins.loader import PluginLoader
from core.weapon_plugins.models import WeaponContext, WeaponPluginError, WeaponResult


@dataclass
class RuntimeSnapshot:
    records: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    active_keys: Dict[str, Tuple[str, str, str]] = field(default_factory=dict)
    routes: Dict[str, str] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    generation: int = 0


class WeaponRuntime:
    """管理插件实例，不拥有武器配置的数据库真相源。"""

    def __init__(self, loader: PluginLoader = None, execution_timeout: float = 5.0):
        self.loader = loader or PluginLoader()
        self.execution_timeout = execution_timeout
        self._snapshot = RuntimeSnapshot()
        self._instances: Dict[Tuple[str, str, str], Any] = {}
        self._pins: Dict[str, Dict[str, Tuple[str, str, str]]] = {}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=4)

    @staticmethod
    def _key(
        record: Dict[str, Any], version: str, package_hash: str = ""
    ) -> Tuple[str, str, str]:
        config_text = json.dumps(
            record.get("config") or {}, ensure_ascii=False, sort_keys=True, default=str
        )
        # 实现与包哈希参与实例身份：换插件或同版本热修复都创建新实例。
        identity = str(record.get("plugin") or "") + ":" + package_hash
        digest = hashlib.sha256(
            (identity + ":" + config_text).encode("utf-8")
        ).hexdigest()[:16]
        return str(record.get("id") or ""), version, digest

    @staticmethod
    def _route(record: Dict[str, Any]) -> str:
        vuln = record.get("vuln") or {}
        deploy = vuln.get("deploy") or {}
        return str(deploy.get("world_endpoint") or "").strip()

    def apply(self, records: List[Dict[str, Any]]) -> RuntimeSnapshot:
        """准备完整新快照后原子替换；无效武器单独进入 errors。"""
        with self._lock:
            old_snapshot = self._snapshot
            new_records: Dict[str, Dict[str, Any]] = {}
            new_keys: Dict[str, Tuple[str, str, str]] = {}
            new_instances: Dict[Tuple[str, str, str], Any] = {}
            routes: Dict[str, str] = {}
            errors: Dict[str, str] = {}
            for record in records:
                if not record.get("enabled") or not record.get("plugin"):
                    continue
                weapon_id = str(record.get("id") or "")
                plugin_id = str(record.get("plugin") or "")
                try:
                    definition = self.loader.get(plugin_id)
                    if definition is None:
                        raise WeaponPluginError(f"plugin not found: {plugin_id}")
                    expected_hash = str(record.get("package_hash") or "")
                    if (
                        expected_hash
                        and definition.package_hash
                        and expected_hash != definition.package_hash
                    ):
                        raise WeaponPluginError(
                            f"package hash mismatch: {plugin_id} {definition.manifest.version}"
                        )
                    key = self._key(
                        record, definition.manifest.version, definition.package_hash
                    )
                    instance = self._instances.get(key)
                    if instance is None:
                        instance = definition.plugin_class(definition.manifest, record)
                        instance.validate()
                        instance.activate(WeaponContext())
                    new_instances[key] = instance
                    new_records[weapon_id] = record
                    new_keys[weapon_id] = key
                    path = self._route(record)
                    if path:
                        routes[path] = weapon_id
                except Exception as exc:
                    errors[weapon_id or plugin_id] = str(exc)

            pinned_keys = {
                key for pins in self._pins.values() for key in pins.values()
            }
            retained = set(new_instances) | pinned_keys
            for key, instance in list(self._instances.items()):
                if key not in retained:
                    try:
                        instance.deactivate()
                    except Exception:
                        pass
            self._instances = {
                key: instance
                for key, instance in {**self._instances, **new_instances}.items()
                if key in retained
            }
            self._snapshot = RuntimeSnapshot(
                records=new_records,
                active_keys=new_keys,
                routes=routes,
                errors=errors,
                generation=old_snapshot.generation + 1,
            )
            return self._snapshot

    def reload_packages(self) -> RuntimeSnapshot:
        with self._lock:
            self.loader.reload()
            records = []
            for original in self._snapshot.records.values():
                record = dict(original)
                definition = self.loader.get(record.get("plugin", ""))
                if definition is not None and definition.package_hash:
                    # 本地受信重载使用新制品；下一次 Hive 下发会携带同一哈希。
                    record["package_hash"] = definition.package_hash
                records.append(record)
            return self.apply(records)

    @property
    def snapshot(self) -> RuntimeSnapshot:
        return self._snapshot

    def active_for(self, mount: str, stage: str = "sensor") -> List[Dict[str, Any]]:
        return [
            record
            for record in self._snapshot.records.values()
            if record.get("mount") == mount and record.get("stage") == stage
        ]

    def _bind(
        self, weapon_id: str, context: WeaponContext
    ) -> Tuple[Any, Dict[str, Any]]:
        with self._lock:
            record = self._snapshot.records.get(weapon_id)
            if record is None:
                raise WeaponPluginError(f"weapon is not active: {weapon_id}")
            session_id = context.session_id
            key = None
            if session_id != "-":
                key = self._pins.get(session_id, {}).get(weapon_id)
            key = key or self._snapshot.active_keys[weapon_id]
            instance = self._instances.get(key)
            if instance is None:
                raise WeaponPluginError(
                    f"pinned plugin unavailable: {weapon_id} {key[1]}"
                )
            if session_id != "-":
                self._pins.setdefault(session_id, {})[weapon_id] = key
                context.session.setdefault("id", session_id)
            states = context.session.setdefault("_weapon_state", {})
            context.state = states.setdefault(weapon_id, {})
            return instance, record

    def bind_route(self, path: str, context: WeaponContext):
        weapon_id = self._snapshot.routes.get(path)
        if not weapon_id:
            return None
        return self._bind(weapon_id, context)

    def bind(self, weapon_id: str, context: WeaponContext):
        return self._bind(weapon_id, context)

    def render(self, weapon_id: str, context: WeaponContext) -> WeaponResult:
        """执行 Prompt 或 CLI 类文本武器。"""
        instance, _ = self._bind(weapon_id, context)
        if hasattr(instance, "render"):
            method = instance.render
        elif hasattr(instance, "next_instruction"):
            method = instance.next_instruction
        else:
            return WeaponResult(error="plugin has no text rendering capability")
        return self.execute(instance, method, context)

    def execute(
        self,
        instance: Any,
        method: Callable[[WeaponContext], WeaponResult],
        context: WeaponContext,
        timeout: float = None,
    ) -> WeaponResult:
        """隔离插件异常和超时；超时后后台线程由执行器回收。"""
        started = time.perf_counter()
        future = self._executor.submit(method, context)
        generation = instance.record.get("generation") or {}
        configured_timeout = (
            instance.record.get("execution_timeout")
            or generation.get("delivery_timeout")
        )
        try:
            result = future.result(timeout or configured_timeout or self.execution_timeout)
            if not isinstance(result, WeaponResult):
                raise TypeError("plugin must return WeaponResult")
        except FutureTimeoutError:
            result = WeaponResult(error="plugin execution timeout")
        except Exception as exc:
            result = WeaponResult(error=str(exc))
        result.data.setdefault("weapon_id", instance.weapon_id)
        result.data.setdefault("plugin_version", instance.manifest.version)
        result.data.setdefault("session_id", context.session_id)
        result.data.setdefault("mount", instance.record.get("mount", ""))
        result.data.setdefault("duration", time.perf_counter() - started)
        result.data.setdefault("ok", result.error is None)
        from core.weapon_plugins.telemetry import record_execution
        record_execution(result)
        return result

    def release_session(self, session_id: str) -> None:
        """会话销毁时释放版本固定，并回收不再需要的旧插件实例。"""
        with self._lock:
            released = self._pins.pop(session_id, None) or {}
            for key in released.values():
                instance = self._instances.get(key)
                if instance is not None:
                    try:
                        instance.release_session(session_id)
                    except Exception:
                        pass
            pinned_keys = {
                key for pins in self._pins.values() for key in pins.values()
            }
            retained = set(self._snapshot.active_keys.values()) | pinned_keys
            for key in list(self._instances):
                if key not in retained:
                    try:
                        self._instances[key].deactivate()
                    except Exception:
                        pass
                    self._instances.pop(key, None)


_RUNTIME = WeaponRuntime()


def weapon_runtime() -> WeaponRuntime:
    return _RUNTIME
