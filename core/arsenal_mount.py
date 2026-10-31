"""漏洞武器 HTTP 挂载适配器。

路由来自统一 WeaponRuntime；具体响应由 weapon_packs 中的脚本生成。
本模块只保留 main.py 与旧测试使用的 HTTP 元组适配，不再按关键词选择行为。
"""

from typing import Dict, Tuple

from core.arsenal import _norm, sensor_cache
from core.weapon_plugins.models import WeaponContext
from core.weapon_plugins.runtime import weapon_runtime


def mount_table() -> Dict[str, dict]:
    """返回 {world_endpoint: 武器记录}，供路由、Swagger 和表面目录使用。"""
    snapshot = weapon_runtime().snapshot
    return {
        path: snapshot.records[weapon_id]
        for path, weapon_id in snapshot.routes.items()
        if weapon_id in snapshot.records
    }


def rebuild_mounts():
    """配置刷新后重新应用当前记录；代码包重载由运行时单独负责。"""
    weapon_runtime().apply(sensor_cache().weapons)


def _direct_instance(record: dict):
    """直接渲染未激活记录（单元测试/试射），不改变当前路由快照。"""
    runtime = weapon_runtime()
    normalized = _norm(record)
    definition = runtime.loader.get(normalized.get("plugin", ""))
    if definition is None:
        raise ValueError(f"plugin not found: {normalized.get('plugin')}")
    instance = definition.plugin_class(definition.manifest, normalized)
    instance.validate()
    instance.activate(WeaponContext())
    return instance


def render_mounted(
    vuln: dict, full_path: str, method: str, sess_world=None
) -> Tuple[str, str, str, Dict[str, str]]:
    """执行漏洞插件并适配为 (body, status, content_type, headers)。"""
    runtime = weapon_runtime()
    session_id = str(getattr(sess_world, "session_id", "") or "-")
    context = WeaponContext(
        session={"id": session_id} if session_id != "-" else {},
        world=sess_world,
        request={"full_path": full_path, "method": method, "session_id": session_id},
    )
    try:
        if vuln.get("id") in runtime.snapshot.records:
            instance, _ = runtime.bind(str(vuln["id"]), context)
        else:
            instance = _direct_instance(vuln)
        result = runtime.execute(instance, instance.handle, context)
    except Exception as exc:
        from core.weapon_plugins.models import WeaponResult
        result = WeaponResult(error=str(exc))
    if result.error:
        return "Weapon execution failed\n", "500", "text/plain", {}
    return (
        result.body or "",
        result.status,
        result.content_type,
        dict(result.headers),
    )
