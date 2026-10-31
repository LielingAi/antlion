"""武器执行遥测：保留 [weapon:id] 索引并附加结构化 JSON。"""

import json
import os

from core.weapon_plugins.models import WeaponResult


def record_execution(result: WeaponResult) -> None:
    """执行结果上送 Hive；本地传感器配置 DB 时同步落 cm_actions。"""
    data = dict(result.data)
    data["events"] = list(result.events)
    data["error"] = result.error
    weapon_id = str(data.get("weapon_id") or "-")
    session_id = str(data.get("session_id") or "-")
    detail = f"[weapon:{weapon_id}] " + json.dumps(
        data, ensure_ascii=False, default=str
    )
    try:
        from services.sensor_shipper import enqueue
        enqueue("cm_action", {
            "session_id": session_id,
            "kind": "weapon_execution",
            "detail": detail,
        })
        if os.environ.get("HONEYPOT_DB"):
            from core.testdb import TestDB
            TestDB(os.environ["HONEYPOT_DB"]).record_cm(
                session_id, "weapon_execution", detail
            )
    except Exception:
        # 遥测失败不改变武器执行结果。
        pass
