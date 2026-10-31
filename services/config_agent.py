"""配置下发 agent — Phase 2: hive 集中管控传感器策略

传感器侧每 60s 拉取 hive 的 /api/sensor_config, 应用到运行中的蜜罐:
  - world_version      → os.environ["HONEYPOT_WORLD_VERSION"] (FakeWorld 每次构造都读)
  - visibility/framing → auth_bait 类属性 (实例读取自动落到类)
  - ladder_enabled     → auth_bait.LADDER_ENABLED
  - alert_*            → alerter.CONFIG (本地告警与 hive 同策略)

让位协议: hive 标记 optimize_active 未过期时 (bandit --optimize 在跑),
visibility/framing 两个键归 UCB1 动态管辖, 下发跳过 — 避免两头写一个旋钮。
"""

import json
import os
import threading
import time
import urllib.request

PULL_INTERVAL = 60.0
POLICY_KEYS = ("visibility", "framing", "ladder_enabled", "world_version")
ALERT_KEYS = ("alert_webhook", "alert_webhooks", "alert_fmt", "alert_threshold")
ARSENAL_KEY = "arsenal_active"
DEEPTEAM_SETTINGS_KEY = "deepteam_model_settings"
MANAGED_BY_BANDIT = ("visibility", "framing")   # optimize 期间让位


class ConfigAgent:
    def __init__(self, hive_url: str = None, token: str = None,
                 bait=None, interval: float = PULL_INTERVAL):
        self.hive_url = (hive_url or os.environ.get("HONEYPOT_HIVE_URL", "")).rstrip("/")
        self.token = token or os.environ.get("HONEYPOT_HIVE_TOKEN", "")
        self.bait = bait                    # AuthBaitEngine 实例 (main 注入)
        self.interval = interval
        self._stop = threading.Event()
        self._thread = None
        self.applied: dict = {}             # 最后应用的键值 (测试/状态可见)
        self.last_pull = 0.0
        self.last_error = ""

    # ------------------------------------------------------------------
    def start(self):
        if not self.hive_url:
            return False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while not self._stop.is_set():
            try:
                payload = self.pull_once()
                if payload is not None:
                    self.apply(payload.get("config", {}),
                               optimize_active=payload.get("optimize", {}).get("active", False))
            except Exception as e:
                self.last_error = str(e)[:120]
            self._stop.wait(self.interval)

    def pull_once(self):
        """GET /api/sensor_config → dict | None (失败)"""
        url = f"{self.hive_url}/api/sensor_config"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "X-Sensor-Id": os.environ.get("HONEYPOT_SENSOR_ID", "")})
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=10) as r:
                self.last_pull = time.time()
                return json.loads(r.read())
        except Exception as e:
            self.last_error = str(e)[:120]
            return None

    def apply(self, cfg: dict, optimize_active: bool = False) -> dict:
        """应用下发配置; optimize 期间跳过 UCB1 管辖键。返回实际应用的键值。"""
        applied = {}
        for key, val in cfg.items():
            if key in MANAGED_BY_BANDIT and optimize_active:
                continue
            if key == "world_version":
                os.environ["HONEYPOT_WORLD_VERSION"] = str(val)
            elif key in ("visibility", "framing", "ladder_enabled") and self.bait is not None:
                if key == "ladder_enabled":
                    setattr(self.bait, "LADDER_ENABLED",
                            str(val).lower() in ("1", "true", "yes"))
                else:
                    setattr(self.bait, key.upper(), str(val))
            elif key == DEEPTEAM_SETTINGS_KEY:
                os.environ["DEEPTEAM_MODEL_SETTINGS"] = str(val)
            elif key == ARSENAL_KEY:
                from core.arsenal import sensor_cache
                from core.arsenal_mount import mount_table
                from core.weapon_plugins.runtime import weapon_runtime
                sensor_cache().load_push(str(val))
                snapshot = weapon_runtime().snapshot
                if snapshot.errors:
                    self.last_error = "; ".join(
                        f"{wid}: {err}" for wid, err in snapshot.errors.items()
                    )[:500]
                # 世界一致性: 有效插件路由进表面目录并重上送 hive。
                try:
                    import json as _json
                    from services.sensor_shipper import enqueue as _ship_meta
                    import main as _main
                    mounted = [{"path": p, "methods": ["GET"], "vulnerable": True,
                                "vuln_id": (w.get("vuln") or {}).get("cve_id", "") or w["id"],
                                "plugin": w.get("plugin", ""),
                                "note": f"动态布设 — {(w.get('vuln') or {}).get('program', '')}"}
                               for p, w in mount_table().items()]
                    _ship_meta("meta", {"key": "world_surface",
                                        "value": _json.dumps(
                                            _main.WORLD_SURFACE + mounted,
                                            ensure_ascii=False)})
                except Exception as exc:
                    self.last_error = f"world surface update failed: {exc}"[:500]
            elif key in ALERT_KEYS:
                from services import alerter
                alerter.CONFIG[key] = str(val)
            else:
                continue
            applied[key] = "<redacted>" if key == DEEPTEAM_SETTINGS_KEY else val
        self.applied.update(applied)
        return applied


_agent: ConfigAgent = None


def init_from_env(bait=None) -> bool:
    global _agent
    if not os.environ.get("HONEYPOT_HIVE_URL"):
        return False
    _agent = ConfigAgent(bait=bait)
    return _agent.start()


def get_agent() -> ConfigAgent:
    return _agent
