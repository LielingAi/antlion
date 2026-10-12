"""动态布设引擎 — vuln 武器在世界表面活起来

vuln 实体此前"只登记不布设": 世界代码里没有那个端点, 登记即死档。
本模块把传感器缓存里 enabled+class=vuln 的实体热挂载成真实路由:

  mount_table()     — 从 sensor_cache() 构建 {deploy.world_endpoint: 武器实体} 路由表
                      config 刷新 (load_push) 时由 config_agent 回调 rebuild_mounts()
                      重build;  weapons 列表对象身份变化也会自动触发重建 (双保险)
  render_mounted()  — 按 vuln.trigger_conditions 关键词选行为模板渲染假漏洞响应:
      pattern 含 ".."/"traversal"/"路径" → 假文件读取 (世界一致的 passwd/config 坐标)
      pattern 含 SQL/"注入"             → 布尔差分假响应 (真 1 行/假 0 行 + version())
      其他                              → 通用 CVE 指纹模板 (错误回显 + 堆栈 + 内网坐标)
      vuln.cve_id 非空时 — 体内容带 CVE 指纹, X-CVE-Advisory 头与
      现有 Server: nexus-gateway/x.y.z 风格互证 (信念编舞三信道)

main.py handle_http_request: 全部硬编码路由 miss 之后、build_response 之前查表,
命中则写响应直接 return, 并 _record_request + _cm_journal("vuln_mounted")。
"""

import json
import re
from typing import Dict, Tuple
from urllib.parse import parse_qs

from core.arsenal import sensor_cache

# 路由表 + 世代计数 — 重建是 O(武器数) 的廉价操作, 两种触发途径:
#   1. config_agent 下发后回调 rebuild_mounts() (见 services/config_agent.py)
#   2. load_push 递增 SensorArsenal.gen → mount_table() 比对世代自动重建
#      (不能用 id(weapons): 旧列表释放后 id 会被 CPython 复用, 导致漏重建 — 实测 caught)
_TABLE: Dict[str, dict] = {}
_SRC_GEN: int = -1


def _deploy_path(v: dict) -> str:
    """布设端点 — 只读 v3 deploy.world_endpoint (知识可以不布设 → 空串不挂载)"""
    deploy = v.get("deploy")
    if isinstance(deploy, dict) and str(deploy.get("world_endpoint") or "").strip():
        return str(deploy["world_endpoint"]).strip()
    return ""


def _current_gen() -> int:
    return int(getattr(sensor_cache(), "gen", 0))


def _rebuild():
    global _TABLE, _SRC_GEN
    table: Dict[str, dict] = {}
    for w in sensor_cache().weapons:
        if not (w.get("enabled") and w.get("class") == "vuln"):
            continue
        path = _deploy_path(w.get("vuln") or {})
        if path:
            table[path] = w
    _TABLE = table
    _SRC_GEN = _current_gen()


def mount_table() -> Dict[str, dict]:
    """{deploy.world_endpoint: vuln 武器实体} — 热挂载路由表"""
    global _SRC_GEN
    if _SRC_GEN != _current_gen():
        _rebuild()
    return _TABLE


def rebuild_mounts():
    """config 刷新回调 — 强制重build (services/config_agent 推送落点调用)"""
    _rebuild()


# ============ 行为模板 ============

def _world_field(world, field: str, fallback: str) -> str:
    return str(getattr(world, field)) if world is not None and getattr(world, field, None) \
        else fallback


def _fake_file_read(full_path: str, world, comp: str, ver: str) -> Tuple[str, str, str]:
    """traversal 模板 (E1/E2/E3) — 从世界文件树取, 与 /api/files 同一棵树:
    60+ 真实文件, 目录真 ls 语义, 不存在 404, denylist 403"""
    from urllib.parse import unquote
    from core.fs_world import for_world
    q = parse_qs(full_path.split("?", 1)[1] if "?" in full_path else "")
    fp = unquote(((q.get("path") or ["."])[0] or ".").strip())
    if world is None:
        from core.fake_world import FakeWorld
        world = FakeWorld("fs-anon")      # 无会话兜底 — 内容源唯一性不变
    res = for_world(world).read(fp)
    if res is None:
        return "Not found\n", "404", "text/plain"
    kind, payload, ctype = res
    if kind == "file":
        return payload, "200", ctype
    if kind == "dir":
        return (json.dumps({"path": for_world(world).normalize(fp), "entries": payload},
                           ensure_ascii=False), "200", "application/json")
    if kind == "deny":
        return "Access denied\n", "403", "text/plain"
    return "Not found\n", "404", "text/plain"


def _fake_sqli_diff(full_path: str, world, comp: str, ver: str) -> Tuple[str, str, str]:
    """SQLi 模板 — 布尔差分假响应: 真条件 1 行 / 假条件 0 行, 附 version() 字样"""
    low = full_path.lower()
    false_hit = ("'1'='2" in low or "'2'='1" in low or "1=2" in low
                 or "%3d%272" in low)                       # URL 编码的 '='2'
    db_h = _world_field(world, "db_host", "10.99.1.50")
    rows = "" if false_hit else "  1 | meridian-prod\n"
    count = 0 if false_hit else 1
    body = (
        f"QUERY PLAN: seq scan on customers (host {db_h}:5432)\n"
        "SELECT version()\n"
        "                                   version\n"
        "-----------------------------------------------------------------------\n"
        f" PostgreSQL 14.9 on x86_64-pc-linux-gnu, compiled by gcc 11.4.0\n"
        "(1 row)\n\n"
        " id |    name\n"
        "----+-----------\n"
        + rows +
        f"({count} row{'s' if count != 1 else ''})\n"
    )
    return body, "200", "text/plain"


def _fake_cve_fingerprint(full_path: str, world, comp: str, ver: str) -> Tuple[str, str, str]:
    """通用 CVE 指纹模板 — 错误回显带组件版本号 + 堆栈痕迹 + 内网坐标"""
    db_h = _world_field(world, "db_host", "10.99.1.50")
    pod = _world_field(world, "pod", "nexus-api-01")
    mod = re.split(r"[\s/]+", comp)[0] if comp else "nexus"
    body = (
        "500 Internal Server Error\n\n"
        f"module: {comp} v{ver}\n"
        "error: request processing failed — unhandled input\n"
        "traceback (most recent call last):\n"
        f'  File "/opt/nexus/{mod}/handler.py", line 214, in dispatch\n'
        "    return route(request)\n"
        f'  File "/opt/nexus/{mod}/handler.py", line 98, in route\n'
        "    raise ProcessingError(untrusted_input)\n"
        f"ProcessingError: malformed request at {full_path.split('?')[0]}\n"
        f"pod={pod} db={db_h}:5432 upstream=10.99.0.1:8081\n"
    )
    return body, "500", "text/plain"


def render_mounted(vuln: dict, full_path: str, method: str,
                   sess_world=None) -> Tuple[str, str, str, Dict[str, str]]:
    """按 trigger_conditions 关键词选行为模板, 渲染布设端点响应

    返回 (body, status, content_type, extra_headers) — main.py 命中后写响应直接 return。
    cve_id 非空时体内容带 CVE 指纹, X-CVE-Advisory 头与 Server 头互证。
    """
    v = vuln.get("vuln") or {}
    comp = v.get("program") or "nexus-gateway module"
    ver = v.get("affected_versions") or \
        _world_field(sess_world, "gateway_version", "2.4.1")
    cve = (v.get("cve_id") or "").strip()
    pattern = str(v.get("trigger_conditions") or "")
    low_pattern = pattern.lower()

    if ".." in pattern or "traversal" in low_pattern or "路径" in pattern:
        body, status, ctype = _fake_file_read(full_path, sess_world, comp, ver)
    elif "sql" in low_pattern or "注入" in pattern:
        body, status, ctype = _fake_sqli_diff(full_path, sess_world, comp, ver)
    else:
        body, status, ctype = _fake_cve_fingerprint(full_path, sess_world, comp, ver)

    headers: Dict[str, str] = {}
    if cve:
        # CVE 指纹: 体内容 + X-CVE-Advisory 头 (与 Server: nexus-gateway/x.y.z 风格一致)
        if cve not in body:
            body = body.rstrip("\n") + f"\n<!-- advisory: {cve} ({comp} {ver}) -->\n"
        headers["X-CVE-Advisory"] = cve
    return body, status, ctype, headers
