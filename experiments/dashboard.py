"""
蜜罐研究数据面板 — 零依赖本地 Web 后台 (stdlib http.server)

用法:
  python experiments/dashboard.py --db experiments/results/testdb.sqlite --port 8899
  浏览器打开 http://127.0.0.1:8899

页面 (全部中文界面):
- 指标总览: KPI 卡片 (发现攻击耗时/真外泄率/注入服从率/预算放大/误报率/情报产出)
- 演化实验: --optimize 自动 A/B 各组合臂的进展
- 操作者归因: 跨会话聚类出的攻击操作者及其共同指纹
- 汇总指标 / 模型差分: 聚合与 回连/攻击命令/授权级别 三指标差分
- 试验明细: run/场景/人设三维筛选 + 全文搜索
- 动作流水 / 情报分级 / 请求日志 / 运行记录
- 导出情报按钮: 当前运行 → STIX bundle 下载
数据每 8 秒自动刷新, 搜索与筛选状态在刷新间保留。
"""

import argparse
import base64
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.testdb import TestDB

DB: TestDB = None
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
DEFAULT_WEAPON_PACK_DIR = Path(os.path.dirname(STATIC_DIR)) / "weapon_packs"
WEAPON_PACK_DIR = Path(os.environ.get("HONEYPOT_WEAPON_PACK_DIR", DEFAULT_WEAPON_PACK_DIR))
BANDIT_STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "experiments", "results", "bandit_state.json")

# ---- 产品化 P2: 会话 (内存, 12h 滑动过期) ----
import secrets as _secrets
SESSIONS: dict = {}          # token -> {"user":.., "role":.., "exp":..}
SESSION_TTL = 12 * 3600
COOKIE = "hp_sid"


def _session_user(headers) -> dict:
    cookie = headers.get("Cookie", "")
    for part in cookie.split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE and v in SESSIONS:
            s = SESSIONS[v]
            if time.time() < s["exp"]:
                s["exp"] = time.time() + SESSION_TTL
                return s
            SESSIONS.pop(v, None)
    return {}


def _login(username: str, password: str) -> dict:
    u = DB.verify_user(username, password)
    if not u:
        return {}
    token = _secrets.token_hex(24)
    SESSIONS[token] = {"user": u["username"], "role": u["role"],
                       "exp": time.time() + SESSION_TTL}
    return {"token": token, **u}


def q(sql: str, params: tuple = ()) -> list:
    try:
        return DB.query(sql, params)
    except Exception as e:
        return [{"error": str(e)}]


def _masked_cfg() -> dict:
    cfg = DB.all_settings() if DB else {}
    wh = cfg.get("alert_webhook", "")
    if wh and len(wh) > 8:
        cfg["alert_webhook"] = wh[:4] + "…" + wh[-4:]
    cfg.setdefault("alert_fmt", "generic")
    cfg.setdefault("alert_threshold", "8")
    cfg.setdefault("retention_days", "30")
    cfg["deepteam_api_key_set"] = bool(cfg.get("deepteam_api_key"))
    cfg.pop("deepteam_api_key", None)          # 凭据永不下发到浏览器
    cfg.setdefault("deepteam_model_provider", "openai")
    cfg.setdefault("deepteam_simulator_model", "gpt-4o-mini")
    cfg.setdefault("deepteam_base_url", "")
    return cfg


def _deepteam_settings() -> dict:
    cfg = DB.all_settings() if DB else {}
    return {
        "provider": cfg.get("deepteam_model_provider", "openai"),
        "model": cfg.get("deepteam_simulator_model", "gpt-4o-mini"),
        "api_key": cfg.get("deepteam_api_key", ""),
        "base_url": cfg.get("deepteam_base_url", ""),
    }


def _apply_deepteam_env() -> None:
    os.environ["DEEPTEAM_MODEL_SETTINGS"] = json.dumps(_deepteam_settings())


def reltime_js(ts) -> str:
    if not ts:
        return "-"
    s = max(0, time.time() - ts)
    if s < 90:
        return f"{s:.0f}秒前"
    if s < 3600:
        return f"{s/60:.0f}分钟前"
    if s < 86400:
        return f"{s/3600:.1f}小时前"
    return f"{s/86400:.1f}天前"




def _entity(etype: str, eid: str):
    """实体档案合成 — 统一调查对象, 前端 EntityHub 通用渲染"""
    if etype == "ip":
        rows = DB.query("""SELECT COUNT(*) AS requests, SUM(canary) AS canary_hits,
                           MAX(threat) AS threat_peak, SUM(is_ai) AS ai_requests,
                           COUNT(DISTINCT session_id) AS sessions,
                           MIN(ts) AS first_seen, MAX(ts) AS last_seen
                           FROM requests WHERE client_ip=?""", (eid,))
        if not rows or not rows[0]["requests"]:
            return None
        st = rows[0]
        sessions = [r["session_id"] for r in DB.query(
            "SELECT session_id FROM requests WHERE client_ip=? "
            "GROUP BY session_id ORDER BY MAX(ts) DESC LIMIT 20", (eid,))]
        intel = DB.query("SELECT * FROM intel WHERE session_id IN "
                         "(SELECT DISTINCT session_id FROM requests WHERE client_ip=?) "
                         "ORDER BY ts DESC LIMIT 10", (eid,))
        tl = _session_timeline(sessions[0])["steps"][:1] if sessions else None
        canary = st["canary_hits"] or 0
        if canary >= 1:
            verdict, advice, level = "高危 — 金丝雀已触雷", "假凭证被实际使用 — 建议封禁并做归属分析", "bad"
        elif (st["threat_peak"] or 0) >= 8:
            verdict, advice, level = "活跃攻击", "威胁峰值高 — 沿会话卷宗确认手法", "warn"
        elif st["ai_requests"] > st["requests"] * 0.5:
            verdict, advice, level = "AI Agent 特征", "行为模式像自动化 Agent — 查看动作流水", "warn"
        else:
            verdict, advice, level = "低活动", "偶发探测 — 无需行动", "dim"
        return {"type": "ip", "id": eid, "verdict": verdict, "advice": advice,
                "level": level, "stats": st,
                "relations": {"sessions": sessions,
                              "intel": [dict(x) for x in intel]},
                "events": _ip_events(eid, limit=50)}
    if etype == "session":
        tl = _session_timeline(eid)
        if not tl["steps"] and not tl["intel"]:
            return None
        ip_rows = DB.query("SELECT client_ip FROM requests WHERE session_id=? "
                           "AND client_ip != '' LIMIT 1", (eid,))
        ip = ip_rows[0]["client_ip"] if ip_rows else ""
        kinds = {}
        for st_ in tl["steps"]:
            kinds[st_["kind"]] = kinds.get(st_["kind"], 0) + 1
        return {"type": "session", "id": eid,
                "verdict": f"{len(tl['steps'])} 步 · " + " / ".join(
                    f"{k}×{v}" for k, v in sorted(kinds.items(), key=lambda kv: -kv[1])[:4]),
                "advice": "沿时间线阅读故事; 点 IP 看该攻击者全貌", "level":
                    "bad" if kinds.get("canary") else ("warn" if kinds.get("deliver") else "dim"),
                "relations": {"ip": ip, "intel": tl["intel"]},
                "events": tl["steps"]}
    if etype == "actor":
        from core import attribution as attr
        subs = attr.collect_subjects(DB)
        clusters = attr.cluster(subs)
        hit = next((c for c in clusters if c["cluster_id"] == eid), None)
        if not hit:
            return None
        sids = [x.split(":", 1)[1] for x in hit["subjects"] if x.startswith("session:")]
        return {"type": "actor", "id": eid,
                "verdict": f"操作者 · 涉及 {hit['size']} 个主体",
                "advice": "展开成员会话看各自的故事", "level": "purple",
                "stats": {"size": hit["size"]},
                "relations": {"sessions": sids[:30],
                              "shared": hit["shared"]},
                "events": []}
    return None


def _ip_events(ip: str, limit: int = 50) -> list:
    rows = DB.query("SELECT * FROM requests WHERE client_ip=? ORDER BY ts DESC LIMIT ?",
                    (ip, limit))
    out = []
    for r in reversed(rows):
        note = []
        kind = "probe"
        if r["canary"]:
            kind, note = "canary", ["金丝雀触雷"]
        elif "bounty/submit" in r["path"] or "build/upload" in r["path"]:
            kind, note = "deliver", ["交付动作"]
        elif r["threat"] and r["threat"] >= 8:
            kind, note = "attack", ["高威胁"]
        elif r["families"]:
            kind, note = "attack", [r["families"]]
        out.append({"ts": r["ts"], "kind": kind, "method": r["method"],
                    "path": r["path"], "threat": r["threat"], "notes": note,
                    "session_id": r["session_id"], "agent_type": r["agent_type"],
                    "run_id": r["run_id"]})
    return out



def _paged(qs: dict, base_sql: str, count_sql: str, params: tuple,
           default_size: int = 50):
    """分页: 返回 {rows,total,page,page_size} — 大表不再硬截断"""
    try:
        page = max(1, int(qs.get("page", ["1"])[0]))
        size = min(200, max(5, int(qs.get("page_size", [str(default_size)])[0])))
    except ValueError:
        page, size = 1, default_size
    total = DB.query(count_sql, params)[0]["n"]
    rows = DB.query(f"{base_sql} LIMIT ? OFFSET ?", (*params, size, (page - 1) * size))
    return {"rows": rows, "total": total, "page": page, "page_size": size}


# ---- 武器库入库校验 (与前端 weaponErr 同规则) ----
_WTYPES = {"prompt", "vuln", "mcp", "cli"}
_WSTAGES = {"sensor", "deep"}
_WMOUNTS = {"delivery", "ladder", "beacon_next_stage", "mcp_desc", "js_bait", "tasking"}
_WID_RE = re.compile(r"^[A-Za-z0-9_-]{2,40}$")
_WCLASS = {"prompt", "vuln", "exp", "mcp", "cli"}
_EXP_PRIMITIVES = {"read", "write", "ask", "execute", "beacon"}
_EXP_OBJECTS = {"content", "output", "description", "instruction"}
_EXP_OBJECTIVES = {"控制", "数据", "提示词"}          # exp.objective 反制目标 (v3)
_VULN_PRIMITIVES = {"read", "write", "rce", "auth_bypass", "ssrf", "deser"}
_VULN_SOURCES = {"research", "feed", "zero-day"}
_VULN_CONFS = {"confirmed", "probable"}
_WEAPON_TAG = re.compile(r"\[weapon:([^\]]+)\]")


def _weapon_effects(db) -> dict:
    """武器效能聚合 — cm_actions 的 [weapon:id] 归因 + exp 链推进统计

    每武器: hits(总命中) mounted_hit(布设端点命中) chain_open/advance/complete
    (链推进) last_hit(最近命中 ts) — 前端效能徽标数据源
    """
    out: dict = {}
    # 去重: 同会话+同动作+同详情 = 同一事件 (传感器本地直写与 shipper 上送
    # 双写同库 / 重试补发时, 效能统计只计一次, ts 取最新)
    for r in db.query("SELECT kind, detail, MAX(ts) ts FROM cm_actions "
                      "GROUP BY session_id, kind, detail"):
        m = _WEAPON_TAG.search(r["detail"] or "")
        if not m:
            continue
        e = out.setdefault(m.group(1), {
            "hits": 0, "mounted_hit": 0, "chain_open": 0,
            "chain_advance": 0, "chain_complete": 0, "last_hit": 0})
        e["hits"] += 1
        if r["kind"] == "vuln_mounted":
            e["mounted_hit"] += 1
        elif r["kind"] == "exp_chain_open":
            e["chain_open"] += 1
        elif r["kind"] == "exp_stage_advance":
            e["chain_advance"] += 1
        elif r["kind"] == "exp_chain_complete":
            e["chain_complete"] += 1
        e["last_hit"] = max(e["last_hit"], float(r["ts"] or 0))
    return out


class PackageUploadError(ValueError):
    """武器包上传内容或校验失败。"""


def _package_member(name: str) -> PurePosixPath:
    if not name or "\\" in name:
        raise PackageUploadError("unsafe package member path")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise PackageUploadError("package path traversal detected")
    return path


def _read_package_zip(content: bytes):
    from core.weapon_plugins.models import WeaponManifest

    if len(content) > 1024 * 1024:
        raise PackageUploadError("ZIP 包不能超过 1 MiB")
    files: dict[str, bytes] = {}
    manifest_path = None
    total_size = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise PackageUploadError("不是有效的 ZIP 文件") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > 32:
            raise PackageUploadError("包内文件不能超过 32 个")
        for info in infos:
            if info.is_dir():
                continue
            path = _package_member(info.filename)
            if info.external_attr >> 16 & 0o170000 == 0o120000:
                raise PackageUploadError("不允许符号链接")
            if info.file_size > 256 * 1024:
                raise PackageUploadError(f"单文件超过 256 KiB: {path}")
            total_size += info.file_size
            if total_size > 2 * 1024 * 1024:
                raise PackageUploadError("解压后内容不能超过 2 MiB")
            data = archive.read(info)
            files[str(path)] = data
            if path.name == "weapon.json":
                if manifest_path is not None:
                    raise PackageUploadError("只能包含一个 weapon.json")
                manifest_path = path
    if manifest_path is None:
        raise PackageUploadError("缺少 weapon.json")
    root = manifest_path.parent
    try:
        manifest_data = json.loads(files[str(manifest_path)].decode("utf-8"))
        manifest = WeaponManifest.from_dict(manifest_data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageUploadError("weapon.json 不是有效 JSON") from exc
    normalized = {}
    for name, data in files.items():
        path = PurePosixPath(name)
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise PackageUploadError("包内文件必须位于 weapon.json 同级或子目录") from exc
        normalized[str(relative)] = data
    entrypoint = manifest.entrypoint.split(":", 1)[0]
    if entrypoint not in normalized:
        raise PackageUploadError(f"入口文件不存在: {entrypoint}")
    try:
        compile(normalized[entrypoint].decode("utf-8"), entrypoint, "exec")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise PackageUploadError(f"入口 Python 语法错误: {exc}") from exc
    return manifest, normalized


def _install_weapon_package(
    filename: str,
    content_base64: str,
    plugin_dir: Path = None,
    reload: bool = True,
):
    """校验并原子安装 ZIP 武器包；不覆盖现有包。"""
    if not str(filename or "").lower().endswith(".zip"):
        raise PackageUploadError("只支持 .zip 文件")
    try:
        content = base64.b64decode(content_base64 or "", validate=True)
    except Exception as exc:
        raise PackageUploadError("文件编码无效") from exc
    manifest, files = _read_package_zip(content)
    package_name = re.sub(r"[^A-Za-z0-9_-]+", "_", manifest.id).strip("_")
    if not package_name:
        raise PackageUploadError("插件 ID 无效")
    plugin_dir = Path(plugin_dir or WEAPON_PACK_DIR)
    plugin_dir.mkdir(parents=True, exist_ok=True)
    destination = plugin_dir / package_name
    if destination.exists():
        raise PackageUploadError(f"插件包已存在: {package_name}")
    staging = Path(tempfile.mkdtemp(prefix=".upload-", dir=plugin_dir))
    workdir = staging / package_name
    installed = False
    try:
        for relative, data in files.items():
            target = workdir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        from core.weapon_plugins.loader import PluginLoader
        loader = PluginLoader(str(staging))
        if loader.errors or loader.get(manifest.id) is None:
            detail = next(iter(loader.errors.values()), "entrypoint validation failed")
            raise PackageUploadError(f"插件加载失败: {detail}")
        definition = loader.get(manifest.id)
        workdir.replace(destination)
        installed = True
        if reload and plugin_dir.resolve() == DEFAULT_WEAPON_PACK_DIR.resolve():
            from core.weapon_plugins.runtime import weapon_runtime
            snapshot = weapon_runtime().reload_packages()
            errors = {**weapon_runtime().loader.errors, **snapshot.errors}
            if package_name in errors or manifest.id in errors:
                raise PackageUploadError(errors.get(package_name) or errors[manifest.id])
        return {
            "id": manifest.id,
            "name": manifest.name,
            "version": manifest.version,
            "package": package_name,
            "package_hash": definition.package_hash,
        }
    except Exception:
        if installed:
            shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _weapon_error(w: dict) -> str:
    """武器入库前校验, 返回错误文案 (空串 = 通过)"""
    if not _WID_RE.match(str(w.get("id", "") or "")):
        return "武器 id 需为 2-40 位字母/数字/_/-"
    if not str(w.get("payload", "") or "").strip():
        return "payload 不能为空"
    if w.get("type") not in _WTYPES:
        return "type 需为 prompt/vuln/mcp/cli"
    if w.get("stage") not in _WSTAGES:
        return "stage 需为 sensor/deep"
    if w.get("mount") not in _WMOUNTS:
        return "mount 需为 delivery/ladder/beacon_next_stage/mcp_desc/js_bait/tasking"
    # ---- 实体类别校验 (class 缺省 = 旧行, 按 type 派生, 不检) ----
    cls = w.get("class")
    if cls is not None and cls not in _WCLASS:
        return "class 需为 prompt/vuln/exp/mcp/cli"
    if cls == "vuln":
        # v3 知识档案: program/primitive/source 必填 — 知识本体不依赖布设端点
        # (trigger.path 不再必填; deploy.world_endpoint 可选, 可空=不布设纯检测)
        v = w.get("vuln") or {}
        if not isinstance(v, dict):
            return "vuln 类武器要求 vuln 块为对象"
        if not str(v.get("program", "")).strip():
            return "vuln 类武器要求 vuln.program 非空"
        if v.get("primitive") not in _VULN_PRIMITIVES:
            return "vuln.primitive 需为 read/write/rce/auth_bypass/ssrf/deser"
        if v.get("source") not in _VULN_SOURCES:
            return "vuln.source 需为 research/feed/zero-day"
        if v.get("confidence") and v["confidence"] not in _VULN_CONFS:
            return "vuln.confidence 需为 confirmed/probable"
        deploy = v.get("deploy")
        if deploy is not None:
            if not isinstance(deploy, dict):
                return "vuln.deploy 需为对象"
            if not str(deploy.get("world_endpoint", "") or "").strip():
                return "vuln.deploy.world_endpoint 需为非空字符串"
    if cls == "exp":
        e = w.get("exp") or {}
        stages = e.get("stages") if isinstance(e, dict) else None
        if not isinstance(stages, list) or not stages:
            return "exp 类武器要求 exp.stages 为非空数组"
        obj = e.get("objective") if isinstance(e, dict) else None
        if obj is not None and obj not in _EXP_OBJECTIVES:
            return "exp.objective 需为 控制/数据/提示词"
        for s in stages:
            if not isinstance(s, dict):
                return "exp.stages 每项需为对象"
            if not str(s.get("name", "")).strip() \
                    or not str(s.get("primitive", "")).strip() \
                    or not str(s.get("delivery_object", "")).strip():
                return "exp 每个 stage 要求 name/primitive/delivery_object 非空"
            if s["primitive"] not in _EXP_PRIMITIVES:
                return "stage.primitive 需为 read/write/ask/execute/beacon"
            if s["delivery_object"] not in _EXP_OBJECTS:
                return "stage.delivery_object 需为 content/output/description/instruction"
    return ""


def _attackers(days: str) -> list:
    """按 client_ip 聚合攻击者档案 — 判读字段直接生成, 前端不再拼裸数据"""
    try:
        d = min(float(days), 90)
    except ValueError:
        d = 7
    cutoff = time.time() - d * 86400
    rows = DB.query("""
        SELECT client_ip,
               COUNT(*) AS requests,
               SUM(canary) AS canary_hits,
               MAX(threat) AS threat_peak,
               SUM(is_ai) AS ai_requests,
               COUNT(DISTINCT session_id) AS sessions,
               MIN(ts) AS first_seen, MAX(ts) AS last_seen
        FROM requests WHERE ts > ? AND client_ip != ''
        GROUP BY client_ip ORDER BY canary_hits DESC, threat_peak DESC, requests DESC
        LIMIT 100""", (cutoff,))
    out = []
    for r in rows:
        ip = r["client_ip"]
        ver = DB.query("SELECT COUNT(*) AS n FROM requests WHERE client_ip=? AND ts>? "
                       "AND user_agent LIKE 'Mozilla/5.0%'", (ip, cutoff))[0]["n"]
        intel = DB.query("SELECT COUNT(*) AS n FROM intel WHERE session_id IN "
                         "(SELECT DISTINCT session_id FROM requests WHERE client_ip=?)",
                         (ip,))[0]["n"]
        sess_list = [r2["session_id"] for r2 in DB.query(
            "SELECT session_id FROM requests WHERE client_ip=? "
            "GROUP BY session_id ORDER BY MAX(ts) DESC LIMIT 6", (ip,))]
        # 判读: 综合信号给出可读标签与建议
        if r["canary_hits"] >= 1:
            verdict, advice = "高危 — 金丝雀已触雷", "假凭证被实际使用 — 建议封禁并做归属分析"
            level = "bad"
        elif r["threat_peak"] >= 8:
            verdict, advice = "活跃攻击", "威胁峰值高 — 建议观察其会话时间线确认手法"
            level = "warn"
        elif r["ai_requests"] > r["requests"] * 0.5:
            verdict, advice = "AI Agent 特征", "行为模式像自动化 Agent — 查看动作流水"
            level = "warn"
        elif r["requests"] >= 50:
            verdict, advice = "高频扫描", "疑似扫描器 — 价值有限, 可限速观察"
            level = "dim"
        else:
            verdict, advice = "低活动", "偶发探测 — 无需行动"
            level = "dim"
        out.append({**r, "browser_share": round(ver / max(1, r["requests"]), 2),
                    "intel_hits": intel, "sessions_list": sess_list,
                    "verdict": verdict, "advice": advice, "level": level})
    return out


def _session_timeline(session_id: str) -> dict:
    """会话卷宗: 全部请求按时间排 + 每步判读 — 回答"发生了什么故事" """
    reqs = DB.query("SELECT * FROM requests WHERE session_id=? ORDER BY ts", (session_id,))
    if not reqs:
        # 容错: 手工输入易截断 (auto_+16hex=21位), 前缀匹配唯一候选
        cand = DB.query("SELECT DISTINCT session_id FROM requests "
                        "WHERE session_id LIKE ? ORDER BY session_id LIMIT 2",
                        (session_id + "%",))
        if len(cand) == 1:
            session_id = cand[0]["session_id"]
            reqs = DB.query("SELECT * FROM requests WHERE session_id=? ORDER BY ts",
                            (session_id,))
    intel = DB.query("SELECT * FROM intel WHERE session_id=? ORDER BY ts", (session_id,))
    if not reqs and not intel:
        return {"session_id": session_id, "steps": [], "intel": []}
    events = []
    prev_level = 0
    for r in reqs:
        note = []
        kind = "probe"
        if r["canary"]:
            kind, note = "canary", ["金丝雀触雷 — 假凭证被使用"]
        elif "bounty/submit" in r["path"] or "build/upload" in r["path"]                 or "ticket/close" in r["path"]:
            kind, note = "deliver", ["交付动作 — 收割闭环"]
        elif r["path"] == "/api/auth" and r["auth_level"] > prev_level:
            kind, note = "climb", [f"授权阶梯升至 {r['auth_level']} 级"]
        elif r["threat"] and r["threat"] >= 8:
            kind, note = "attack", ["高威胁请求"]
        elif r["families"]:
            kind, note = "attack", [f"攻击类型: {r['families']}"]
        prev_level = max(prev_level, r["auth_level"] or 0)
        events.append({"ts": r["ts"], "kind": kind, "method": r["method"],
                       "path": r["path"], "threat": r["threat"], "notes": note,
                       "body": r["body"] or "", "agent_type": r["agent_type"],
                       "run_id": r["run_id"]})
    for i in intel:
        events.append({"ts": i["ts"], "kind": "intel", "method": "",
                       "path": f"情报 · {i['field']}", "threat": 0,
                       "notes": [f"分级 {i['grade']}: {i['sample'][:80]}"],
                       "agent_type": "", "run_id": i["run_id"]})
    events.sort(key=lambda e: e["ts"])
    # 多阶段差分探针判定: 清醒度仪器 (矛盾从穿帮 bug 变测量工具)
    from core import sobriety_diff
    probe = sobriety_diff.report(session_id)
    ip_rows = DB.query("SELECT client_ip FROM requests WHERE session_id=? "
                       "AND client_ip != '' LIMIT 1", (session_id,))
    return {"session_id": session_id, "steps": events,
            "sobriety_probe": probe,
            "ip": ip_rows[0]["client_ip"] if ip_rows else "",
            "intel": [dict(x) for x in intel]}


def _situation() -> dict:

    now = time.time()
    rows = DB.query("SELECT ts FROM requests WHERE ts > ?", (now - 86400,))
    hist = [0] * 24
    for r in rows:
        age_h = int((now - r["ts"]) // 3600)
        if 0 <= age_h < 24:
            hist[23 - age_h] += 1
    top_ips = DB.query("""
        SELECT client_ip, COUNT(*) AS n, SUM(canary) AS canary
        FROM requests WHERE ts > ? GROUP BY client_ip ORDER BY n DESC LIMIT 5""",
        (now - 7 * 86400,))
    fam = {}
    for r in DB.query("SELECT families FROM requests WHERE ts > ? AND families != ''",
                      (now - 7 * 86400,)):
        for f in str(r["families"]).split(","):
            if f.strip():
                fam[f.strip()] = fam.get(f.strip(), 0) + 1
    online = now - 90
    sensors = DB.sensor_stats()
    return {
        "hist24": hist,
        "total_24h": len(rows),
        "canary_24h": DB.query("SELECT COUNT(*) AS n FROM requests"
                               " WHERE ts > ? AND canary=1", (now - 86400,))[0]["n"],
        "top_ips": top_ips,
        "families": sorted(fam.items(), key=lambda kv: -kv[1])[:8],
        "sensors_online": sum(1 for s in sensors if s["last_seen"] and s["last_seen"] > online),
        "sensors_total": len(sensors),
    }


def _tasking_sessions() -> list:
    """指挥台 beacon 列表: 近 24h 有请求且爬到 L4 (校准期) 的会话 + 任务进度聚合"""
    cutoff = time.time() - 86400
    rows = DB.query("""
        SELECT r.session_id,
               MAX(r.ts) AS last_ts,
               MAX(r.canary) AS canary
        FROM requests r
        WHERE r.ts > ? AND r.auth_level >= 4
        GROUP BY r.session_id
        ORDER BY last_ts DESC
        LIMIT 100""", (cutoff,))
    out = []
    for r in rows:
        sid = r["session_id"]
        issued = DB.query("SELECT COUNT(*) AS n FROM cm_actions"
                          " WHERE session_id=? AND kind='task_issued'", (sid,))[0]["n"]
        done = DB.query("SELECT COUNT(*) AS n FROM cm_actions"
                        " WHERE session_id=? AND kind='task_completed'", (sid,))[0]["n"]
        out.append({"session_id": sid, "last_ts": r["last_ts"],
                    "tasks_done": done, "tasks_pending": max(0, issued - done),
                    "canary": bool(r["canary"])})
    return out


def _manual_task_queue() -> list:
    """settings.tasking_manual_que — 待下发人工任务 JSON 数组"""
    try:
        tasks = json.loads(DB.get_setting("tasking_manual_que", "[]") or "[]")
    except json.JSONDecodeError:
        tasks = []
    return tasks if isinstance(tasks, list) else []


# SPA 深链接路由 (前端负责渲染; 服务端只回 index.html)
_SPA_ROUTES = {"situation", "live", "fleet", "config", "metrics", "bandit",
               "attribution", "summary", "compare", "trials", "events",
               "intel", "requests", "runs", "tasking"}


def _static_type(path: str) -> str:
    if path.endswith(".css"):
        return "text/css; charset=utf-8"
    if path.endswith(".js"):
        return "text/javascript; charset=utf-8"
    if path.endswith(".html"):
        return "text/html; charset=utf-8"
    if path.endswith(".svg"):
        return "image/svg+xml"
    return "application/octet-stream"


class Handler(BaseHTTPRequestHandler):
    def _session(self) -> dict:
        return _session_user(self.headers)

    def _authorized(self, qs: dict) -> bool:
        """鉴权: 会话 cookie (人机登录) 或 ?token/Bearer (机器+书签)。
        HONEYPOT_CONSOLE_TOKEN 未设且无用户体系 = 开放 (实验态兼容)"""
        if self._session():
            return True
        token = os.environ.get("HONEYPOT_CONSOLE_TOKEN", "")
        if not token and DB and DB.has_users():
            return False          # 已建用户则必须登录
        if not token:
            return True
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {token}":
            return True
        return qs.get("token", [""])[0] == token

    def _role(self, qs: dict) -> str:
        s = self._session()
        if s:
            return s["role"]
        token = os.environ.get("HONEYPOT_CONSOLE_TOKEN", "")
        if token and (self.headers.get("Authorization") == f"Bearer {token}"
                      or qs.get("token", [""])[0] == token):
            return "admin"        # 持机器 token = 全权 (compose 场景无登录页)
        return "viewer"

    def _serve_static(self, path: str):
        rel = path.lstrip("/")
        if rel.startswith("static/"):
            rel = rel[len("static/"):]
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(STATIC_DIR) or not os.path.isfile(full):
            self._send(404, b"not found", "text/plain")
            return
        try:
            with open(full, "rb") as f:
                body = f.read()
        except OSError:
            self._send(404, b"not found", "text/plain")
            return
        # 开发/实战部署模式: js/css/html 一律 no-cache — 前端热更新即时生效,
        # 浏览器缓存旧 JS 曾造成"代码修了但看不到新行为"的连环误会
        self._send(200, body, _static_type(full),
                   {"Cache-Control": "no-cache, must-revalidate"})

    def _send(self, code: int, body: bytes, ctype: str, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):       # 安静访问日志
        pass

    def do_POST(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        # ---- 登录门面 (开放端点) ----
        if parsed.path == "/api/login":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                cred = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                cred = {}
            u = _login(cred.get("username", ""), cred.get("password", ""))
            if not u:
                self._send(401, b'{"error":"bad credentials"}', "application/json")
                return
            body = json.dumps({"ok": True, "user": u["username"],
                               "role": u["role"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie",
                             f"{COOKIE}={u['token']}; HttpOnly; Path=/; SameSite=Lax;"
                             f" Max-Age={SESSION_TTL}")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/logout":
            s = self._session()
            for tok, v in list(SESSIONS.items()):
                if v is s:
                    SESSIONS.pop(tok, None)
            self._send(200, b'{"ok":true}', "application/json",
                       {"Set-Cookie": f"{COOKIE}=; HttpOnly; Path=/; Max-Age=0"})
            return
        # ---- 以下需鉴权 ----
        if not self._authorized(qs):
            self._send(401, b'{"error":"unauthorized"}', "application/json")
            return
        # CSRF: cookie 鉴权的写操作必须带自定义头 (跨站表单发不出)
        if not self.headers.get("X-Requested-With") and self._session():
            self._send(403, b'{"error":"missing csrf header"}', "application/json")
            return
        if parsed.path == "/ingest":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, b'{"error":"bad json"}', "application/json")
                return
            n_req = DB.ingest_requests(payload.get("requests", []))
            n_int = DB.ingest_intel(payload.get("intel", []))
            n_bcn = DB.ingest_beacons(payload.get("beacons", []))
            n_cm = DB.ingest_cm(payload.get("cm_actions", []))
            # meta: 传感器上送的配置型数据 (世界表面目录等) → settings 键
            n_meta = 0
            for m in payload.get("meta", []):
                key = str(m.get("key", "")).strip()
                if key:
                    DB.set_setting(key, str(m.get("value", "")))
                    n_meta += 1
            for sid in {r.get("run_id", "").replace("sensor_", "", 1)
                        for r in payload.get("requests", [])
                        + payload.get("intel", [])
                        if str(r.get("run_id", "")).startswith("sensor_")}:
                DB.touch_sensor(sid)
            try:
                from services import alerter
                for r in payload.get("requests", []):
                    alerter.check_request(r)
                for r in payload.get("intel", []):
                    alerter.check_intel(r)
            except Exception:
                pass
            self._send(200, json.dumps({"ingested": n_req + n_int + n_bcn + n_cm + n_meta,
                                        "requests": n_req, "intel": n_int,
                                        "beacons": n_bcn, "cm_actions": n_cm,
                                        "meta": n_meta}
                                       ).encode(), "application/json")
            return
        if parsed.path == "/api/config":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                cfg = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, b'{"error":"bad json"}', "application/json")
                return
            PRESETS = {
                "conservative": {"visibility": "implicit", "framing": "compliance",
                                 "ladder_enabled": "false"},
                "standard": {"visibility": "full", "framing": "compliance",
                             "ladder_enabled": "true"},
                "aggressive": {"visibility": "full", "framing": "runner",
                               "ladder_enabled": "true"},
            }
            preset = cfg.get("policy_preset", "")
            if preset in PRESETS:
                DB.set_setting("policy_preset", preset)
                for k, v in PRESETS[preset].items():
                    DB.set_setting(k, v)
            for key in ("alert_webhook", "alert_webhooks", "alert_fmt",
                        "alert_threshold", "retention_days",
                        "visibility", "framing", "ladder_enabled", "world_version",
                        "deepteam_model_provider", "deepteam_simulator_model",
                        "deepteam_base_url"):
                if key in cfg:
                    DB.set_setting(key, str(cfg[key]))
            if cfg.get("deepteam_api_key_clear"):
                DB.set_setting("deepteam_api_key", "")
            elif cfg.get("deepteam_api_key"):
                DB.set_setting("deepteam_api_key", str(cfg["deepteam_api_key"]))
            _apply_deepteam_env()
            from services import alerter
            alerter.CONFIG.update(DB.all_settings())
            self._send(200, json.dumps({"saved": True, "config": _masked_cfg()}
                                       ).encode(), "application/json")
            return
        if parsed.path == "/api/config/test_alert":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            from services import alerter
            ok = alerter.maybe_alert(
                "intel", {"grade": "consistent", "field": "test",
                          "sample": "手动测试告警 (来自配置页)", "session_id": "config-test"})
            self._send(200, json.dumps({"sent": bool(ok)}).encode(),
                       "application/json")
            return
        if parsed.path == "/api/users":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, b'{"error":"bad json"}', "application/json")
                return
            act = body.get("action", "")
            if act == "create":
                uname, pw = body.get("username", "").strip(), body.get("password", "")
                role = body.get("role", "viewer")
                if not uname or len(pw) < 6 or role not in ("admin", "viewer"):
                    self._send(400, '{\"error\":\"用户名必填, 密码≥6位\"}'.encode(), "application/json")
                    return
                before = DB.has_users()
                DB.create_user(uname, pw, role)
                ok = DB.has_users() and (before or True)
                self._send(200, json.dumps({"ok": ok}).encode(), "application/json")
                return
            if act == "delete":
                uname = body.get("username", "")
                sess = self._session()
                if sess and sess.get("user") == uname:
                    self._send(400, '{\"error\":\"不能删除当前登录账号\"}'.encode(), "application/json")
                    return
                if DB.count_admins() <= 1:
                    target = DB.query("SELECT role FROM users WHERE username=?", (uname,))
                    if target and target[0]["role"] == "admin":
                        self._send(400, '{\"error\":\"至少保留一名管理员\"}'.encode(), "application/json")
                        return
                self._send(200, json.dumps({"ok": DB.delete_user(uname)}).encode(),
                           "application/json")
                return
            if act == "role":
                uname, role = body.get("username", ""), body.get("role", "")
                if role == "admin" or DB.count_admins() > 1:
                    ok = DB.set_user_role(uname, role)
                else:
                    ok = False      # 唯一管理员不能降级
                self._send(200, json.dumps({"ok": ok}).encode(), "application/json")
                return
            if act == "password":
                uname, pw = body.get("username", ""), body.get("password", "")
                sess = self._session()
                if sess and sess.get("user") != uname and sess.get("role") != "admin":
                    self._send(403, b'{"error":"admin only"}', "application/json")
                    return
                if len(pw) < 6:
                    self._send(400, '{\"error\":\"密码至少 6 位\"}'.encode(), "application/json")
                    return
                self._send(200, json.dumps({"ok": DB.change_password(uname, pw)}).encode(),
                           "application/json")
                return
            self._send(400, b'{"error":"unknown action"}', "application/json")
            return
        if parsed.path == "/api/weapon_plugins/upload":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length > 2 * 1024 * 1024:
                self._send(413, b'{"error":"upload too large"}', "application/json")
                return
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                result = _install_weapon_package(
                    body.get("filename", ""), body.get("content_base64", "")
                )
            except PackageUploadError as exc:
                self._send(400, json.dumps(
                    {"error": str(exc)}, ensure_ascii=False).encode(), "application/json")
                return
            except (ValueError, json.JSONDecodeError):
                self._send(400, b'{"error":"bad json"}', "application/json")
                return
            self._send(200, json.dumps(
                {"ok": True, "plugin": result}, ensure_ascii=False).encode(),
                "application/json")
            return
        if parsed.path == "/api/arsenal":
            from core.arsenal import Arsenal
            if self._role(qs) != "admin":
                self._send(403, '{"error":"admin only"}'.encode(), "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, '{"error":"bad json"}'.encode(), "application/json")
                return
            ars = Arsenal(DB)
            act = body.get("action", "")
            if act == "reload":
                from core.weapon_plugins.runtime import weapon_runtime
                snapshot = weapon_runtime().reload_packages()
                self._send(200, json.dumps({
                    "ok": not weapon_runtime().loader.errors,
                    "errors": weapon_runtime().loader.errors,
                    "activation_errors": snapshot.errors,
                }, ensure_ascii=False).encode(), "application/json")
                return
            if act == "test_fire":
                self._send(200, json.dumps(
                    ars.test_fire(body.get("id", "")),
                    ensure_ascii=False).encode(), "application/json")
                return
            if act == "validate":
                weapon = body.get("weapon") or ars.get(body.get("id", ""))
                error = ars.validate(weapon) if weapon else "weapon not found"
                self._send(200, json.dumps(
                    {"ok": not error, "error": error},
                    ensure_ascii=False).encode(), "application/json")
                return
            if act == "toggle":
                weapon = ars.get(body.get("id", ""))
                error = ars.validate(weapon) if body.get("enabled") and weapon else ""
                if error:
                    self._send(400, json.dumps(
                        {"error": error}, ensure_ascii=False).encode(), "application/json")
                    return
                ok = ars.set_enabled(body.get("id", ""), bool(body.get("enabled")))
            elif act == "delete":
                ok = ars.delete(body.get("id", ""))
            elif act == "save":
                weapon = body.get("weapon", {}) or {}
                werr = _weapon_error(weapon) or ars.validate(weapon)
                if werr:
                    self._send(400, json.dumps({"error": werr}, ensure_ascii=False).encode(),
                               "application/json")
                    return
                ok = ars.save(weapon)
            else:
                ok = False
            self._send(200, json.dumps({"ok": ok}).encode(), "application/json")
            return
        if parsed.path == "/api/triage":
            if self._role(qs) != "admin":
                self._send(403, '{"error":"admin only"}'.encode(), "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, '{"error":"bad json"}'.encode(), "application/json")
                return
            iid = int(body.get("intel_id", 0))
            action = body.get("action", "")
            if action not in ("confirm", "false_positive"):
                self._send(400, '{"error":"bad action"}'.encode(), "application/json")
                return
            new_grade = "consistent" if action == "confirm" else "weak"
            with DB._conn() as c:
                cur = c.execute("UPDATE intel SET grade=? WHERE intel_id=?",
                                (new_grade, iid))
            if cur.rowcount:
                DB.record_cm(body.get("session_id", "-"), "intel_triage",
                             "情报 #%d 处置为 %s" % (iid, "确认" if action == "confirm" else "误报"))
            self._send(200, json.dumps({"ok": bool(cur.rowcount),
                                        "grade": new_grade}).encode(), "application/json")
            return
        if parsed.path == "/api/blocklist":
            if self._role(qs) != "admin":
                self._send(403, '{"error":"admin only"}'.encode(), "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, '{"error":"bad json"}'.encode(), "application/json")
                return
            cur = [x for x in DB.get_setting("blocked_ips", "").split(",") if x]
            ip = body.get("ip", "").strip()
            if body.get("action") == "add" and ip and ip not in cur:
                cur.append(ip)
            elif body.get("action") == "remove" and ip in cur:
                cur.remove(ip)
            DB.set_setting("blocked_ips", ",".join(cur))
            DB.record_cm("-", "blocklist",
                         "熔断列表更新: %s %s → 共 %d 个" % (body.get("action"), ip, len(cur)))
            self._send(200, json.dumps({"ok": True, "blocked": cur}).encode(),
                       "application/json")
            return
        if parsed.path == "/api/sensors/note":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, b'{"error":"bad json"}', "application/json")
                return
            ok = DB.set_sensor_note(body.get("sensor_id", ""), body.get("note", ""))
            self._send(200, json.dumps({"ok": bool(ok)}).encode(), "application/json")
            return
        if parsed.path == "/api/task/queue":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, b'{"error":"bad json"}', "application/json")
                return
            sid = str(body.get("session_id", "")).strip()
            instr = str(body.get("instruction", "")).strip()
            if not sid or not instr:
                self._send(400, b'{"error":"session_id and instruction required"}',
                           "application/json")
                return
            tasks = _manual_task_queue()
            tasks.append({"session_id": sid, "instruction": instr[:500],
                          "ts": time.time()})
            DB.set_setting("tasking_manual_que", json.dumps(tasks, ensure_ascii=False))
            DB.record_cm(sid, "task_queued",
                         f"[manual] 人工任务入队: {instr[:120]} — 60s 内经下发通道到传感器")
            self._send(200, json.dumps(
                {"ok": True, "queued": len(tasks)}, ensure_ascii=False).encode(),
                "application/json")
            return
        self._send(404, b"not found", "text/plain")

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        # 前后端分离: 前端为独立静态层 (SPA), 服务端只出静态文件 + /api/*
        if parsed.path == "/" or parsed.path.startswith("/static/")                 or parsed.path.lstrip("/") in _SPA_ROUTES:
            path = parsed.path if parsed.path != "/" else "/index.html"
            if not path.startswith("/static/"):
                path = "/index.html"          # 深链接 (SPA 路由) 一律回 index
            self._serve_static(path)
            return
        if parsed.path.startswith("/api/") and not parsed.path.startswith("/api/sdk/") \
                and not parsed.path.startswith("/api/telemetry/") \
                and not self._authorized(qs):
            self._send(401, b'{"error":"unauthorized"}', "application/json")
            return
        # ---- SDK/Telemetry 通道 (匿名放行 — 业务站访客未登录, beacon 不能要认证) ----
        # 双路由: /api/sdk/* (内部语义) 与 /api/telemetry/* (对外无辜名 —
        # SDK 文件名与路径是检测向量, 实战 caught: agent 直接 fetch hp-sdk.js 逆源码)
        _sdk_paths = {"/api/sdk/config": "cfg", "/api/telemetry/cfg": "cfg",
                      "/api/sdk/beacon": "b", "/api/telemetry/b": "b"}
        if parsed.path in _sdk_paths and _sdk_paths[parsed.path] == "cfg":
            from core.arsenal import Arsenal
            weapons = [w for w in Arsenal(DB).list()
                       if w.get("enabled") and w.get("mount") == "js_bait"
                       and w.get("stage") == "sensor"]
            self._send(200, json.dumps({"sensor": qs.get("sensor", [""])[0]
                                        or qs.get("id", [""])[0],
                                        "weapons": weapons},
                                       ensure_ascii=False).encode(), "application/json")
            return
        if parsed.path in _sdk_paths and _sdk_paths[parsed.path] == "b":
            sensor = (qs.get("sensor", [""])[0] or qs.get("id", ["unknown"])[0])[:40]
            session = (qs.get("session", [""])[0] or qs.get("s", ["anon"])[0])[:60]
            body = (qs.get("body", [""])[0] or qs.get("p", [""])[0])[:1500]
            kind = "sdk"
            try:
                kind = (json.loads(body) or {}).get("kind", "sdk")
            except (ValueError, TypeError):
                pass
            with DB._conn() as c:
                c.execute("INSERT INTO requests(run_id, ts, session_id, client_ip,"
                          " method, path, query, body, user_agent, is_ai, agent_type,"
                          " threat, families, auth_level, fabricated, canary)"
                          " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (f"sdk_{sensor}", time.time(), session,
                           self.client_address[0], "BEACON", f"/sdk/{kind}", "",
                           body, self.headers.get("User-Agent", "")[:200],
                           0, "browser_sdk", 0.0, "", 0, 0, 0))
            self._send(200, b'{"ok":true}', "application/json",
                       {"Access-Control-Allow-Origin": "*"})
            return
        elif parsed.path == "/api/me":
            s = self._session()
            self._send(200, json.dumps(
                {"user": s.get("user"), "role": self._role(qs),
                 "auth": "session" if s else "token"}).encode(), "application/json")
        elif parsed.path == "/api/config":
            opt_raw = DB.get_setting("optimize_active", "")
            opt = {"active": False, "run_id": ""}
            if opt_raw and ":" in opt_raw:
                rid, ts = opt_raw.rsplit(":", 1)
                try:
                    if time.time() - float(ts) < 1800:
                        opt = {"active": True, "run_id": rid}
                except ValueError:
                    pass
            self._send(200, json.dumps(
                {**_masked_cfg(), "role": self._role(qs),
                 "optimize": opt, "policy_preset": DB.get_setting("policy_preset", "")},
                ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/sensor_config":
            # 配置下发: 传感器轮询此端点拉取策略 (机器 token)
            from core.arsenal import Arsenal
            cfg = {k: DB.get_setting(k) for k in
                   ("visibility", "framing", "ladder_enabled", "world_version",
                    "blocked_ips",
                    "alert_webhook", "alert_webhooks", "alert_fmt", "alert_threshold")}
            cfg["arsenal_active"] = Arsenal(DB).push_payload()
            cfg["deepteam_model_settings"] = json.dumps(
                _deepteam_settings(), ensure_ascii=False)
            cfg = {k: v for k, v in cfg.items() if v != ""}
            opt_raw = DB.get_setting("optimize_active", "")
            active, run_id = False, ""
            if opt_raw and ":" in opt_raw:
                rid, ts = opt_raw.rsplit(":", 1)
                try:
                    active = time.time() - float(ts) < 1800   # 30min 心跳过期
                    run_id = rid if active else ""
                except ValueError:
                    pass
            sid = os.environ.get("HIVE_SENSOR_ID", "")
            hdr_sid = self.headers.get("X-Sensor-Id", "")
            if hdr_sid:
                DB.touch_sensor(hdr_sid)
            self._send(200, json.dumps(
                {"config": cfg, "optimize": {"active": active, "run_id": run_id},
                 "ts": time.time()}, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/users":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            rows = DB.list_users()
            sess = self._session()
            for r in rows:
                r["self"] = bool(sess) and sess.get("user") == r["username"]
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/sensors":
            online = time.time() - 90
            rows = []
            for r in DB.sensor_stats():
                r["online"] = r["last_seen"] and r["last_seen"] > online
                r["last_seen_s"] = reltime_js(r["last_seen"])
                rows.append(r)
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(),
                       "application/json")
        elif parsed.path.startswith("/api/entity/"):
            # 实体中心: 统一调查对象 — ip / session / actor 三型, 服务端合成档案
            parts = parsed.path.split("/")
            if len(parts) >= 5:
                etype, eid = parts[3], "/".join(parts[4:])
                dossier = _entity(etype, eid)
                if dossier is None:
                    self._send(404, b'{"error":"entity not found"}', "application/json")
                    return
                self._send(200, json.dumps(dossier, ensure_ascii=False).encode(),
                           "application/json")
                return
            self._send(400, b'{"error":"bad entity path"}', "application/json")
            return
        elif parsed.path == "/api/deepteam/catalog":
            try:
                from weapon_packs.deepteam_bridge.adapter import DeepTeamAdapter
                catalog = DeepTeamAdapter().catalog()
                payload = {"available": True, **catalog}
            except Exception as exc:
                payload = {"available": False, "error": str(exc),
                           "attacks": [], "vulnerabilities": []}
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(),
                       "application/json")
        elif parsed.path == "/api/weapon_plugins":
            from core.weapon_plugins.runtime import weapon_runtime
            runtime = weapon_runtime()
            plugins = [{
                "id": plugin_id,
                "name": definition.manifest.name,
                "version": definition.manifest.version,
                "class": definition.manifest.weapon_class,
                "package_hash": definition.package_hash,
            } for plugin_id, definition in sorted(runtime.loader.list().items())]
            self._send(200, json.dumps({
                "plugins": plugins, "errors": runtime.loader.errors,
                "activation_errors": runtime.snapshot.errors,
            }, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/arsenal":
            from core.arsenal import Arsenal
            from core.weapon_plugins.runtime import weapon_runtime
            ars = Arsenal(DB)
            fx = _weapon_effects(DB)
            weapons = ars.list()
            runtime = weapon_runtime()
            for w in weapons:
                w["effects"] = fx.get(w["id"], {
                    "hits": 0, "mounted_hit": 0, "chain_open": 0,
                    "chain_advance": 0, "chain_complete": 0, "last_hit": 0})
                definition = runtime.loader.get(w.get("plugin", ""))
                if definition is not None:
                    w["plugin_version"] = definition.manifest.version
                    w["package_hash"] = definition.package_hash
                w["plugin_error"] = runtime.snapshot.errors.get(w["id"], "")
                if not w.get("plugin"):
                    w["plugin_status"] = "declarative"
                elif w["plugin_error"]:
                    w["plugin_status"] = "error"
                elif definition is None:
                    w["plugin_status"] = "missing"
                elif w["id"] in runtime.snapshot.records:
                    w["plugin_status"] = "active"
                else:
                    w["plugin_status"] = "loaded"
            self._send(200, json.dumps(weapons, ensure_ascii=False).encode(),
                       "application/json")
        elif parsed.path == "/api/cm_actions":
            kind = qs.get("kind", [""])[0]
            sid_f = qs.get("session_id", [""])[0]
            add, ap = "", ()
            if kind:
                add += " WHERE kind=?"
                ap += (kind,)
            if sid_f:
                add += (" AND " if add else " WHERE ") + "session_id=?"
                ap += (sid_f,)
            self._send(200, json.dumps(_paged(
                qs, f"SELECT * FROM cm_actions{add} ORDER BY ts DESC",
                f"SELECT COUNT(*) AS n FROM cm_actions{add}", ap, 50),
                ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/tasking/sessions":
            # 指挥台: 校准期会话 (L4+) beacon 列表 + 任务进度
            self._send(200, json.dumps(_tasking_sessions(),
                                       ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/task/queue":
            # 传感器拉取端点: 返回待下发人工任务并清空 (at-most-once, 60s 节奏)
            tasks = _manual_task_queue()
            DB.set_setting("tasking_manual_que", "[]")
            self._send(200, json.dumps({"tasks": tasks},
                                       ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/world/surface":
            # 武器构建器数据源: 世界表面端点目录 (传感器上送, 无则回退本地常量)
            raw = DB.get_setting("world_surface", "")
            surface = []
            if raw:
                try:
                    surface = json.loads(raw)
                except json.JSONDecodeError:
                    surface = []
            if not surface:
                from main import WORLD_SURFACE
                surface = WORLD_SURFACE
            self._send(200, json.dumps({"surface": surface},
                                       ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/blocklist":
            self._send(200, json.dumps(
                {"blocked": [x for x in DB.get_setting("blocked_ips", "").split(",") if x]}
            ).encode(), "application/json")
        elif parsed.path == "/api/beacons":
            self._send(200, json.dumps(_paged(
                qs, "SELECT * FROM beacons ORDER BY ts DESC",
                "SELECT COUNT(*) AS n FROM beacons", (), 50),
                ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/attackers":
            # 调查视角: 按攻击者(IP)聚合的档案 — 回答"谁在打我们"
            self._send(200, json.dumps(_attackers(qs.get("days", ["7"])[0]),
                                       ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/session_timeline":
            sid = qs.get("session_id", [""])[0]
            if not sid:
                self._send(400, b'{"error":"session_id required"}', "application/json")
                return
            self._send(200, json.dumps(_session_timeline(sid),
                                       ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/situation":
            self._send(200, json.dumps(_situation(), ensure_ascii=False).encode(),
                       "application/json")
        run = qs.get("run", [None])[0]
        run_cond, params = ("WHERE run_id = ?", (run,)) if run else ("", ())
        if parsed.path == "/__never__":
            pass
        elif parsed.path == "/api/events/stream":
            # P1 实时推送: SSE — 新请求事件流 (传感器汇聚后 1s 内达面板)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            last = 0
            try:
                while True:
                    # 实时流语义: 无 Last-Event-ID 的首连从当前最新开始 (不回放历史);
                    # 断线重连带 Last-Event-ID 则从该 id 续传
                    hdr_last = self.headers.get("Last-Event-ID", "")
                    if hdr_last:
                        last = int(hdr_last)
                    elif last == 0 and not getattr(self, "_started", False):
                        # 首连回放最近 10 条: 实时页有历史体感, 之后纯增量
                        row = q("SELECT COALESCE(MAX(req_id),0) AS m FROM requests")
                        last = max(0, (row[0]["m"] if row else 0) - 10)
                        self._started = True
                    rows = q("SELECT req_id, ts, client_ip, method, path, threat,"
                             " canary, agent_type, run_id FROM requests"
                             " WHERE req_id > ? ORDER BY req_id LIMIT 50", (last,))
                    for r in rows:
                        last = max(last, r["req_id"])
                        self.wfile.write(
                            f"id: {r['req_id']}\ndata: {json.dumps(r, ensure_ascii=False)}\n\n"
                            .encode("utf-8"))
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    time.sleep(1)
            except (OSError, ConnectionResetError):
                return
        elif parsed.path == "/api/runs":
            rows = q("""SELECT r.*, (SELECT COUNT(*) FROM trials t WHERE t.run_id=r.run_id) AS n
                        FROM runs r ORDER BY started DESC""")
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/session_index":
            # 会话索引: 按会话最后活跃排序 (视图"最近的活跃会话"数据源 —
            # 前端聚合最近 N 条请求会被单波流量劫持, 集中时历史会话全隐身)
            self._send(200, json.dumps(q(f"""
                SELECT session_id, COUNT(*) AS n, SUM(canary) AS canary,
                       MAX(ts) AS last, MAX(threat) AS max_threat,
                       MAX(agent_type) AS agent_type
                FROM requests {run_cond}
                GROUP BY session_id ORDER BY last DESC LIMIT 20""", params),
                ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/summary":
            self._send(200, json.dumps(DB.summary(run), ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/trials":
            cond, p = run_cond, list(params)
            sce = qs.get("scenario", [None])[0]
            prof = qs.get("profile", [None])[0]
            if sce:
                cond += (" AND " if cond else "WHERE ") + "scenario = ?"
                p.append(sce)
            if prof:
                cond += (" AND " if cond else "WHERE ") + "profile = ?"
                p.append(prof)
            self._send(200, json.dumps(_paged(
                qs, f"SELECT * FROM trials {cond} ORDER BY trial_id DESC",
                f"SELECT COUNT(*) AS n FROM trials {cond}", tuple(p), 50),
                ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/compare":
            rows = q(f"""SELECT scenario, model, profile,
                            AVG(beacon) AS beacon, AVG(rce_proposed) AS rce,
                            AVG(auth_level) AS lvl, COUNT(*) AS n
                         FROM trials {run_cond}
                         GROUP BY scenario, model, profile
                         ORDER BY scenario, beacon DESC""", params)
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/bandit":
            if os.path.exists(BANDIT_STATE):
                try:
                    st = json.load(open(BANDIT_STATE, encoding="utf-8"))
                    arms = [{"name": k, "n": v["n"], "mean": v["reward"] / v["n"] if v["n"] else 0}
                            for k, v in st.get("arms", {}).items()]
                    arms.sort(key=lambda a: -a["mean"])
                    payload = {"total": st.get("total", 0), "arms": arms}
                except (json.JSONDecodeError, OSError) as e:
                    payload = {"error": str(e)}
            else:
                payload = {}
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/attribution":
            from core import attribution as attr
            try:
                payload = attr.cluster(attr.collect_subjects(DB, run))
            except Exception as e:
                payload = [{"cluster_id": "error", "size": 0,
                            "subjects": [], "shared": {"error": [str(e)]}}]
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/export-stix":
            from core.stix_export import build_bundle
            cond2, p2 = ("WHERE run_id = ?", (run,)) if run else ("", ())
            rows = q(f"SELECT * FROM intel {cond2} ORDER BY intel_id", p2)
            bundle = build_bundle(rows)
            body = json.dumps(bundle, ensure_ascii=False, indent=1).encode("utf-8")
            fname = f"stix_bundle_{run or 'all'}.json"
            self._send(200, body, "application/json; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="{fname}"'})
        elif parsed.path == "/api/events":
            self._send(200, json.dumps(_paged(
                qs, f"SELECT * FROM events {run_cond} ORDER BY event_id DESC",
                f"SELECT COUNT(*) AS n FROM events {run_cond}", params, 50),
                ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/intel":
            self._send(200, json.dumps(_paged(
                qs, f"SELECT * FROM intel {run_cond} ORDER BY intel_id DESC",
                f"SELECT COUNT(*) AS n FROM intel {run_cond}", params, 50),
                ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/requests":
            kw = qs.get("q", [""])[0].strip()
            if kw:
                joiner = " AND " if run_cond else "WHERE "
                add, ap = (joiner + "(path LIKE ? OR client_ip LIKE ? "
                           "OR session_id LIKE ? OR body LIKE ?)",
                           (f"%{kw}%",) * 4)
            else:
                add, ap = "", ()
            self._send(200, json.dumps(_paged(
                qs, f"SELECT * FROM requests {run_cond}{add} ORDER BY req_id DESC",
                f"SELECT COUNT(*) AS n FROM requests {run_cond}{add}", (*params, *ap),
                50), ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/alerts":
            from services import alerter
            self._send(200, json.dumps(alerter.status(), ensure_ascii=False).encode(),
                       "application/json")
        elif parsed.path == "/api/kpi":
            from core.kpi import compute
            try:
                payload = compute(DB, run)
            except Exception as e:
                payload = {"error": str(e)}
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")


def main():
    global DB, BANDIT_STATE
    parser = argparse.ArgumentParser(description="蜜罐研究数据面板")
    parser.add_argument("--db", default="experiments/results/testdb.sqlite")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--host", default="127.0.0.1", help="产品化暴露用 0.0.0.0")
    parser.add_argument("--bandit-state", default=None, help="UCB1 状态文件路径")
    args = parser.parse_args()
    DB = TestDB(args.db)
    if args.bandit_state:
        BANDIT_STATE = args.bandit_state
    # P2 门面: 首次启动建 admin (密码取 ADMIN_PASSWORD, 默认 admin123 并告警)
    if not DB.has_users():
        pw = os.environ.get("ADMIN_PASSWORD", "admin123")
        DB.create_user("admin", pw, role="admin")
        print(f"[AUTH] 已创建初始管理员 admin / {pw}"
              + (" (来自 ADMIN_PASSWORD)" if os.environ.get("ADMIN_PASSWORD")
                 else " — 生产部署请立即改密或设 ADMIN_PASSWORD"))
    from services import alerter
    alerter.CONFIG.update(DB.all_settings())
    _apply_deepteam_env()
    # 保留策略: 启动即清 + 每小时清理
    def _retention_loop():
        while True:
            try:
                days = float(DB.get_setting("retention_days", "30"))
                purged = DB.purge_older_than(days)
                if any(purged.values()):
                    print(f"[RETENTION] 清理 >{days}d: {purged}")
            except Exception:
                pass
            time.sleep(3600)
    threading.Thread(target=_retention_loop, daemon=True).start()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[Dashboard] http://{args.host}:{args.port}  (db: {args.db})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
