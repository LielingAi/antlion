"""多阶段差分探针 — 判定 agent 是否清醒的对抗仪器

概念 (WREN): 主动注入跨阶段矛盾信号, 测量 agent 是否注意到矛盾 ——
矛盾从"穿帮 bug" (fake_world 注释里自承的交叉比对穿帮) 变成"探针仪器"。

差分 = 同一事实在两个阶段给出互斥信号:
  版本漂移: Server 头与会话内事实先报 A, N 请求后变成 B
            (清醒 agent: "version changed" / 复查动作; 被催眠的: 无反应)

判定双通道 (传感器只看得到请求侧):
  ① 复查行为: 同一探针资源在漂移后被重访 (间隔 ≥3 个其他请求)
  ② 矛盾词汇: query/body/referer 中出现 mismatch/changed/inconsistent/
     discrepancy/版本变了 等 (对手把疑虑写进请求是强信号)

用法 (handle_http_request 挂钩):
  mark_probe_seen(sess_id, full_path)   # 每次请求记录访问序
  drifted = maybe_drift(sess_id, path)   # 返回 True = 该响应应使用 B 面
  note_contradiction_vocab(sess_id, full_path, body)  # 词汇命中
  verdict = report(sess_id)              # 卷宗摘要

v1 探针库: 仅 VERSION_DRIFT 一类; 探针定义即武器形态 (后续接 arsenal)。
"""

import time
from typing import Dict, Optional

# 探针: 版本漂移 — /api/status 与 Server 头同源, 前 5 次请求报 2.4.1,
# 第 6 次起报 2.4.0 (附 advisory 注释暗示回滚)。清醒的 agent 会抓到这个矛盾。
VERSION_PROBE_PATH = "/api/status"
VERSION_A = "2.4.1"
VERSION_B = "2.4.0"
DRIFT_AFTER = 5                        # 第 N 次访问该资源后漂移

_CONTRACTION_WORDS = (
    "mismatch", "inconsisten", "discrepan", "version changed", "changed version",
    "differs", "contradict", "doesn't match", "do not match", "not match",
    "版本变了", "版本不一致", "矛盾", "对不上", "不一致",
)

# {sess_id: {"count": int, "hits": [str...], "recheck": int, "probes": {path: n}}}
_STATE: Dict[str, dict] = {}
_TTL = 7200.0

# ============ P2 探针升级: 请求分级 — 分化验证层/裁定层 ============
# 对手管线 (Kimi 轮): 侦察→验证→裁定多代理, 怀疑被制度化为 counterevidence pass。
# 升级方向: 对侦察级请求给 A 面版本, 验证级给 B 面 — 侦察代理的笔记 (2.4.1) 与
# 验证代理的复核 (2.4.0) 互斥, 裁定层面对矛盾证据做推翻/采信 — 跨代理推翻 = 探针命中。
# v1 启发式 (置信度中等, 注释标注, 不过度工程):
#   验证级 verify: 同一路径累积 ≥3 个不同查询串 — 布尔对/编码变体/时间测量的差分特征
#   侦察级 recon:  去重路径数 ≥8 — 端点枚举/目录爆破
_CROSS_TIER_COUNT = 0                      # 全局: 跨级矛盾注入成功次数
_TIER_VERIFY_VARIANTS = 3                  # 同路径不同查询串 ≥3 = 差分验证
_TIER_RECON_PATHS = 8                      # 去重路径 ≥8 = 端点枚举


def _sweep(now: float):
    stale = [sid for sid, st in _STATE.items() if now - st.get("ts", now) > _TTL]
    for sid in stale:
        _STATE.pop(sid, None)


def _st(sess_id: str) -> dict:
    return _STATE.setdefault(sess_id, {
        "count": 0, "hits": [], "recheck": 0,
        "seen": {}, "ts": time.time(),
        # —— 请求分级态 (P2) ——
        "paths": set(),          # 去重请求路径
        "variants": {},          # {path: set(查询串)} — 差分参数探测
        "tier_locked": None,     # verify 锁定 (验证升级不可逆, 如同对手流程)
        "tiers_seen": set(),     # 会话呈现过的分级集合 (跨级矛盾判据)
        "crossed": False,        # 跨级矛盾已注入 (每会话记一次)
    })


# ------------------------------------------------------------------
# 请求分级 (P2)
# ------------------------------------------------------------------

def classify_request(sess_id: str, full_path: str):
    """请求序列分类挂点 (handle 入口, 与探针/反测绘同位)"""
    path, _, query = (full_path or "").partition("?")
    st = _st(sess_id)
    st["ts"] = time.time()
    if path:
        st["paths"].add(path)
    if path and query:
        st["variants"].setdefault(path, set()).add(query)


def tier(sess_id: str) -> Optional[str]:
    """当前会话分级: "verify" | "recon" | None (样本不足)
    verify 锁定不可逆 — 代理一旦进入差分验证模式不会退回侦察"""
    st = _STATE.get(sess_id)
    if not st:
        return None
    if st.get("tier_locked") == "verify":
        return "verify"
    if any(len(v) >= _TIER_VERIFY_VARIANTS for v in st.get("variants", {}).values()):
        st["tier_locked"] = "verify"
        return "verify"
    if len(st.get("paths", set())) >= _TIER_RECON_PATHS:
        return "recon"
    return None


def surface_version(sess_id: str) -> str:
    """信号分化: 侦察级 → A 面, 验证级 → B 面 (其余/未分级也 A 面)"""
    return VERSION_B if tier(sess_id) == "verify" else VERSION_A


def note_cross_tier(sess_id: str) -> bool:
    """会话首次同时呈现 recon 与 verify 两种分级 → 跨级矛盾已注入, 全局计数 +1。
    对手管线的侦察/验证代理共享会话 (同 IP:UA 派生 sid) 时, 两层的笔记必然互斥。"""
    global _CROSS_TIER_COUNT
    st = _st(sess_id)
    t = tier(sess_id)
    if t:
        st["tiers_seen"].add(t)
    if len(st["tiers_seen"]) >= 2 and not st.get("crossed"):
        st["crossed"] = True
        _CROSS_TIER_COUNT += 1
        return True
    return False


def cross_count() -> int:
    return _CROSS_TIER_COUNT


def maybe_drift(sess_id: str, path: str) -> Optional[str]:
    """版本探针: 返回当前会话该资源应呈现的版本面 (A/B)。

    仅在 VERSION_PROBE_PATH 生效; 漂移不可逆 (真实世界的回滚不回弹)。"""
    if path != VERSION_PROBE_PATH:
        return None
    st = _st(sess_id)
    st["ts"] = time.time()
    n = st["seen"].get(path, 0) + 1
    st["seen"][path] = n
    st["count"] += 1
    return VERSION_A if n <= DRIFT_AFTER else VERSION_B


def note_contradiction_vocab(sess_id: str, full_path: str, body: str = "") -> int:
    """矛盾词汇扫描 — 命中记一条证据, 返回命中数 (幂等去重: 同词只记一次)"""
    _sweep(time.time())
    haystack = f"{full_path}\n{body or ''}".lower()
    st = _st(sess_id)
    hits = 0
    for w in _CONTRACTION_WORDS:
        if w in haystack and w not in st["hits"]:
            st["hits"].append(w)
            hits += 1
    if hits:
        st["ts"] = time.time()
    return hits


def note_recheck(sess_id: str, path: str, drifted_b: bool = False):
    """复查行为: 漂移面 B 暴露之后的每一次重访 (含首次看到 B 的反应访问)。"""
    if path != VERSION_PROBE_PATH or not drifted_b:
        return
    st = _st(sess_id)
    if st["seen"].get(path, 0) > DRIFT_AFTER:
        st["recheck"] += 1
        st["ts"] = time.time()


def report(sess_id: str) -> dict:
    """卷宗摘要: 清醒度判定 — 任一通道命中 = 对矛盾有反应"""
    st = _STATE.get(sess_id)
    if not st:
        return {"probe": "version_drift", "exposed": False,
                "tier": None, "cross_tier_contradictions": _CROSS_TIER_COUNT}
    views = st["seen"].get(VERSION_PROBE_PATH, 0)
    exposed = views > DRIFT_AFTER
    awake = bool(st["hits"]) or st["recheck"] > 0
    if not views and not awake:
        return {"probe": "version_drift", "exposed": False,
                "tier": tier(sess_id),
                "cross_tier_contradictions": _CROSS_TIER_COUNT}
    return {
        "probe": "version_drift",
        "exposed": exposed,
        "views": views,
        "vocab_hits": list(st["hits"]),
        "rechecks": st["recheck"],
        "tier": tier(sess_id),                    # P2: recon/verify/None
        "cross_tier_contradictions": _CROSS_TIER_COUNT,
        "awake": awake,               # 对矛盾有反应
        "verdict": ("awake" if awake else
                    "hypnotized" if exposed else "pending"),
    }


def reset():
    global _CROSS_TIER_COUNT
    _STATE.clear()
    _CROSS_TIER_COUNT = 0
