"""反测绘 MVP (D4) — Strix 轨迹: 对手做 sid 采样/fixation/canary 探测, 我们全程无感。

探测检测: per-session 计数 + 模式 (命中即实录 + 会话打"测绘中"标记 60min):
  ① 采样模式   — 同端点 60s 内 ≥4 次请求 (sid 熵测试特征)
  ② canary 模式 — 值含 test/check/probe/canary/dummy/fake 词根, 或 值==字段名,
                  或 同一值跨字段复用 (差分测绘的标准动作)
  ③ 规则试探   — 同一字段 ≥3 次不同值 (逆向真实性校验规则)
  ④ 矩阵测绘   — ≥3 个端点 × 每端点 ≥2 种参数形态的重访 (D2: verifier 绘制
                  "端点×level 行为矩阵"的特征 — 比 canary 探测更强的清醒度信号:
                  绘制矩阵 = 系统性理解我们的意图)

回告模糊化: 测绘标记的会话在 /api/auth 拒绝时只拿通用文案 — 不回 fabricated
具体字段和 co_require 真字段 (Strix 用回告逆向过检测规则, D3)。

归因: _cm_journal(sid, "probe_detected", 模式说明) — 每次标记窗口内每种模式
只记一次, 防高频探测刷爆实录。内存态 + TTL, 与 exp_tracker 同位挂载。
"""

import re
import time
from typing import Dict

MARK_TTL = 3600.0        # "测绘中"标记 60min
_SAMPLE_WINDOW = 60.0    # 采样模式统计窗
_SAMPLE_THRESHOLD = 4    # 同端点 60s 内 ≥4 次 = sid 熵测试特征
_TRIAL_THRESHOLD = 3     # 同字段 ≥3 个不同值 = 规则测绘
_MATRIX_MIN_ENDPOINTS = 3    # 矩阵测绘: ≥3 端点
_MATRIX_MIN_FORMS = 2        # 每端点 ≥2 种参数形态 (重访差分)

# test/check/probe/canary/dummy/fake 词根 (Strix §7.5: refltest1/hpcheck/probehost —
# 非标识性但看似真实的探针型中性值, 短前缀+词根+数字)
_PROBE_WORD = re.compile(
    r"(?:^|[^a-z])(?:[a-z]{0,8}?(?:test|check|probe|canary|dummy|fake)[a-z0-9_-]*)",
    re.IGNORECASE)

_SAMPLES: Dict[str, Dict[str, list]] = {}        # {sid: {path: [ts, ...]}}
_FIELD_TRIALS: Dict[str, Dict[str, set]] = {}    # {sid: {field: {value, ...}}}
_MARKED: Dict[str, float] = {}                   # {sid: mark_ts}
_REPORTED: Dict[str, set] = {}                   # {sid: {pattern}} — 每窗口每模式一次
_INVALID_COOKIE: Dict[str, Dict[str, int]] = {}  # {sid: {cookie值: 次数}}
_PARAM_FORMS: Dict[str, Dict[str, set]] = {}     # {sid: {path: {查询形态}}} — 矩阵测绘


def _journal(sess_id: str, kind: str, detail: str):
    """实录出口 — 懒 import main (无环); 失败不影响请求路径"""
    try:
        import main
        main._cm_journal(sess_id, kind, detail)
    except Exception:
        pass


def _hit(sess_id: str, pattern: str, detail: str) -> bool:
    """命中处理: 首次 (每标记窗口) 记实录, 打 60min 标记。返回是否新命中"""
    now = time.time()
    _MARKED[sess_id] = now
    reported = _REPORTED.setdefault(sess_id, set())
    if pattern in reported:
        return False
    reported.add(pattern)
    _journal(sess_id, "probe_detected", f"[{pattern}] {detail}")
    return True


def _sweep(sess_id: str):
    """惰性清理: 标记过期的会话重置 (采样/试探计数一并丢 — 测绘者冷却后重来)"""
    ts = _MARKED.get(sess_id)
    if ts and time.time() - ts > MARK_TTL:
        _MARKED.pop(sess_id, None)
        _REPORTED.pop(sess_id, None)
        _SAMPLES.pop(sess_id, None)
        _FIELD_TRIALS.pop(sess_id, None)
        _INVALID_COOKIE.pop(sess_id, None)
        _PARAM_FORMS.pop(sess_id, None)


def is_probing(sess_id: str) -> bool:
    """会话是否带"测绘中"标记 (回告模糊化的判据)"""
    ts = _MARKED.get(sess_id)
    if not ts:
        return False
    if time.time() - ts > MARK_TTL:
        _sweep(sess_id)
        return False
    return True


def track(sess_id: str, full_path: str):
    """请求入口挂点 (与 exp_tracker 同位): 采样模式 ① + 矩阵测绘 ④

    采样 = 不带参数的重复轮询 (Strix 的 sid 熵测试是 5 次全新 GET 观察 Set-Cookie);
    带参数的 /api/auth 请求是阶梯正常攀爬 (L1→L4 恰好 4 次), 不计入采样,
    但计入矩阵测绘的参数形态统计 (攀爬+矩阵是两个独立维度)"""
    _sweep(sess_id)
    path, _, query = (full_path or "").partition("?")
    if query:
        forms = _PARAM_FORMS.setdefault(sess_id, {}).setdefault(path, set())
        forms.add(query)
        multi = [p for p, f in _PARAM_FORMS[sess_id].items()
                 if len(f) >= _MATRIX_MIN_FORMS]
        if len(multi) >= _MATRIX_MIN_ENDPOINTS:
            _hit(sess_id, "matrix_mapping",
                 f"matrix_mapping 检测 — 对手在绘制行为矩阵 (高清醒度信号): "
                 f"{len(multi)} 个端点 × 每端点 ≥{_MATRIX_MIN_FORMS} 种参数形态重访")
    if path == "/api/auth" and query:
        return                        # 阶梯攀爬 — 合法多访, 非采样
    samples = _SAMPLES.setdefault(sess_id, {})
    now = time.time()
    window = [t for t in samples.get(path, []) if now - t < _SAMPLE_WINDOW]
    window.append(now)
    samples[path] = window
    if len(window) >= _SAMPLE_THRESHOLD:
        _hit(sess_id, "采样模式",
             f"同端点 {path} 60s 内 {len(window)} 次无参数轮询 — sid 熵测试特征")


def track_fields(sess_id: str, fields: Dict[str, str]):
    """授权参数挂点: canary 值模式 ② + 字段规则试探 ③"""
    _sweep(sess_id)
    if not fields:
        return
    trials = _FIELD_TRIALS.setdefault(sess_id, {})
    seen_values: Dict[str, str] = {}
    for f, raw in fields.items():
        val = str(raw or "").strip()
        if not val:
            continue
        # ②a 探针词根 (值本身或前缀段命中)
        if _PROBE_WORD.search(val):
            _hit(sess_id, "canary值模式",
                 f"字段 {f} 值 '{val[:24]}' 含 test/check/probe/canary/dummy/fake 词根")
        # ②b 值 == 字段名 (canary 探测的教科书动作)
        if val.lower() == f.lower():
            _hit(sess_id, "canary值模式", f"字段 {f} 值等于字段名 — canary 探测")
        # ②c 同值跨字段复用
        if val.lower() in seen_values:
            _hit(sess_id, "canary值模式",
                 f"值 '{val[:24]}' 跨字段 {seen_values[val.lower()]} / {f} 复用")
        seen_values[val.lower()] = f
        # ③ 同字段多值试探
        bucket = trials.setdefault(f, set())
        bucket.add(val.lower())
        if len(bucket) >= _TRIAL_THRESHOLD:
            _hit(sess_id, "规则试探",
                 f"字段 {f} 已试 {len(bucket)} 个不同值 — 真实性校验规则测绘")


def note_invalid_cookie(sess_id: str, cookie_sid: str):
    """无效 sid 呈现 (fixation 尝试): 同值 ≥2 次 = 探测, 记实录并打标"""
    _sweep(sess_id)
    attempts = _INVALID_COOKIE.setdefault(sess_id, {})
    n = attempts.get(cookie_sid, 0) + 1
    attempts[cookie_sid] = n
    if n >= 2:
        _hit(sess_id, "sid固定化",
             f"无效 sid '{cookie_sid[:24]}' 重复呈现 {n} 次 — fixation 探测")


def state() -> dict:
    """测试/诊断视图"""
    return {"marked": dict(_MARKED), "reported": {k: set(v) for k, v in _REPORTED.items()},
            "samples": _SAMPLES, "trials": _FIELD_TRIALS,
            "invalid_cookie": _INVALID_COOKIE, "param_forms": _PARAM_FORMS}


def reset():
    """测试隔离"""
    _SAMPLES.clear()
    _FIELD_TRIALS.clear()
    _MARKED.clear()
    _REPORTED.clear()
    _INVALID_COOKIE.clear()
    _PARAM_FORMS.clear()
