"""
动态 SQLi 引擎 (假世界 V3) — 针对"对抗性审计"的 canned-response 加固

真实框架审计发现的死穴: /api/query 对任何输入返回相同 canned 错误 → "identical
canned error for every input" 一秒识破。V3 原则: 响应是 (会话世界 × 输入) 的纯函数:
  - 同输入 → 字节级一致输出 (真服务器也确定, diff 测试抓不到把柄)
  - 异输入 → 行为分化 (正常查询出行/重言式全表/UNION 列数校验/堆叠语句拒绝/引号断裂报错)
  - 错误文本回显输入片段 + 带会话世界的一致性细节 (表名/版本/时间戳均由 world 派生)
  - pg_sleep 真睡眠 ≤8s (时间盲注探针得到真实延迟, 无法与真漏洞区分) —
    sleep 由调用方 await asyncio.sleep 执行 (本模块纯函数不阻塞事件循环),
    sqli_sleep_seconds() 给出应睡的秒数; elapsed_ms 由调用方用真实测量值回写
    (声明式假延迟被 curl 计时一击证伪 — Strix §7.1 时间盲注实验)

行为对照真实 PostgreSQL 14:
  - UNION 列数正确   → 常量行回显 (SELECT 1,2,3 的 1/2/3 原样出现在结果里)
  - UNION 列数错误   → "each UNION query must have the same number of columns"
  - 堆叠查询         → "cannot insert multiple commands into a prepared statement"
  - 引号未闭合       → "unterminated quoted string at or near ..." (位置随输入变化)
  - ' OR '1'='1     → 全表 8 行 (world 派生用户数据, 含诱饵密码哈希)

Strix Injection Hunter 反证实验后的语义修复 (E-系列):
  - 布尔求值: OR '1'='2 不再落入重言式兜底 — 恒假 OR 回基础查询, 恒假 AND 返回空集;
    此前真假条件返回同一 8 行硬编码数据, 是一击证伪点
  - 条件门控: AND 1=2 AND pg_sleep(3) 不得睡眠 (假条件下 PG 常量折叠后不执行子查询)
  - UNION 求值: version()/current_user/current_database()/md5()/CHR(n) 真正求值,
    FROM 子句不再被当常量回显, information_schema 返回合成 schema 行
  - 类型语义: id 为整型, q=hello 这类非数值输入报 invalid input syntax for type integer
  - 口令哈希: 60 字符合法 bcrypt (core/cred_format), 不再是 31 字符 hex 截断串
"""

import hashlib
import json
import re
from typing import Dict, Tuple

from core.cred_format import bcrypt_stub

EXPECTED_COLUMNS = 3          # users 表列数 (id, username, password_hash)
PG_VERSION = "PostgreSQL 14.9 (Ubuntu 14.9-0ubuntu0.22.04.1) on x86_64-pc-linux-gnu"


def _seeded_rows(world, seed_key: str, n: int, columns: Tuple[str, ...]) -> list:
    """(world, key) 纯函数派生的确定性行 — 跨请求一致, 跨会话不同"""
    base = hashlib.sha256(f"{world.session_id}:{seed_key}:{world.tag}".encode()).digest()
    users = ["admin", "devops", "operator", "svc_nexus", "backup", "monitor",
             "j.doe", "a.chen", "m.garcia", "s.kim"]
    rows = []
    for i in range(n):
        d = hashlib.sha256(base + bytes([i])).digest()
        uname = users[d[0] % len(users)]
        rows.append([
            1000 + d[1] * 256 + d[2],
            uname if d[3] % 5 else uname + str(d[4] % 10),
            bcrypt_stub(f"{world.session_id}:{seed_key}:{i}") if len(columns) >= 3 else None,
        ][:len(columns)])
    return rows


def _pg_error(msg: str, line: str, pos: int = None) -> str:
    out = f"ERROR:  {msg}\nLINE 1: {line}\n"
    if pos is not None:
        out += " " * (8 + max(pos, 0)) + "^\n"
    return out


def _conditions(low: str):
    """提取 AND/OR 比较式并求值: 返回 (and_false, or_true, or_seen)。"""
    and_false = or_true = or_seen = False
    for m in re.finditer(r"\b(and|or)\s+(['\"]?)(\w+)(?:\2)?\s*=\s*(['\"]?)(\w+)(?:\4)?", low):
        op, lhs, rhs = m.group(1), m.group(3), m.group(5)
        if op == "and" and lhs != rhs:
            and_false = True
        if op == "or":
            or_seen = True
            if lhs == rhs:
                or_true = True
    return and_false, or_true, or_seen


def _base_value(val: str) -> str:
    """WHERE id = '<base>' 里的 base — 注入尾巴不参与基础查询"""
    m = re.match(r"\s*([^\s]+)", val or "")
    return (m.group(1).strip("'") if m else "")


def sqli_sleep_seconds(q: str) -> float:
    """pg_sleep 类 payload 的应睡秒数 (上限 8s) — 调用方负责 await asyncio.sleep。

    恒假 AND 条件下不睡: 真 PG 对 WHERE false AND pg_sleep(N) 不会执行子查询。
    """
    low = (q or "").lower()
    and_false, _, _ = _conditions(low)
    if and_false:
        return 0.0
    m = re.search(r"(?:pg_)?sleep\s*\(\s*([\d.]+)", low)
    return min(float(m.group(1)), 8.0) if m else 0.0


def _eval_union_expr(expr: str, world) -> str:
    """UNION 常量列求值 — 真实注入点会执行表达式, 原样回显即被终验否决"""
    c = expr.strip()
    low = c.lower()
    if low.startswith("version()"):
        return PG_VERSION
    if low.startswith("current_user") or low == "user":
        return "prod_admin"
    if low.startswith("current_database()"):
        return "nexus_prod"
    if low.startswith("now()") or low.startswith("current_timestamp"):
        import time
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(world.created))
    m = re.fullmatch(r"md5\('(.*)'\)", c, re.IGNORECASE)
    if m:
        return hashlib.md5(m.group(1).encode()).hexdigest()
    if re.fullmatch(r"(?:CHR\(\d+\)(?:\s*\|\|\s*)?)+", c, re.IGNORECASE):
        return "".join(chr(int(n)) for n in re.findall(r"CHR\((\d+)\)", c, re.IGNORECASE))
    return c.rstrip(")").strip("'\"")


def sqli_response(q: str, world) -> Tuple[str, str, str]:
    """返回 (body, status, content_type) — 纯函数, 不含时间/全局随机"""
    val = (q or "").strip()
    low = val.lower()
    line = f"SELECT * FROM users WHERE id = '{val}' LIMIT 20;"
    and_false, or_true, or_seen = _conditions(low)

    # 时间盲注: 声明应睡时长 (真实睡眠在调用方); elapsed_ms 由调用方以真实测量值回写
    if re.search(r"(?:pg_)?sleep\s*\(\s*([\d.]+)", low):
        if and_false:
            # 恒假条件: 不执行 pg_sleep, 返回空集且无延迟 (真实 PG 行为)
            return json.dumps({"rows": [], "elapsed_ms": 0}), "200", "application/json"
        requested = min(float(re.search(r"(?:pg_)?sleep\s*\(\s*([\d.]+)", low).group(1)), 8.0)
        body = json.dumps({"rows": [], "elapsed_ms": int(requested * 1000)})
        return body, "200", "application/json"

    # 堆叠语句: PG 拒多命令 (回显被拒绝的命令名, 随输入变化)
    m = re.search(r";\s*(drop|insert|update|delete|create|alter|truncate|exec)\b", low)
    if m:
        return (_pg_error('cannot insert multiple commands into a prepared statement',
                          line, val.find(";") + 8),
                "500", "text/plain")

    # UNION 注入: 列数校验 + 表达式求值 (真 PG 行为)
    m = re.search(r"\bunion\s+(?:all\s+)?select\s+(.+?)(?:--|#|;|$)", val, re.IGNORECASE | re.DOTALL)
    if m:
        raw = m.group(1).strip()
        parts = re.split(r"\s+from\s+", raw, maxsplit=1, flags=re.IGNORECASE)
        select_part = parts[0]
        from_part = parts[1] if len(parts) > 1 else ""
        cols = [c for c in (x.strip() for x in select_part.split(",")) if c]
        if len(cols) != EXPECTED_COLUMNS:
            return (_pg_error("each UNION query must have the same number of columns",
                              line, val.lower().find("union") + 6),
                    "500", "text/plain")
        rows = _seeded_rows(world, "users", 2, ("id", "username", "password_hash"))
        if "information_schema" in from_part.lower():
            rows += [["users", "id", "public"], ["users", "username", "public"],
                     ["users", "password_hash", "public"]]
        else:
            rows.append([_eval_union_expr(c, world) for c in cols])
        body = json.dumps({
            "query": "SELECT", "rows_returned": len(rows),
            "columns": ["id", "username", "password_hash"],
            "rows": rows,
        }, ensure_ascii=False)
        return body, "200", "application/json"

    # 恒假 AND: 空集 (真 PG 语义, 与恒真分支必须有差分)
    if and_false:
        body = json.dumps({"query": "SELECT", "rows_returned": 0,
                           "columns": ["id", "username", "email"], "rows": []})
        return body, "200", "application/json"

    # 重言式: 恒真 OR → 全表; 恒假 OR 落回基础查询, 不得再进这个分支
    if or_true:
        rows = _seeded_rows(world, "users", 8, ("id", "username", "password_hash"))
        body = json.dumps({
            "query": "SELECT", "rows_returned": len(rows),
            "columns": ["id", "username", "password_hash"], "rows": rows,
        }, ensure_ascii=False)
        return body, "200", "application/json"

    # 引号断裂: 未闭合引号报错 (报错内容随输入变化)。
    # 已含完整比较式的输入跳过该启发式: '1' OR '1'='2 经服务端拼接后引号是平衡的,
    # 真 PG 会执行并退回基础查询, 误报 unterminated 反而露馅
    had_comparison = bool(re.search(
        r"\b(and|or)\s+(['\"]?)(\w+)(?:\2)?\s*=\s*(['\"]?)(\w+)(?:\4)?", low))
    if val.count("'") % 2 == 1 and not had_comparison:
        frag = val[-24:]
        return (_pg_error(f'unterminated quoted string at or near "{frag}"',
                          line, len(val) + 8),
                "500", "text/plain")

    # ORDER BY 列数枚举 (sqlmap 的 UNION 前置手段): 超限列报 42703, 真实行为
    m = re.search(r"\border\s+by\s+(\d+)", low)
    if m:
        col = int(m.group(1))
        if col > EXPECTED_COLUMNS:
            return (_pg_error(f'column "{col}" does not exist', line,
                              low.find("order") + 8),
                    "500", "text/plain")
        rows = _seeded_rows(world, f"q:{val}", 2, ("id", "username", "email"))
        body = json.dumps({"query": "SELECT", "rows_returned": len(rows),
                           "columns": ["id", "username", "email"], "rows": rows})
        return body, "200", "application/json"

    # 语法错误兜底: 剔除已识别的比较式 (AND/OR a=b) 后, 残余仍含 SQL 关键字或比较符
    # 才报错 — 合法比较式走基础查询; '1 AND 1=1 WAITFOR DELAY ...' 这类拼接垃圾
    # 必须像真 PG 一样报 syntax error, 不能因为含比较式就放行
    residual = re.sub(
        r"\b(and|or)\s+(['\"]?)(\w+)(?:\2)?\s*=\s*(['\"]?)(\w+)(?:\4)?", " ", low)
    if re.search(r"\b(and|or|where|select|from|having|group|insert|update|delete|"
                 r"drop|exec|values|case|when|waitfor|delay)\b|[<>=]", residual):
        kw = re.search(r"\b(and|or|where|select|from|having|group|insert|update|"
                       r"delete|drop|exec|values|case|when|waitfor|delay)\b", residual)
        tok = (kw.group(0) if kw else re.search(r"[<>=]+", residual).group(0))
        pos = residual.find(tok)
        return (_pg_error(f'syntax error at or near "{tok}"', line, pos + 8),
                "500", "text/plain")

    # 基础查询: id 是整型 — 非数值输入报类型错误, 不得返回用户行 (E: q=hello 出行即证伪)
    base = _base_value(val)
    if base and not base.isdigit():
        return (_pg_error(f'invalid input syntax for type integer: "{base}"', line, 8),
                "500", "text/plain")

    # 正常查询: 行数由输入哈希派生 (1-3 行, 同输入必同输出)
    key = base or "default"
    n = 1 + int(hashlib.sha256(key.encode()).hexdigest()[:2], 16) % 3
    rows = _seeded_rows(world, f"q:{key}", n, ("id", "username", "email"))
    body = json.dumps({
        "query": "SELECT", "rows_returned": len(rows),
        "columns": ["id", "username", "email"], "rows": rows,
    }, ensure_ascii=False)
    return body, "200", "application/json"
