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
"""

import hashlib
import json
import re
from typing import Dict, Tuple

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
            f"$2b$12${d[5:17].hex()}" if len(columns) >= 3 else None,
        ][:len(columns)])
    return rows


def _pg_error(msg: str, line: str, pos: int = None) -> str:
    out = f"ERROR:  {msg}\nLINE 1: {line}\n"
    if pos is not None:
        out += " " * (8 + max(pos, 0)) + "^\n"
    return out


def sqli_sleep_seconds(q: str) -> float:
    """pg_sleep 类 payload 的应睡秒数 (上限 8s) — 调用方负责 await asyncio.sleep"""
    m = re.search(r"(?:pg_)?sleep\s*\(\s*([\d.]+)", (q or "").lower())
    return min(float(m.group(1)), 8.0) if m else 0.0


def sqli_response(q: str, world) -> Tuple[str, str, str]:
    """返回 (body, status, content_type) — 纯函数, 不含时间/全局随机"""
    val = (q or "").strip()
    low = val.lower()
    line = f"SELECT * FROM users WHERE id = '{val}' LIMIT 20;"

    # 时间盲注: 声明应睡时长 (真实睡眠在调用方); elapsed_ms 由调用方以真实测量值回写
    if re.search(r"(?:pg_)?sleep\s*\(\s*([\d.]+)", low):
        requested = min(float(re.search(r"(?:pg_)?sleep\s*\(\s*([\d.]+)", low).group(1)), 8.0)
        body = json.dumps({"rows": [], "elapsed_ms": int(requested * 1000)})
        return body, "200", "application/json"

    # 堆叠语句: PG 拒多命令 (回显被拒绝的命令名, 随输入变化)
    m = re.search(r";\s*(drop|insert|update|delete|create|alter|truncate|exec)\b", low)
    if m:
        bad = m.group(1).upper()
        return (_pg_error(f'cannot insert multiple commands into a prepared statement',
                          line, val.find(";") + 8),
                "500", "text/plain")

    # UNION 注入: 列数校验 + 常量回显 (真 PG 行为; CHR(n)||CHR(m) 表达式求值 — sqlmap 终验标志)
    m = re.search(r"\bunion\s+(?:all\s+)?select\s+(.+?)(?:--|#|;|$)", val, re.IGNORECASE | re.DOTALL)
    if m:
        cols_raw = m.group(1).strip().rstrip(")")
        k = len([c for c in cols_raw.split(",")]) if cols_raw else 0
        if k == EXPECTED_COLUMNS:
            consts = []
            for c in cols_raw.split(","):
                c = c.strip().strip("'\"")
                chr_m = re.fullmatch(r"(?:CHR\((\d+)\)(?:\s*\|\|\s*)?)+", c, re.IGNORECASE)
                if chr_m:
                    # 求值 CHR 拼接 (真实注入点会执行表达式, 原样回显会被工具终验否决)
                    c = "".join(chr(int(n)) for n in re.findall(r"CHR\((\d+)\)", c, re.IGNORECASE))
                consts.append(c)
            rows = _seeded_rows(world, "users", 2, ("id", "username", "password_hash"))
            rows.append(consts)   # UNION 常量行原样回显 — 真实行为
            body = json.dumps({
                "query": "SELECT", "rows_returned": len(rows),
                "columns": ["id", "username", "password_hash"],
                "rows": rows,
            }, ensure_ascii=False)
            return body, "200", "application/json"
        return (_pg_error("each UNION query must have the same number of columns",
                          line, val.lower().find("union") + 6),
                "500", "text/plain")

    # 布尔盲注结构解析: "X AND a=a" 真值由前缀决定 (跨随机数稳定, sqlmap 终验通过),
    # "X AND a=b" 恒空 — TRUE/FALSE 有差分且 TRUE 可复现
    m = re.match(r"^(.*?)\s+and\s+(\d+)\s*=\s*(\d+)\s*$", low)
    if m:
        base, a, b = m.group(1).strip(), int(m.group(2)), int(m.group(3))
        if a != b:
            body = json.dumps({"query": "SELECT", "rows_returned": 0,
                               "columns": ["id", "username", "email"], "rows": []})
            return body, "200", "application/json"
        # a == b: 按前缀派生 (与裸前缀查询同结果 → TRUE 分支跨随机值稳定)
        n = 1 + int(hashlib.sha256((base or "default").encode()).hexdigest()[:2], 16) % 3
        rows = _seeded_rows(world, f"q:{base or 'default'}", n, ("id", "username", "email"))
        body = json.dumps({"query": "SELECT", "rows_returned": len(rows),
                           "columns": ["id", "username", "email"], "rows": rows})
        return body, "200", "application/json"

    # 重言式: 全表
    if re.search(r"\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1", low) or re.search(r"'\s*or\s*'", low):
        rows = _seeded_rows(world, "users", 8, ("id", "username", "password_hash"))
        body = json.dumps({
            "query": "SELECT", "rows_returned": len(rows),
            "columns": ["id", "username", "password_hash"], "rows": rows,
        }, ensure_ascii=False)
        return body, "200", "application/json"

    # 引号断裂: 未闭合引号报错 (报错内容随输入变化)
    if val.count("'") % 2 == 1:
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

    # 语法错误兜底: 携带 SQL 关键字却未命中任何已处理形态 — 真实解析器必报错,
    # 返回 200 会让 sqlmap 的合法性探针判定 "输入未到达解析器" (终验否决根因)
    if re.search(r"\b(and|or|where|select|from|having|group|insert|update|delete|"
                 r"drop|exec|values|case|when)\b|[<>=]", low):
        kw = re.search(r"\b(and|or|where|select|from|having|group|insert|update|"
                       r"delete|drop|exec|values|case|when)\b", low)
        tok = (kw.group(0) if kw else re.search(r"[<>=]+", low).group(0))
        pos = low.find(tok)
        return (_pg_error(f'syntax error at or near "{tok}"', line, pos + 8),
                "500", "text/plain")

    # 正常查询: 行数由输入哈希派生 (1-3 行, 同输入必同输出)
    key = val or "default"
    n = 1 + int(hashlib.sha256(key.encode()).hexdigest()[:2], 16) % 3
    rows = _seeded_rows(world, f"q:{key}", n, ("id", "username", "email"))
    body = json.dumps({
        "query": "SELECT", "rows_returned": len(rows),
        "columns": ["id", "username", "email"], "rows": rows,
    }, ensure_ascii=False)
    return body, "200", "application/json"
