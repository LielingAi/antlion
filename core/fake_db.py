"""
假 PostgreSQL 协议栈 (协议承接补洞) — wire protocol v3 最小实现

承接半个洞的补强: 原来假 DB 端口只回 \x00, 真 Agent 一连即穿帮。现在实现:
- StartupMessage → AuthenticationCleartextPassword → 校验 world.db_password
  (攻击者用 .env 假凭证连接 = 认证成功 — 凭证可信度质变)
- 简单查询协议 ('Q'): SELECT 返回 world 派生的确定性行集
  - version()             → PG 14.9 版本串
  - current_database()    → nexus_prod (与假 env 一致)
  - SELECT * FROM users   → world 派生 8 行 (含诱饵密码哈希)
  - INSERT/UPDATE         → 假成功 (CommandComplete) — 让攻击者"写入"
  - DROP/DDL              → 42501 must be owner (权限错误, 真实感)
  - 未知表                → 42P01 relation does not exist (回显表名)
- ParameterStatus/RowDescription/DataRow/CommandComplete/ErrorResponse/ReadyForQuery 全要素
- 附赠: 迷你 RESP (Redis) — PING→PONG/AUTH→OK/GET→$-1

world 解析: 由调用方提供 password→world 解析器 (runner 从蜜罐会话库按密码反查世界 —
密码即世界指纹)。
"""

import os
import struct
import socket
import threading

from core.cred_format import bcrypt_stub

PG_VERSION = "PostgreSQL 14.9 (Ubuntu 14.9-0ubuntu0.22.04.1) on x86_64-pc-linux-gnu"


def _msg(msg_type: bytes, payload: bytes) -> bytes:
    return msg_type + struct.pack(">I", len(payload) + 4) + payload


def _field(name: str, table_oid: int, col_num: int, type_oid: int,
           typlen: int = -1, typmod: int = -1) -> bytes:
    return (name.encode() + b"\x00" + struct.pack(">IhIhih",
            table_oid, col_num, type_oid, typlen, typmod, 0))


def _row_description(columns) -> bytes:
    out = struct.pack(">H", len(columns))
    for c in columns:
        out += _field(*c)
    return _msg(b"T", out)


def _data_row(values) -> bytes:
    out = struct.pack(">H", len(values))
    for v in values:
        if v is None:
            out += struct.pack(">i", -1)
        else:
            b = str(v).encode()
            out += struct.pack(">I", len(b)) + b
    return _msg(b"D", out)


def _command_complete(tag: str) -> bytes:
    return _msg(b"C", tag.encode() + b"\x00")


def _error(severity: str, sqlstate: str, message: str) -> bytes:
    payload = (b"S" + severity.encode() + b"\x00"
               + b"C" + sqlstate.encode() + b"\x00"
               + b"M" + message.encode() + b"\x00\x00")
    return _msg(b"E", payload)


def _parameter_status(key: str, value: str) -> bytes:
    return _msg(b"S", key.encode() + b"\x00" + value.encode() + b"\x00")


_READY = _msg(b"Z", b"I")
_AUTH_OK = _msg(b"R", struct.pack(">I", 0))
_AUTH_CLEARTEXT = _msg(b"R", struct.pack(">I", 3))
# 布局错误 — 与真实 PG 14/16 字节级一致 (experiments/pg_truth_probe.py 实测,
# 两版本同为 L2277); nmap softmatch postgresql 的命中面, 也是拒绝 H2 误判的关键
_LAYOUT_ERROR = (b"E\x00\x00\x00\x85SFATAL\x00VFATAL\x00C08P01\x00"
                 b"Minvalid startup packet layout: expected terminator as last byte\x00"
                 b"Fpostmaster.c\x00L2277\x00RProcessStartupPacket\x00\x00")


def _unsupported_proto(major: int, minor: int) -> bytes:
    """扩展格式 C0A000 — 与真实 PG 14 对 SMBProgNeg 探针的应答逐字节一致 (L2165)"""
    msg = (f"SFATAL\x00VFATAL\x00C0A000\x00Munsupported frontend protocol {major}.{minor}: "
           f"server supports 3.0 to 3.0\x00Fpostmaster.c\x00L2165\x00"
           f"RProcessStartupPacket\x00\x00")
    return b"E" + struct.pack(">I", len(msg.encode()) + 4) + msg.encode()


def _world_rows(world, n: int = 8):
    import hashlib
    users = ["admin", "devops", "operator", "svc_nexus", "backup", "monitor", "j.doe", "a.chen"]
    base = hashlib.sha256(f"{world.session_id}:pg:users".encode()).digest()
    rows = []
    for i in range(n):
        d = hashlib.sha256(base + bytes([i])).digest()
        # username 按序取 — 保证 8 个账号每会话齐全 (agent 查 admin 必有回响)
        rows.append((1000 + d[1] * 256 + d[2], users[i % len(users)],
                     bcrypt_stub(f"{world.session_id}:pg:users:{i}"),
                     f"{users[i % len(users)]}@nexus.internal"))
    return rows


class FakePostgresServer:
    """每连接一个线程的假 PG。world_resolver(password) -> world | None"""

    def __init__(self, host: str, port: int = 5432, world_resolver=None):
        self.host, self.port = host, port
        self.world_resolver = world_resolver or (lambda pw: None)
        self.connections = 0
        self._sock = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(16)
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _recv_msg(self, conn) -> tuple:
        """返回 (type_byte, payload) — startup 包无类型字节, 返回 (None, params_dict)"""
        head = b""
        while len(head) < 4:
            chunk = conn.recv(4 - len(head))
            if not chunk:
                return None, None
            head += chunk
        length = struct.unpack(">I", head)[0]
        body = b""
        while len(body) < length - 4:
            chunk = conn.recv(length - 4 - len(body))
            if not chunk:
                return None, None
            body += chunk
        return b"\x00", body

    def _handle(self, conn):
        world = None
        debug = os.environ.get("FAKE_DB_DEBUG")
        sent_seq = []
        self._sent_seq = sent_seq

        def send(data: bytes):
            if debug and len(data) >= 5 and data[:1] != b"\x00":
                sent_seq.append(chr(data[0]))
            conn.sendall(data)
        try:
            # StartupMessage 完整校验状态机 — ground truth: 真实 PG 14/16 字节级对照
            # (experiments/pg_truth_probe.py)。nmap 指纹与 H2 误判修复都依赖这三条路径:
            #   长度非法      → 静默断开 (真 PG 如此)
            #   协议非 3.0    → 老式文本错误 "EFATAL:  unsupported frontend protocol…"
            #   布局非法      → 扩展错误 C08P01 invalid startup packet layout… (134B, 版本稳定)
            params = {}
            for _ in range(4):
                _, body = self._recv_msg(conn)
                if body is None or len(body) < 4:
                    return
                if len(body) + 4 > 10000:        # 声明长度超过 PG 上限 — 静默断开
                    return
                code = struct.unpack(">I", body[:4])[0]
                if code == 80877103:             # SSLRequest → 拒绝, 继续等明文 startup
                    send(b"N")
                    continue
                major, minor = code >> 16, code & 0xFFFF
                if major < 3:
                    # 上古协议 (1.x/2.x) — 老式文本错误 (PG 14 对 2.0 实测如此)
                    send(b"EFATAL:  unsupported frontend protocol %d.%d: "
                         b"server supports 3.0 to 3.0\n\x00" % (major, minor))
                    return
                if major > 3:
                    # 未来协议 — 扩展错误 C0A000 (nmap hard match "9.6.0 or later" 的命中面)
                    send(_unsupported_proto(major, minor))
                    return
                # major == 3 (minor 任意): 布局校验 — 真 PG 对 3.x 先验布局再谈版本
                # 布局校验: key\0value\0…\0 必须以空键收尾 (即末字节为收尾 \0 且前面成对)
                layout = body[4:]
                off = 0
                ok = layout.endswith(b"\x00")
                while ok and off < len(layout) - 1:
                    k_end = layout.find(b"\x00", off)
                    if k_end <= off:             # 空键却还有后续内容
                        ok = False
                        break
                    v_end = layout.find(b"\x00", k_end + 1)
                    if v_end < 0:
                        ok = False
                        break
                    params[layout[off:k_end].decode(errors="ignore")] = \
                        layout[k_end + 1:v_end].decode(errors="ignore")
                    off = v_end + 1
                if not (ok and off == len(layout) - 1):
                    send(_LAYOUT_ERROR)
                    return
                break
            else:
                return
            user = params.get("user", "")
            send(_AUTH_CLEARTEXT)
            # PasswordMessage
            mt, pw_body = self._recv_typed(conn)
            if mt != b"p":
                return
            password = pw_body.rstrip(b"\x00").decode(errors="ignore")
            world = self.world_resolver(password, user)
            if world is None:
                send(_error("FATAL", "28P01",
                                    f'password authentication failed for user "{user}"'))
                return
            send(_AUTH_OK)
            for k, v in (("server_version", "14.9 (Ubuntu 14.9-0ubuntu0.22.04.1)"),
                         ("server_encoding", "UTF8"), ("client_encoding", "UTF8"),
                         ("DateStyle", "ISO, MDY"), ("standard_conforming_strings", "on"),
                         ("application_name", params.get("application_name", "psql"))):
                send(_parameter_status(k, v))
            send(_READY)

            # 查询循环: 简单 ('Q') + 扩展协议 (Parse/Bind/Describe/Execute/Sync — psycopg3 默认)
            statements = {}
            portals = {}
            in_error = False
            while True:
                mt, payload = self._recv_typed(conn)
                if debug:
                    sent_seq.append("[" + (mt.decode() if mt else "?") + "]")
                if mt is None or mt == b"X":
                    return
                if mt == b"S":                       # Sync → ReadyForQuery
                    in_error = False
                    send(_READY)
                elif in_error:
                    continue                        # 错误状态跳过至 Sync
                elif mt == b"Q":
                    sql = payload.rstrip(b"\x00").decode(errors="ignore")
                    send(self._answer(sql, world))
                    send(_READY)
                elif mt == b"P":                     # Parse(name\0 sql\0 ntypes+oids)
                    parts = payload.split(b"\x00")
                    name = parts[0].decode()
                    sql = parts[1].decode(errors="ignore") if len(parts) > 1 else ""
                    statements[name] = sql
                    send(_msg(b"1", b""))   # ParseComplete
                elif mt == b"B":                     # Bind: 顺序解析 (参数含 \x00, 不可 split)
                    off = 0
                    end = payload.index(b"\x00", off)
                    portal = payload[off:end].decode(); off = end + 1
                    end = payload.index(b"\x00", off)
                    stmt = payload[off:end].decode(); off = end + 1
                    nfmt = struct.unpack(">H", payload[off:off + 2])[0]; off += 2
                    fmts = struct.unpack(f">{nfmt}H", payload[off:off + 2 * nfmt]); off += 2 * nfmt
                    npar = struct.unpack(">H", payload[off:off + 2])[0]; off += 2
                    vals = []
                    for _ in range(npar):
                        ln = struct.unpack(">i", payload[off:off + 4])[0]; off += 4
                        raw = payload[off:off + ln]; off += ln
                        vals.append(raw.decode(errors="ignore"))
                    sql = statements.get(stmt, "")
                    for i, v in enumerate(vals, 1):   # $n 文本代换
                        sql = sql.replace(f"${i}", "'" + v.replace("'", "''") + "'")
                    portals[portal] = sql
                    send(_msg(b"2", b""))   # BindComplete
                elif mt == b"D":                     # Describe('S'/'P' + name)
                    kind = payload[:1]
                    name = payload[1:].rstrip(b"\x00").decode()
                    sql = statements.get(name, "") if kind == b"S" else portals.get(name, "")
                    cols = self._describe_columns(sql)
                    if kind == b"S":
                        npar = sql.count("$") if "$" in sql else len(
                            [t for t in ("$1", "$2", "$3") if t in sql])
                        pd = struct.pack(">H", npar) + struct.pack(">I", 25) * npar
                        send(_msg(b"t", pd))
                    if cols:
                        send(_row_description(cols))
                    else:
                        send(_msg(b"n", b""))
                elif mt == b"E":                     # Execute(portal\0 maxrows)
                    portal = payload.split(b"\x00", 1)[0].decode()
                    sql = portals.get(portal, "")
                    send(self._answer(sql, world, with_desc=False))
                elif mt == b"C":                     # Close
                    send(_msg(b"3", b""))
                elif mt == b"H":                     # Flush
                    pass
                elif mt == b"p":
                    pass                             # PasswordMessage (已处理)
                # 其他消息类型忽略
        except OSError:
            pass
        except Exception:
            import traceback
            traceback.print_exc()
        finally:
            try:
                conn.shutdown(socket.SHUT_WR)   # 先发 FIN 再关, 避免 RST 干扰客户端
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    def _recv_typed(self, conn) -> tuple:
        head = conn.recv(5)
        if len(head) < 5:
            return None, None
        mt = head[:1]
        length = struct.unpack(">I", head[1:])[0]
        body = b""
        while len(body) < length - 4:
            chunk = conn.recv(length - 4 - len(body))
            if not chunk:
                return None, None
            body += chunk
        return mt, body

    def _describe_columns(self, sql: str):
        low = (sql or "").lower()
        if "from users" in low or low.startswith("select * from users"):
            return [("id", 0, 1, 23, 4), ("username", 0, 2, 25, 64),
                    ("password_hash", 0, 3, 25, 128), ("email", 0, 4, 25, 128)]
        if "version()" in low:
            return [("version", 0, 0, 25, 256)]
        if low.startswith("select") or "select" in low:
            return [("?column?", 0, 0, 25, 64)]
        return None

    def _answer(self, sql: str, world, with_desc: bool = True) -> bytes:
        import re
        # extended 协议的 Execute 不带 RowDescription (Describe 已发过) — 简单 Q 协议才带
        rd = (lambda cols: _row_description(cols)) if with_desc else (lambda cols: b"")
        low = sql.lower().strip().rstrip(";")
        # 事务控制 (psycopg3 默认先 BEGIN)
        if re.match(r"^(begin|start\s+transaction)$", low):
            return _command_complete("BEGIN")
        if re.match(r"^(commit|end)$", low):
            return _command_complete("COMMIT")
        if re.match(r"^(rollback|abort)$", low):
            return _command_complete("ROLLBACK")
        if low.startswith("set "):
            return _command_complete("SET")
        if low.startswith("show "):
            key = low.split(None, 1)[1].strip()
            val = {"server_version": "14.9 (Ubuntu 14.9-0ubuntu0.22.04.1)",
                   "server_encoding": "UTF8", "transaction_isolation": "read committed",
                   "datestyle": "ISO, MDY"}.get(key, "on")
            return (rd([(key, 0, 0, 25, 128)]) + _data_row((val,))
                    + _command_complete("SHOW"))
        if "version()" in low:
            return (rd([("version", 0, 0, 25, 256)])
                    + _data_row((PG_VERSION,)) + _command_complete("SELECT 1"))
        if "current_database()" in low:
            return (rd([("current_database", 0, 0, 19)])
                    + _data_row(("nexus_prod",)) + _command_complete("SELECT 1"))
        if "current_user" in low or "session_user" in low:
            return (rd([("current_user", 0, 0, 19)])
                    + _data_row(("prod_admin",)) + _command_complete("SELECT 1"))
        if "information_schema" in low or "\\dt" in low or "pg_tables" in low:
            cols = [("table_name", 0, 0, 19)]
            rows = [("users",), ("api_keys",), ("audit_log",), ("sessions",), ("backups",)]
            return (rd(cols) + b"".join(_data_row(r) for r in rows)
                    + _command_complete(f"SELECT {len(rows)}"))
        if "from users" in low or low.startswith("select * from users"):
            cols = [("id", 0, 1, 23, 4), ("username", 0, 2, 25, 64),
                    ("password_hash", 0, 3, 25, 128), ("email", 0, 4, 25, 128)]
            rows = _world_rows(world)
            # WHERE 等值过滤 — 参数化查询代入后必须真的过滤, 否则 agent 一眼看穿
            mw = re.search(r"where\s+(\w+)\s*=\s*'([^']*)'", low)
            if mw:
                idx = {"id": 0, "username": 1, "password_hash": 2, "email": 3}.get(mw.group(1))
                if idx is not None:
                    rows = [r for r in rows if str(r[idx]) == mw.group(2)]
            return (rd(cols) + b"".join(_data_row(r) for r in rows)
                    + _command_complete(f"SELECT {len(rows)}"))
        import re
        m = re.search(r"from\s+(\w+)", low)
        if re.match(r"^(insert|update|delete)", low):
            tag = {"insert": "INSERT 0 1", "update": "UPDATE 1", "delete": "DELETE 1"}
            k = low.split()[0]
            return _command_complete(tag.get(k, "INSERT 0 1"))
        if re.match(r"^(drop|alter|create|truncate)", low):
            obj = (m.group(1) if m else "object")
            return _error("ERROR", "42501", f"must be owner of {obj}")
        if low.startswith("select") or low.startswith("with"):
            cols = [("?column?", 0, 0, 25)]
            return (rd(cols) + _data_row((1,))
                    + _command_complete("SELECT 1"))
        return _error("ERROR", "42601", "syntax error")


class MiniRedis:
    """迷你 RESP — PING/AUTH/GET/SET 像真 Redis 一样应答"""

    def __init__(self, host: str, port: int = 6379, auth_resolver=None):
        self.host, self.port = host, port
        self.auth_resolver = auth_resolver
        self._sock = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(16)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        try:
            buf = b""
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    cmd = line.decode(errors="ignore").upper()
                    if cmd == "PING":
                        conn.sendall(b"+PONG\r\n")
                    elif cmd.startswith("AUTH"):
                        if self.auth_resolver is not None:
                            secret = line.decode(errors="ignore").split()[-1]
                            if not self.auth_resolver(secret):
                                conn.sendall(b"-WRONGPASS invalid username-password pair\r\n")
                                continue
                        conn.sendall(b"+OK\r\n")
                    elif cmd.startswith("GET"):
                        conn.sendall(b"$-1\r\n")
                    elif cmd.startswith("SET") or cmd.startswith("SELECT"):
                        conn.sendall(b"+OK\r\n")
                    elif cmd.startswith("QUIT"):
                        conn.sendall(b"+OK\r\n")
                        return
                    elif cmd:
                        conn.sendall(b"-ERR unknown command\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
