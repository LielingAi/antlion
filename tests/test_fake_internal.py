"""假内网下游: 世界坐标可指向真实监听地址, Redis 只认蜜罐发出去的口令。"""

import socket

import pytest

from core.fake_db import MiniRedis
from core.fake_world import FakeWorld


def test_world_coordinates_follow_internal_host(monkeypatch):
    monkeypatch.setenv("HONEYPOT_INTERNAL_HOST", "203.0.113.10")
    monkeypatch.setenv("HONEYPOT_PG_PUBLIC_PORT", "15432")
    monkeypatch.setenv("HONEYPOT_REDIS_PUBLIC_PORT", "16379")
    w = FakeWorld("internal-test", version=2)
    assert w.db_host == w.redis_host == w.gateway_host == "203.0.113.10"
    assert w.db_port == 15432 and w.redis_port == 16379
    env = w.env()
    assert f"@{w.db_host}:15432/nexus_prod" in env
    assert f"http://{w.gateway_host}:8081/internal" in env


def test_world_coordinates_default_to_narrative_ips(monkeypatch):
    monkeypatch.delenv("HONEYPOT_INTERNAL_HOST", raising=False)
    w = FakeWorld("internal-test", version=2)
    assert w.db_host.startswith("10.99.")
    assert w.db_port == 5432


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _redis_roundtrip(port, lines):
    out = b""
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        for line in lines:
            conn.sendall(line.encode() + b"\r\n")
            out += conn.recv(256)
    return out


def test_redis_accepts_only_issued_password():
    port = _free_port()
    resolver = lambda secret: {"db_host": "w"} if secret == "s3cret" else None
    server = MiniRedis("127.0.0.1", port, auth_resolver=resolver)
    server.start()
    try:
        assert b"+OK" in _redis_roundtrip(port, ["AUTH prod_admin s3cret", "PING"])
        bad = _redis_roundtrip(port, ["AUTH prod_admin wrong"])
        assert b"WRONGPASS" in bad
    finally:
        server._sock.close()


def test_redis_without_resolver_keeps_legacy_open_auth():
    port = _free_port()
    server = MiniRedis("127.0.0.1", port)
    server.start()
    try:
        assert b"+OK" in _redis_roundtrip(port, ["AUTH anything"])
    finally:
        server._sock.close()
