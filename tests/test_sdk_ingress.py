"""SDK collector: 白名单转发, 管理面路径与凭据请求头都不能穿过去。"""

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from services import sdk_ingress


def test_allowed_paths_exact_match():
    assert sdk_ingress.allowed("/static/telemetry.js")
    assert sdk_ingress.allowed("/api/telemetry/cfg")
    assert sdk_ingress.allowed("/api/telemetry/b")


def test_management_paths_rejected():
    for path in ("/", "/api/arsenal", "/api/login", "/api/requests",
                 "/api/config", "/api/telemetry", "/api/telemetry/b/../arsenal",
                 "/static/../experiments/dashboard.py", "/static/index.html"):
        assert not sdk_ingress.allowed(path), path


def test_credentials_never_forwarded():
    assert "Cookie" not in sdk_ingress.FORWARD_HEADERS
    assert "Authorization" not in sdk_ingress.FORWARD_HEADERS


class _StubHive(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        _StubHive.seen.append((self.path, dict(self.headers)))
        body = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_collector_relays_only_allowlisted_paths(monkeypatch):
    hive = _serve(_StubHive)
    monkeypatch.setattr(sdk_ingress, "HIVE",
                        f"http://127.0.0.1:{hive.server_address[1]}")
    collector = _serve(sdk_ingress.CollectorHandler)
    base = f"http://127.0.0.1:{collector.server_address[1]}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(base + "/api/telemetry/cfg?id=web-1", timeout=5) as resp:
            assert resp.status == 200
            assert json.loads(resp.read())["path"] == "/api/telemetry/cfg?id=web-1"
        req = urllib.request.Request(
            base + "/static/telemetry.js",
            headers={"Authorization": "Bearer secret", "Cookie": "sid=1",
                     "User-Agent": "agent/1.0"})
        with opener.open(req, timeout=5):
            pass
        for path in ("/api/arsenal", "/api/login", "/"):
            try:
                opener.open(base + path, timeout=5)
                raise AssertionError(f"{path} should be 404")
            except urllib.error.HTTPError as exc:
                assert exc.code == 404
        forwarded = dict(_StubHive.seen[-1][1])
        assert "Authorization" not in forwarded and "Cookie" not in forwarded
        assert forwarded["User-Agent"] == "agent/1.0"
        assert len(_StubHive.seen) == 2          # 管理面请求根本没到 hive
    finally:
        collector.shutdown()
        hive.shutdown()
