"""SDK/telemetry 采集入口 — 只把白名单路径转发给 hive, 控制台仍只绑回环。

telemetry.js 载体需要攻击方浏览器能到达的 collector: 页面、配置拉取、信标。
hive 整体只监听 127.0.0.1, 本服务单独暴露一个端口, 且只放行 SDK 所需的六个路径,
管理面 (/api/arsenal、/api/login、/api/requests ...) 一律 404。

环境变量:
  HIVE_INTERNAL_URL  hive 地址 (默认 http://127.0.0.1:8899, compose 内为 http://hive:8899)
  SDK_INGRESS_PORT   监听端口 (默认 8898)
"""

import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HIVE = os.environ.get("HIVE_INTERNAL_URL", "http://127.0.0.1:8899").rstrip("/")
PORT = int(os.environ.get("SDK_INGRESS_PORT", "8898"))
TIMEOUT = 10

ALLOWED_PATHS = frozenset({
    "/static/telemetry.js",
    "/static/demo_sdk.html",
    "/api/sdk/config",
    "/api/sdk/beacon",
    "/api/telemetry/cfg",
    "/api/telemetry/b",
})
# 只透传无害请求头: Cookie/Authorization 绝不经过这个对外端口
FORWARD_HEADERS = {"User-Agent", "Referer", "Accept", "Accept-Language"}


def allowed(path: str) -> bool:
    return path in ALLOWED_PATHS


class CollectorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not allowed(urlsplit(self.path).path):
            self.send_error(404)
            return
        headers = {k: v for k, v in self.headers.items() if k in FORWARD_HEADERS}
        req = urllib.request.Request(HIVE + self.path, headers=headers)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=TIMEOUT) as resp:
                self._relay(resp.status, resp.headers, resp.read())
        except urllib.error.HTTPError as exc:
            self._relay(exc.code, exc.headers, exc.read()[:4096])
        except (urllib.error.URLError, TimeoutError, OSError):
            self.send_error(502)

    # 采集端点全是 GET (图片信标/配置拉取), 其余方法一律不存在
    do_POST = do_PUT = do_DELETE = do_PATCH = lambda self: self.send_error(404)

    def _relay(self, status, headers, body):
        self.send_response(status)
        self.send_header("Content-Type",
                         headers.get("Content-Type", "application/octet-stream"))
        cors = headers.get("Access-Control-Allow-Origin")
        if cors:
            self.send_header("Access-Control-Allow-Origin", cors)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), CollectorHandler)
    print(f"[SDK-INGRESS] collector :{PORT} → {HIVE} "
          f"({len(ALLOWED_PATHS)} paths, 管理面不转发)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
