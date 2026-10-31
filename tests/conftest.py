"""pytest 全局: 时序拟真默认关闭 — 测试不能变慢; 时序用例自行 monkeypatch 打开"""
import os

import pytest

os.environ["HONEYPOT_TIMING_FAKE"] = "0"

# deepteam 在 import 时会 load_dotenv() — 仓库根目录的部署 .env 会因此进入测试进程。
# 单元测试必须与本机部署配置隔离, 否则"同一 sid 世界是否漂移"这类断言会被部署值改写。
_DEPLOY_ENV_KEYS = (
    "HONEYPOT_INTERNAL_HOST", "HONEYPOT_PG_PUBLIC_PORT",
    "HONEYPOT_REDIS_PUBLIC_PORT", "HONEYPOT_FAKE_INTERNAL",
    "HONEYPOT_WORLD_SCOPE", "HONEYPOT_PUBLIC_BASE", "HONEYPOT_BEACON_BASE",
)


@pytest.fixture(autouse=True)
def _isolate_deploy_env(monkeypatch):
    for key in _DEPLOY_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
