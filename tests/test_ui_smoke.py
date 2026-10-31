# -*- coding: utf-8 -*-
"""前端冒烟测试 — 每个路由必须渲染且无'加载失败' (pytest 门禁)

存在意义: 此前前端改动只靠开发者的 Playwright 抽查, 覆盖率约 60%,
UI 断点全部由 WREN 人肉发现。此测试把全路由扫描固化为门禁。
"""
import json
import threading
import urllib.request
import zipfile

import pytest

pytest.importorskip("playwright.sync_api", reason="playwright 未安装")
from playwright.sync_api import sync_playwright  # noqa: E402

from core.testdb import TestDB  # noqa: E402


@pytest.fixture()
def hive(tmp_path):
    import experiments.dashboard as d
    from http.server import ThreadingHTTPServer
    d.DB = TestDB(str(tmp_path / "ui.sqlite"))
    d.DB.create_user("admin", "admin123", role="admin")
    d.SESSIONS.clear()
    d.DB.ingest_requests([
        {"run_id": "sensor_t1", "path": "/.env", "canary": 1, "client_ip": "6.6.6.6",
         "session_id": "ui-s1", "user_agent": "ua", "is_ai": 1, "agent_type": "llm",
         "threat": 9.0, "families": "info_disclosure", "auth_level": 1,
         "method": "GET", "ts": 1700000000.0},
        {"run_id": "sensor_t1", "path": "/api/bounty/submit", "canary": 1,
         "client_ip": "6.6.6.6", "session_id": "ui-s1", "method": "POST",
         "user_agent": "ua", "is_ai": 1, "agent_type": "llm", "threat": 5.0,
         "families": "", "auth_level": 1, "ts": 1700000001.0},
    ])
    d.DB.ingest_intel([{"run_id": "sensor_t1", "session_id": "ui-s1",
                        "field": "delivery_exfil", "grade": "consistent",
                        "hash_key": "h", "sample": "poc", "ts": 1700000002.0}])
    d.DB.touch_sensor("t1")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), d.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()


def test_all_routes_render(hive):
    """全部目的地与 tab 路由: 不得出现'加载失败', 不得有 pageerror"""
    routes = ["situation", "events/tail", "events/requests", "events/actions",
              "ops", "tasking", "arsenal", "investigate", "sessions",
              "fleet", "intel/graded", "intel/actors",
              "experiments/trials", "experiments/summary", "experiments/compare",
              "experiments/bandit", "experiments/runs", "config",
              "e/ip/6.6.6.6", "e/session/ui-s1"]
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context()
        pg = ctx.new_page()
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(f"http://127.0.0.1:{hive}/", wait_until="domcontentloaded")
        pg.wait_for_timeout(700)
        pg.fill("#login-user", "admin")
        pg.fill("#login-pass", "admin123")
        pg.click("button[type=submit]")
        pg.wait_for_timeout(1500)
        failures = []
        for route in routes:
            r = ctx.new_page()
            errs = []
            r.on("pageerror", lambda e: errs.append(str(e)))
            r.goto(f"http://127.0.0.1:{hive}/#/{route}", wait_until="domcontentloaded")
            r.wait_for_timeout(1400)
            text = r.evaluate("document.getElementById('content').innerText || ''")
            if "加载失败" in text:
                snippet = text[text.index("加载失败"):text.index("加载失败") + 80]
                failures.append(f"{route}: {snippet}")
            if errs:
                failures.append(f"{route}: JS {errs[0][:80]}")
            r.close()
        ctx.close()
        b.close()
    assert not failures, "前端路由断点:\n" + "\n".join(failures)


def test_arsenal_list_pagination(hive):
    """清单分页: 页大小、前后翻页、筛选后自动回到第一页。"""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.goto(f"http://127.0.0.1:{hive}/", wait_until="domcontentloaded")
        page.wait_for_timeout(500)
        page.fill("#login-user", "admin")
        page.fill("#login-pass", "admin123")
        page.click("button[type=submit]")
        page.wait_for_timeout(1000)
        page.goto(f"http://127.0.0.1:{hive}/#/arsenal", wait_until="domcontentloaded")
        page.wait_for_selector(".arsenal-item")
        assert page.locator(".arsenal-item").count() == 10
        assert page.locator("[data-testid=arsenal-page-info]").inner_text() == "1 / 2 页"

        page.select_option("[data-testid=arsenal-page-size]", "5")
        assert page.locator(".arsenal-item").count() == 5
        assert page.locator("[data-testid=arsenal-page-info]").inner_text() == "1 / 3 页"
        assert not page.locator("[data-testid=arsenal-next-page]").is_disabled()
        page.click("[data-testid=arsenal-next-page]")
        assert page.locator(".arsenal-item").count() == 5
        assert page.locator("[data-testid=arsenal-page-info]").inner_text() == "2 / 3 页"
        assert not page.locator("[data-testid=arsenal-next-page]").is_disabled()
        page.click("[data-testid=arsenal-next-page]")
        assert page.locator("[data-testid=arsenal-page-info]").inner_text() == "3 / 3 页"
        assert page.locator("[data-testid=arsenal-next-page]").is_disabled()
        assert not page.locator("[data-testid=arsenal-prev-page]").is_disabled()

        page.click("[data-testid=arsenal-prev-page]")
        assert page.locator("[data-testid=arsenal-page-info]").inner_text() == "2 / 3 页"
        page.fill(".arsenal-search", "SQLI")
        assert page.locator(".arsenal-item").count() == 3
        assert page.locator("[data-testid=arsenal-page-info]").inner_text() == "1 / 1 页"
        assert page.locator("[data-testid=arsenal-next-page]").is_disabled()
        assert not errors, errors
        browser.close()


def test_deepteam_builder_controls(hive):
    """DeepTeam 参考武器在构建器中可编辑工艺并预览动作契约。"""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.goto(f"http://127.0.0.1:{hive}/", wait_until="domcontentloaded")
        page.wait_for_timeout(500)
        page.fill("#login-user", "admin")
        page.fill("#login-pass", "admin123")
        page.click("button[type=submit]")
        page.wait_for_timeout(1000)
        page.goto(f"http://127.0.0.1:{hive}/#/arsenal", wait_until="domcontentloaded")
        page.click('[data-weapon-id="W-DT-PROMPT-LEAK-1"]')
        page.click('button:text("编辑武器")')
        page.wait_for_selector(".weapon-editor-panel")
        assert page.locator('[data-testid="deepteam-toggle"]').is_checked()
        assert "Base64" in page.locator(".weapon-editor-panel").inner_text()
        page.click('button:text("下一步: 预览 →")')
        preview = page.locator(".weapon-editor-panel").inner_text()
        assert "DeepTeam" in preview
        assert "Agent 解码并回传原始任务上下文" in preview
        assert "prompt_captured" in preview
        assert not errors, errors
        browser.close()


def test_weapon_package_upload(hive, tmp_path):
    """管理员可在武器库上传 ZIP 包并完成安装。"""
    import experiments.dashboard as d
    d.WEAPON_PACK_DIR = tmp_path / "packs"
    package = tmp_path / "ui-plugin.zip"
    manifest = {
        "id": "test.ui_upload", "name": "UI uploaded plugin", "version": "1.0.0",
        "api_version": 1, "class": "prompt", "entrypoint": "weapon.py:Plugin",
    }
    source = (
        "from core.weapon_plugins.base import PromptWeaponPlugin\n"
        "from core.weapon_plugins.models import WeaponResult\n"
        "class Plugin(PromptWeaponPlugin):\n"
        "    def render(self, context):\n"
        "        return WeaponResult.prompt('ui-upload')\n"
    )
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("weapon.json", json.dumps(manifest))
        archive.writestr("weapon.py", source)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.goto(f"http://127.0.0.1:{hive}/", wait_until="domcontentloaded")
        page.wait_for_timeout(500)
        page.fill("#login-user", "admin")
        page.fill("#login-pass", "admin123")
        page.click("button[type=submit]")
        page.wait_for_timeout(1000)
        page.goto(f"http://127.0.0.1:{hive}/#/arsenal", wait_until="domcontentloaded")
        page.click('[data-testid="plugin-upload-button"]')
        page.set_input_files('[data-testid="plugin-upload-file"]', str(package))
        page.click('[data-testid="plugin-upload-submit"]')
        page.wait_for_function("document.body.innerText.includes('已安装')")
        assert (d.WEAPON_PACK_DIR / "test_ui_upload" / "weapon.json").is_file()
        assert not errors, errors
        browser.close()


def test_deepteam_model_settings_ui(hive):
    """模型供应商和凭据可配置，API Key 保存后不回显。"""
    import os
    import experiments.dashboard as d
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.goto(f"http://127.0.0.1:{hive}/", wait_until="domcontentloaded")
        page.wait_for_timeout(500)
        page.fill("#login-user", "admin")
        page.fill("#login-pass", "admin123")
        page.click("button[type=submit]")
        page.wait_for_timeout(1000)
        page.goto(f"http://127.0.0.1:{hive}/#/config", wait_until="domcontentloaded")
        page.select_option('[data-testid="deepteam-provider"]', "deepseek")
        page.fill('[data-testid="deepteam-model"]', "deepseek-test")
        page.fill('[data-testid="deepteam-api-key"]', "secret")
        page.click('[data-testid="deepteam-model-save"]')
        page.wait_for_function("document.body.innerText.includes('DeepTeam 模型配置已保存并下发')")
        assert d.DB.get_setting("deepteam_model_provider") == "deepseek"
        assert d.DB.get_setting("deepteam_simulator_model") == "deepseek-test"
        assert d.DB.get_setting("deepteam_api_key") == "secret"
        assert page.locator('[data-testid="deepteam-api-key"]').input_value() == ""
        assert "secret" not in page.locator("#content").inner_text()
        page.check('[data-testid="deepteam-clear-key"]')
        page.click('[data-testid="deepteam-model-save"]')
        page.wait_for_timeout(400)
        assert d.DB.get_setting("deepteam_api_key") == ""
        assert d._masked_cfg()["deepteam_api_key_set"] is False
        assert not errors, errors
        browser.close()
    os.environ.pop("DEEPTEAM_MODEL_SETTINGS", None)
