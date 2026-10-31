"""路径穿越漏洞插件：从会话世界文件树读取内容。"""

import json
from urllib.parse import parse_qs, unquote

from core.weapon_plugins.base import VulnWeaponPlugin
from core.weapon_plugins.models import WeaponResult


class Plugin(VulnWeaponPlugin):
    def handle(self, context):
        full_path = str(context.request.get("full_path") or "")
        world = context.world
        if world is None:
            from core.fake_world import FakeWorld
            world = FakeWorld("fs-anon")
        from core.fs_world import for_world

        query = parse_qs(full_path.split("?", 1)[1] if "?" in full_path else "")
        file_path = unquote(((query.get("path") or ["."])[0] or ".").strip())
        tree = for_world(world)
        result = tree.read(file_path)
        if result is None:
            response = WeaponResult.http("Not found\n", status="404")
        else:
            kind, payload, content_type = result
            if kind == "file":
                response = WeaponResult.http(payload, content_type=content_type)
            elif kind == "dir":
                response = WeaponResult.http(
                    json.dumps(
                        {"path": tree.normalize(file_path), "entries": payload},
                        ensure_ascii=False,
                    ),
                    content_type="application/json",
                )
            elif kind == "deny":
                response = WeaponResult.http("Access denied\n", status="403")
            else:
                response = WeaponResult.http("Not found\n", status="404")
        response.events.append({"kind": "file_read", "path": file_path})
        return self.with_advisory(response, context)
