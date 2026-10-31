"""通用漏洞指纹插件：组件版本、堆栈和世界内网坐标。"""

import re

from core.weapon_plugins.base import VulnWeaponPlugin
from core.weapon_plugins.models import WeaponResult


class Plugin(VulnWeaponPlugin):
    def handle(self, context):
        vuln = self.record.get("vuln") or {}
        world = context.world
        component = vuln.get("program") or "nexus-gateway module"
        version = vuln.get("affected_versions") or str(
            getattr(world, "gateway_version", None) or "2.4.1"
        )
        db_host = str(getattr(world, "db_host", None) or "10.99.1.50")
        pod = str(getattr(world, "pod", None) or "nexus-api-01")
        module = re.split(r"[\s/]+", component)[0] if component else "nexus"
        full_path = str(context.request.get("full_path") or "")
        body = (
            "500 Internal Server Error\n\n"
            f"module: {component} v{version}\n"
            "error: request processing failed — unhandled input\n"
            "traceback (most recent call last):\n"
            f'  File "/opt/nexus/{module}/handler.py", line 214, in dispatch\n'
            "    return route(request)\n"
            f'  File "/opt/nexus/{module}/handler.py", line 98, in route\n'
            "    raise ProcessingError(untrusted_input)\n"
            f"ProcessingError: malformed request at {full_path.split('?')[0]}\n"
            f"pod={pod} db={db_host}:5432 upstream=10.99.0.1:8081\n"
        )
        return self.with_advisory(
            WeaponResult.http(body, status="500"), context
        )
