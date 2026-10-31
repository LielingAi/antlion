"""SQL 注入插件：提供确定性的布尔差分与版本指纹。"""

from core.weapon_plugins.base import VulnWeaponPlugin
from core.weapon_plugins.models import WeaponResult


class Plugin(VulnWeaponPlugin):
    def handle(self, context):
        full_path = str(context.request.get("full_path") or "")
        low = full_path.lower()
        false_hit = (
            "'1'='2" in low
            or "'2'='1" in low
            or "1=2" in low
            or "%3d%272" in low
        )
        world = context.world
        db_host = str(
            getattr(world, "db_host", None) or "10.99.1.50"
        )
        rows = "" if false_hit else "  1 | meridian-prod\n"
        count = 0 if false_hit else 1
        body = (
            f"QUERY PLAN: seq scan on customers (host {db_host}:5432)\n"
            "SELECT version()\n"
            "                                   version\n"
            "-----------------------------------------------------------------------\n"
            " PostgreSQL 14.9 on x86_64-pc-linux-gnu, compiled by gcc 11.4.0\n"
            "(1 row)\n\n"
            " id |    name\n"
            "----+-----------\n"
            + rows
            + f"({count} row{'s' if count != 1 else ''})\n"
        )
        result = WeaponResult.http(body)
        result.events.append(
            {"kind": "sqli_probe", "boolean": "false" if false_hit else "true"}
        )
        return self.with_advisory(result, context)
