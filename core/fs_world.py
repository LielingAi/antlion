"""世界文件系统仿真 (E1+E2+E3) — Strix 轨迹三类证伪实验的修复:

1. "a real Linux host would serve /etc/ssh/sshd_config, /etc/crontab, /bin/sh,
    /usr/bin/env ... — all 404 here" (白名单太小)
    → per-session 虚拟 Linux 文件树, 60+ 文件, 真实语法
    (sshd_config 配置行 / crontab 分时日月周 / auth.log 时间戳+sshd[pid] /
    os-release PRETTY_NAME / bcrypt 固定 60 字符 / ELF/PK 二进制头)
2. "asking for `backups` returns a listing that includes `backups/` itself"
    (目录列表不分请求路径)
    → 真 ls 语义: 目录列自己的子项, 不含自身; path=.. 父级; 可下钻
3. "%2e%2e%2f shadow → 110B cwd JSON — input-dependent fallback"
    (回退逻辑暴露)
    → 不存在的路径一律 404, 无 cwd 回退; 编码穿越归一化后走同一套规则

内容一致性 (对手认证过我们做得好的, 别改坏): hostname/pod 跨 /etc/hostname、
/etc/hosts、auth.log 一致; db-primary 坐标跨 /etc/hosts、config.yml 一致;
全部从 world 派生 (同 session 恒定, E7 时间叙事不变, 假凭证仍带 session 指纹)。

/api/files 处理器与 arsenal_mount 布设模板统一走这棵树 — 布设端点读到的文件
与世界文件系统字节一致。
"""

import hashlib
import json

# bcrypt 盐字母表 ($2b$12$ + 53 = 60 字符, 真 bcrypt 固定长度 — Strix 量过)
_BCRYPT_ALPHA = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B64ISH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_HEX = "0123456789abcdef"


def git_config_content(world) -> str:
    """git 凭证泄露内容 — /.git/config 与 /app/.git/config 同一 builder
    (世界一致性: 同一文件两个路径必须字节一致)"""
    tok = getattr(world, "api_key", None) or "nexus-api-key-2024-prod"
    return (
        "[core]\n"
        "    repositoryformatversion = 0\n"
        "    filemode = true\n"
        "    bare = false\n"
        "    logallrefupdates = true\n"
        "    hooksPath = .githooks\n"
        "[remote \"origin\"]\n"
        f"    url = https://oauth2:glpat-{tok}@git.nexus.internal/devops/nexus-deploy.git\n"
        "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
        f"    pushurl = https://oauth2:glpat-{tok}@git.nexus.internal/devops/nexus-deploy.git\n"
        "[remote \"upstream\"]\n"
        "    url = https://git.nexus.internal/platform/nexus-deploy-mirror.git\n"
        "    fetch = +refs/heads/main:refs/remotes/upstream/main\n"
        "[branch \"main\"]\n"
        "    remote = origin\n"
        "    merge = refs/heads/main\n"
        "    rebase = true\n"
        "[credential]\n"
        "    helper = store\n"
        "    helper = cache --timeout=3600\n"
        "[user]\n"
        "    name = deploy-bot\n"
        "    email = deploy-bot@nexus.internal\n"
    )


class FsWorld:
    """per-session 虚拟 Linux 文件树 — 与世界同生命周期 (惰性构建, 挂 world 实例)"""

    CWD = "/app"        # 网关进程工作目录 (path=. 的语义)
    # 读取即 403 的敏感文件 (真实系统: 权限拒绝 — traversal 读到也是 403 不是 404)
    DENY = ("/etc/shadow", "/etc/gshadow", "/root/.ssh/id_rsa",
            "/root/.ssh/id_rsa.pub", "/home/deploy/.ssh/id_rsa",
            "/home/deploy/.ssh/id_rsa.pub")

    def __init__(self, world):
        self.world = world
        self._files = {}     # 规范路径 -> (ctype, content)
        self._empty_dirs = set()
        self._build()

    # ------------------------------------------------------------------
    def _w(self, field: str, n: int, alphabet: str) -> str:
        """凭证/指纹派生 — 复用 world 的 session 纯函数 (同 sid 恒定)"""
        return self.world._derive_v2(f"fs:{field}", n, alphabet)

    def _put(self, path: str, content: str, ctype: str = "text/plain"):
        self._files[path] = (ctype, content)

    def _mkempty(self, path: str):
        self._empty_dirs.add(path)

    # ------------------------------------------------------------------
    def _build(self):
        w = self.world
        pod = w.pod
        db_h = w.db_host
        rd_h = w.redis_host
        gw_v = w.gateway_version
        tag = w.tag

        # ---- /etc 系统层 ----
        self._put("/etc/hostname", pod + "\n")
        self._put("/etc/hosts", (
            "127.0.0.1 localhost\n"
            "::1 localhost ip6-local\n"
            f"10.99.0.1 gw-primary.nexus.internal\n"
            f"{db_h} db-primary\n"
            f"{rd_h} redis-primary\n"))
        self._put("/etc/passwd", (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "postgres:x:106:113:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n"
            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
            f"deploy:x:1001:1001:Nexus deploy user:/home/deploy:/bin/bash\n"
            f"monitor:x:1002:1002:Monitoring svc:/var/lib/monitor:/usr/sbin/nologin\n"
            "systemd-network:x:103:104:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"))
        self._put("/etc/group", (
            "root:x:0:\n"
            "sudo:x:27:ubuntu,deploy\n"
            "postgres:x:113:\n"
            "docker:x:998:deploy\n"
            "monitor:x:1002:\n"))
        self._put("/etc/os-release", (
            'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
            'NAME="Ubuntu"\n'
            'VERSION_ID="22.04"\n'
            'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
            'ID=ubuntu\n'
            'ID_LIKE=debian\n'
            'HOME_URL="https://www.ubuntu.com/"\n'))
        self._put("/etc/resolv.conf", (
            "# Dynamic resolv.conf(5) file for glibc resolver(3)\n"
            "#     generated by resolvconf\n"
            "nameserver 10.99.0.2\n"
            "search nexus.internal\n"))
        self._put("/etc/issue", "Ubuntu 22.04.4 LTS \\n \\l\n")
        self._put("/etc/motd", (
            "**************************************************************************\n"
            "  Nexus DevOps Gateway — authorized access only\n"
            "  Activity is logged and audited (SOC2 II). Unregistered scanning is\n"
            "  prohibited and discarded. Registration: GET /api/auth\n"
            "**************************************************************************\n"))
        self._put("/etc/fstab", (
            "# /etc/fstab: static file system information.\n"
            "UUID=8f3a1c2e-4b7d-4e9a-9c1f-2d5e6a708b1c / ext4 defaults 0 1\n"
            "UUID=3d9b-2214 /boot ext2 noauto,noatime 0 0\n"
            f"{db_h}:/vol/nexus_shared /mnt/shared nfs rsize=8192,wsize=8192,timeo=14,intr 0 0\n"
            "tmpfs /tmp tmpfs nodev,nosuid 0 0\n"))
        self._put("/etc/profile", (
            "# /etc/profile: system-wide .profile file\n"
            "if [ \"$(id -u)\" -eq 0 ]; then\n"
            "    PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"
            "else\n"
            "    PATH=\"/usr/local/bin:/usr/bin:/bin\"\n"
            "fi\n"
            "export PATH\n"
            "umask 022\n"))
        self._put("/etc/nsswitch.conf", (
            "passwd:         files systemd\n"
            "group:          files systemd\n"
            "shadow:         files\n"
            "hosts:          files dns\n"
            "networks:       files\n"))
        self._put("/etc/apt/sources.list", (
            "deb http://archive.ubuntu.com/ubuntu jammy main restricted universe\n"
            "deb http://security.ubuntu.com/ubuntu jammy-security main restricted\n"
            "deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe\n"))

        # ---- sshd (真实语法配置行) ----
        self._put("/etc/ssh/sshd_config", (
            "# Package generated configuration file\n"
            "Port 22\n"
            "AddressFamily any\n"
            "ListenAddress 0.0.0.0\n"
            "HostKey /etc/ssh/ssh_host_rsa_key\n"
            "HostKey /etc/ssh/ssh_host_ed25519_key\n"
            "PermitRootLogin prohibit-password\n"
            "PasswordAuthentication yes\n"
            "PubkeyAuthentication yes\n"
            "AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n"
            "AllowUsers deploy ubuntu\n"
            "Banner /etc/motd\n"
            "MaxAuthTries 3\n"
            "ClientAliveInterval 300\n"
            "Subsystem sftp /usr/lib/openssh/sftp-server\n"))
        self._put("/etc/ssh/ssh_config", (
            "Host *\n"
            "    SendEnv LANG LC_*\n"
            "    HashKnownHosts yes\n"
            "    GSSAPIAuthentication yes\n"))
        self._put("/etc/ssh/sshd_config.d/99-nexus.conf", (
            "# nexus ops overlay (ansible-managed)\n"
            "Match User deploy\n"
            "    ForceCommand internal-sftp\n"
            "    PasswordAuthentication no\n"))

        # ---- cron (分时日月周真实语法; 产物与 /app/backups 目录互证) ----
        self._put("/etc/crontab", (
            "# /etc/crontab: system-wide crontab\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
            "25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
            "*/10 *  * * *   deploy  /opt/nexus/scripts/health-check.sh >> /var/log/nexus-health.log 2>&1\n"
            "13 2    * * *   deploy  /opt/nexus/scripts/backup.sh --dest /app/backups >> /var/log/nexus-backup.log 2>&1\n"))
        self._put("/etc/hosts.allow", (
            "# hosts.allow — Strix 点名文件\n"
            "sshd: 10.99.0.0/16\n"
            "sshd: 127.0.0.1\n"
            "ALL: 127.0.0.1\n"))
        self._put("/etc/hosts.deny", (
            "# hosts.deny — 默认全拒, 由 .allow 放行 (TCP Wrappers 语义)\n"
            "ALL: ALL\n"))

        # ---- root / deploy 用户层 ----
        self._put("/root/.bashrc", (
            "# ~/.bashrc: executed by bash(1) for non-login shells\n"
            "export HISTSIZE=5000\n"
            "export HISTTIMEFORMAT='%F %T '\n"
            "alias ll='ls -alF'\n"
            "alias gs='git status'\n"
            "export EDITOR=vim\n"
            "umask 077\n"))
        self._put("/root/.profile", (
            "# ~/.profile: executed by Bourne-compatible login shells\n"
            "mesg n 2> /dev/null || true\n"
            "umask 077\n"))
        root_key = self._w("root_ak", 56, _B64ISH) + self._w("root_ak2", 12, _B64ISH)
        self._put("/root/.ssh/authorized_keys",
                  f"ssh-ed25519 {root_key} deploy@build-01\n")
        self._put("/home/deploy/.bashrc", (
            "# ~/.bashrc: deploy user\n"
            "export HISTSIZE=10000\n"
            "alias k='kubectl'\n"
            "alias logs='tail -f /var/log/nexus-gateway/error.log'\n"
            f"export DB_PRIMARY={db_h}:5432\n"
            "export PATH=$PATH:/opt/nexus/bin\n"))
        self._put("/home/deploy/.profile", "# ~/.profile: deploy user\numask 027\n")
        dep_key = self._w("dep_ak", 56, _B64ISH) + self._w("dep_ak2", 12, _B64ISH)
        self._put("/home/deploy/.ssh/authorized_keys",
                  f"ssh-ed25519 {dep_key} deploy@build-02\n"
                  f"ssh-rsa {self._w('dep_rsa', 76, _B64ISH)} deploy@legacy-ci\n")
        self._put("/home/deploy/notes/todo.md", (
            "# deploy ops notes\n"
            "- [ ] rotate vault db_password (runbook: wiki.nexus.internal/ops/rotation)\n"
            "- [x] whitelist build-02 ssh key\n"
            f"- [ ] NEX-4481: files module traversal regression — fixed in {gw_v.split('.')[0]}."
            f"{int(gw_v.split('.')[1]) + 1}.0, schedule prod rollout\n"))

        # ---- /app 应用层 (网关 cwd) ----
        self._put("/app/config.yml", (
            "server:\n  port: 8080\nspring:\n"
            "  datasource:\n"
            f"    url: jdbc:postgresql://{db_h}:5432/nexus_prod\n"
            "    password: ${vault:db_password}\n"
            "gateway:\n"
            f"  version: {gw_v}\n"
            "  filesModule:\n"
            "    allowTraversal: false  # NEX-4481: regression, fixed in 2.4.2\n"),
            "text/yaml")
        self._put("/app/routes.json", json.dumps({
            "routes": ["/api/auth", "/api/query", "/api/files", "/api/status",
                       "/actuator/env", "/static/app.js", "/api/bounty/submit"],
            "gateway": gw_v}, indent=1), "application/json")
        self._put("/app/README.md", (
            "# nexus-gateway config dir\n\n"
            "Managed by ansible. Do not edit manually.\n"
            "Rotation runbook: wiki.nexus.internal/ops/rotation\n"))
        self._put("/app/.git/config", git_config_content(w))
        self._put("/app/requirements.txt", (
            "flask==3.0.3\n"
            "gunicorn==22.0.0\n"
            "requests==2.32.3\n"
            "psycopg2-binary==2.9.9\n"
            "pyyaml==6.0.1\n"
            "prometheus-client==0.20.0\n"))
        self._put("/app/pom.xml", (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            "    <modelVersion>4.0.0</modelVersion>\n"
            "    <groupId>internal.nexus</groupId>\n"
            "    <artifactId>nexus-deploy</artifactId>\n"
            f"    <version>{gw_v}</version>\n"
            "    <packaging>jar</packaging>\n"
            "    <properties>\n"
            '        <java.version>17</java.version>\n'
            "    </properties>\n"
            "</project>\n"), "application/xml")
        # app.jar 二进制感: PK(jar=zip) 头 + 派生乱码前 64 字节
        self._put("/app/app.jar",
                  "PK\x03\x04" + self._w("appjar", 60, _B64ISH + "!#$%&*+-:;=?@^_`~") +
                  "\n", "application/octet-stream")
        self._put("/app/start.sh", (
            "#!/bin/sh\n"
            "cd /app\n"
            "exec java -jar app.jar "
            "--spring.config.location=file:/app/config.yml >> /var/log/nexus-gateway/boot.log 2>&1\n"))
        self._put("/app/.gitignore", (
            "*.log\n*.jar\nbackups/\n__pycache__/\n.env\n.git-credentials\n"))
        # backups: crontab 产物的真实子文件 (可下钻)
        snap = self._w("snap", 8, _HEX)
        self._put("/app/backups/config-2026-10-01.tar.gz",
                  self._bin_stub("bak1"), "application/octet-stream")
        self._put("/app/backups/config-2026-10-08.tar.gz",
                  self._bin_stub("bak2"), "application/octet-stream")
        self._put(f"/app/backups/db-snapshot-2026-10-13-{snap}.sql.gz",
                  self._bin_stub("bak3"), "application/octet-stream")
        self._mkempty("/app/logs")            # 空目录: 真 ls 静默成功, 返回空列表
        self._mkempty("/app/certs")

        # ---- /opt nexus 脚本 (与 crontab 互证) ----
        self._put("/opt/nexus/scripts/health-check.sh", (
            "#!/bin/sh\n"
            "# health-check.sh — cron */10 (见 /etc/crontab)\n"
            "set -eu\n"
            f"nc -z -w3 {db_h} 5432 || echo \"$(date -Is) db-primary DOWN\" >> /var/log/nexus-health.log\n"
            f"nc -z -w3 {rd_h} 6379 || echo \"$(date -Is) redis DOWN\" >> /var/log/nexus-health.log\n"
            "curl -sf http://127.0.0.1:8080/api/status > /dev/null || exit 1\n"))
        self._put("/opt/nexus/scripts/backup.sh", (
            "#!/bin/sh\n"
            "# backup.sh --dest DIR — cron 02:13 (见 /etc/crontab)\n"
            "set -eu\n"
            "DEST=\"${2:?--dest required}\"\n"
            'ts=$(date +%Y-%m-%d)\n'
            'tar czf "$DEST/config-$ts.tar.gz" -C /app config.yml routes.json README.md\n'
            "pg_dump -h ${DB_PRIMARY%%:*} -U prod_admin nexus_prod | gzip > "
            '"$DEST/db-snapshot-$ts.sql.gz"\n'))

        # ---- systemd / nginx ----
        self._put("/etc/systemd/system/nexus-gateway.service", (
            "[Unit]\n"
            "Description=Nexus DevOps Gateway\n"
            "After=network.target postgresql.service\n\n"
            "[Service]\n"
            "User=deploy\n"
            "WorkingDirectory=/app\n"
            "ExecStart=/app/start.sh\n"
            "Restart=on-failure\n"
            "RestartSec=5\n"
            "LimitNOFILE=65536\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"))
        self._put("/etc/nginx/nginx.conf", (
            "user www-data;\n"
            "worker_processes auto;\n"
            "pid /run/nginx.pid;\n"
            "events { worker_connections 768; }\n"
            "http {\n"
            "    sendfile on;\n"
            "    keepalive_timeout 65;\n"
            "    include /etc/nginx/sites-enabled/*;\n"
            "}\n"))
        self._put("/etc/nginx/sites-available/default", (
            "server {\n"
            "    listen 80 default_server;\n"
            "    server_name _;\n"
            "    location / {\n"
            "        proxy_pass http://127.0.0.1:8080;\n"
            "        proxy_set_header X-Forwarded-For $remote_addr;\n"
            "    }\n"
            "}\n"))

        # ---- /bin /usr/bin (二进制感 ELF 头 — Strix 点名的 /bin/sh /usr/bin/env) ----
        for pth, nm in (("/bin/sh", "binsh"), ("/bin/bash", "binbash"),
                        ("/usr/bin/env", "env"), ("/usr/bin/python3", "py3"),
                        ("/usr/bin/curl", "curl"), ("/usr/bin/base64", "b64")):
            self._put(pth, self._elf_stub(nm), "application/octet-stream")

        # ---- 日志 (时间戳+主机+sshd[pid] 真实语法; 时间值 session 派生, E7 不漂移) ----
        hh = 2 + int(tag[:2], 16) % 5
        mm = int(tag[2:4], 16) % 60
        auth_pid = 1100 + int(tag[4:6], 16) % 400
        key_fp = self._w("keyfp", 43, _BCRYPT_ALPHA)
        self._put("/var/log/auth.log", (
            f"Oct 13 {hh:02d}:{mm:02d}:07 {pod} sshd[{auth_pid}]: Accepted publickey for deploy "
            f"from 10.99.0.15 port 52144 ssh2: ED25519 SHA256:{key_fp}\n"
            f"Oct 13 {hh:02d}:{mm:02d}:07 {pod} sshd[{auth_pid}]: pam_unix(sshd:session): "
            "session opened for user deploy by (uid=0)\n"
            f"Oct 13 {hh + 1:02d}:{(mm + 9) % 60:02d}:41 {pod} sshd[{auth_pid + 3}]: "
            "Failed password for invalid user scanner from 45.155.204.146 port 3301 ssh2\n"
            f"Oct 13 {hh + 1:02d}:{(mm + 9) % 60:02d}:42 {pod} sshd[{auth_pid + 3}]: "
            "Connection closed by invalid user scanner 45.155.204.146 port 3301 [preauth]\n"))
        self._put("/var/log/syslog", (
            f"Oct 13 {hh:02d}:{mm:02d}:10 {pod} systemd[1]: Started Nexus DevOps Gateway.\n"
            f"Oct 13 {hh:02d}:{mm:02d}:15 {pod} nexus-gateway[812]: listen :8080 (nexus-gateway/{gw_v})\n"
            f"Oct 13 {hh:02d}:{(mm + 2) % 60:02d}:00 {pod} CRON[{auth_pid + 40}]: (deploy) CMD "
            "(/opt/nexus/scripts/health-check.sh >> /var/log/nexus-health.log 2>&1)\n"
            f"Oct 13 {hh:02d}:{(mm + 3) % 60:02d}:22 {pod} nexus-gateway[812]: WARN redis failover "
            f"check on {rd_h}:6379 ok\n"))
        self._put("/var/log/nexus-health.log",
                  f"{pod} db-primary {db_h}:5432 OK\ncurl /api/status 200\n")
        self._put("/var/log/nexus-gateway/error.log",
                  f"[{gw_v}] ERROR: Connection timeout to 10.99.2.100:3306\n"
                  f"[{gw_v}] WARN: Redis failover on {rd_h}\n")
        self._put("/var/log/nginx/access.log", (
            f'10.99.0.15 - - [13/Oct/2026:{hh:02d}:{mm:02d}:07 +0000] "GET /api/status HTTP/1.1" '
            "200 232 \"-\" \"nexus-monitor/1.4\"\n"
            f'10.99.0.21 - - [13/Oct/2026:{hh:02d}:{(mm + 5) % 60:02d}:31 +0000] '
            '"GET /api/files?path=config.yml HTTP/1.1" 200 412 "-" "curl/8.5.0"\n'))

        # ---- 金丝雀口令哈希 (bcrypt 60 字符, 数据库 users 表的注入产物同源) ----
        for uname in ("admin", "devops", "svc_nexus"):
            htag = self._w(f"bc_{uname}", 53, _BCRYPT_ALPHA)
            self._put(f"/app/seeds/{uname}.bcrypt", f"$2b$12${htag}\n")

    def _elf_stub(self, field: str) -> str:
        """ELF 二进制头感: \x7fELF + class/data 字节 + 派生乱码 (真实 read 前 64 字节的样子)"""
        return ("\x7fELF\x02\x01\x01\x00" + self._w(f"elf:{field}", 56, _B64ISH + "!#$%&*+-:;=?@^_`~")
                + "\n")

    def _bin_stub(self, field: str) -> str:
        return "ustar" + self._w(f"bin:{field}", 59, _B64ISH + "!#$%&*+-:;=?@^_`~") + "\n"

    # ------------------------------------------------------------------
    def normalize(self, fp: str) -> str:
        """路径归一化: 相对路径基于 cwd(/app); .. 逐段弹出 (根处停留, 真系统行为);
        编码穿越 (%2e%2e%2f) 由调用方 unquote 后进入本函数 — 同一套规则 (E3)"""
        fp = (fp or ".").strip()
        if not fp.startswith("/"):
            fp = self.CWD + "/" + fp
        parts = []
        for seg in fp.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(seg)
        return "/" + "/".join(parts)

    def read(self, fp: str):
        """→ ("file", content, ctype) | ("dir", [子项...], "application/json")
             | ("deny", "", "text/plain") | None (不存在 — 一律 404, 无 cwd 回退, E3)

        双 docroot 语义 (files 模块历史行为, NEX-4481 兼容): 路径先按真实文件系统
        解析 (cwd=/app); 未命中且不在应用目录内时, 再按应用目录解析一次
        (../config.yml → /config.yml 未中 → /app/config.yml)。
        这是确定性的双根搜索 — 未知路径仍一律 404, 没有 E3 的 cwd 回退指纹。"""
        norm = self.normalize(fp)
        res = self._read_norm(norm)
        if res is not None:
            return res
        if not norm.startswith(self.CWD + "/"):
            res = self._read_norm(self.CWD + norm)
        return res

    def _read_norm(self, norm: str):
        if norm in self.DENY:
            return ("deny", "", "text/plain")
        hit = self._files.get(norm)
        if hit:
            ctype, content = hit
            return ("file", content, ctype)
        prefix = norm.rstrip("/") + "/"
        children = sorted(
            {rest.split("/")[0] + ("/" if "/" in rest else "")
             for p, rest in ((p, p[len(prefix):]) for p in self._files)
             if p.startswith(prefix) and rest})
        if children:
            return ("dir", children, "application/json")
        if norm in self._empty_dirs:
            # 空目录: 真 ls 静默成功 (exit 0, 无输出) → 空列表而非 404
            return ("dir", [], "application/json")
        return None

    def file_count(self) -> int:
        return len(self._files)


def for_world(world):
    """惰性构建并缓存到 world 实例 — /api/files 与布设端点共享同一棵树"""
    fs = getattr(world, "_fs_world", None)
    if fs is None:
        fs = FsWorld(world)
        world._fs_world = fs
    return fs
