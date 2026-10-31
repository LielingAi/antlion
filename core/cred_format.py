"""凭证格式合法化 — 对手会拿 bcrypt.checkpw 验证 salt, 形式不对即证伪。

Strix LFI Post-Exploit 实测: 60 字符形似 bcrypt 的串, salt 末位不在 .Oeu 内,
checkpw 直接 ValueError: Invalid salt → "不可能是任何真实口令的 bcrypt 输出"。
"""

import hashlib

_ALPHA = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_SALT_LAST = ".Oeu"          # bcrypt salt 第 22 位只编码 2 bit, 末字符只可能这四者


def bcrypt_stub(seed: str) -> str:
    """60 字符合法 bcrypt 形态: $2b$12$ + 22 位 salt + 31 位 hash。

    同 seed 恒定 (确定性世界纪律), 不需要是可逆真哈希 — 对手用错误口令 checkpw
    应得到 False 而不是 Invalid salt。
    """
    block = hashlib.sha256(f"bcrypt:{seed}".encode()).digest()
    chars = []
    while len(chars) < 53:
        chars.extend(_ALPHA[b % 64] for b in block)
        block = hashlib.sha256(block).digest()
    chars = chars[:53]
    chars[21] = _SALT_LAST[hashlib.sha256(f"salt:{seed}".encode()).digest()[0] % 4]
    return "$2b$12$" + "".join(chars)
