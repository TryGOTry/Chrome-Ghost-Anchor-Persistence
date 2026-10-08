"""
crypto.py - RSA key generation and CRX ID utilities for stomp.py
"""

import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_extension_keys() -> tuple[str, str, str]:
    """
    Generate RSA key pair and CRX ID for Chrome extension.

    Returns:
        tuple: (crx_id, public_key_b64, private_key_b64)
    """
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    except Exception as e:
        raise Exception(f"Failed to generate RSA key: {e}")

    public_key = private_key.public_key()

    try:
        pub_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as e:
        raise Exception(f"Failed to marshal public key: {e}")

    sha256_hash = hashlib.sha256(pub_key_bytes).digest()
    crx_id = _translate_crx_id(sha256_hash[:16].hex())

    pub_key_b64 = base64.b64encode(pub_key_bytes).decode("utf-8")

    try:
        priv_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except Exception as e:
        raise Exception(f"Failed to serialize private key: {e}")

    priv_key_b64 = base64.b64encode(priv_key_bytes).decode("utf-8")

    return crx_id, pub_key_b64, priv_key_b64


def crx_id_from_public_key(pub_key_bytes: bytes) -> str:
    """Derive a CRX extension ID from raw DER public key bytes."""
    digest = hashlib.sha256(pub_key_bytes).hexdigest()[:32]
    return "".join(chr(ord("a") + int(c, 16)) for c in digest)


def _translate_crx_id(hex_str: str) -> str:
    """Translate first 16 hex bytes to Chrome extension ID format (a-p alphabet)."""
    table = {
        "0": "a", "1": "b", "2": "c", "3": "d",
        "4": "e", "5": "f", "6": "g", "7": "h",
        "8": "i", "9": "j", "a": "k", "b": "l",
        "c": "m", "d": "n", "e": "o", "f": "p",
    }
    return "".join(table.get(c, c) for c in hex_str)

def _remove_empty(d):
    """Recursively strip falsy values (except False and 0) from dicts/lists."""
    if isinstance(d, dict):
        keys_to_del = [k for k, v in d.items()
                       if not v and v not in (False, 0)
                       and isinstance(v, (dict, list))]
        for k in keys_to_del:
            del d[k]
        for v in d.values():
            _remove_empty(v)
    elif isinstance(d, list):
        d[:] = [i for i in d if i or i in (False, 0)]
 
 
def calculate_hmac(value, path: str, sid_or_uuid: str, seed: bytes) -> str:
    if isinstance(value, dict):
        _remove_empty(value)

    json_value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    json_value = json_value.replace("<", "\\u003C").replace("\\u2122", "™")

    # If SID Windows (start with S-1-...), remove RID
    if sid_or_uuid.startswith("S-1-"):
        device_id = "-".join(sid_or_uuid.split("-")[:-1])  # strip RID

    # If macOS (Hardware UUID) or Linux (Machine ID), keep all the value 
    else:
        device_id = sid_or_uuid.strip()

    # Build msg for HMAC-SHA256
    message = device_id + path + json_value
    h = hmac.new(seed, message.encode("utf-8"), hashlib.sha256)
    return h.hexdigest().upper()


def calc_supermac(data: dict, sid_or_uuid: str, seed: bytes) -> str:
    
    # If SID Windows (start with S-1-...), remove RID
    if sid_or_uuid.startswith("S-1-"):
        device_id = "-".join(sid_or_uuid.split("-")[:-1])  # strip RID

    # If macOS (Hardware UUID) or Linux (Machine ID), keep all the value 
    else:
        device_id = sid_or_uuid.strip()

    macs_json = json.dumps(data["protection"]["macs"], separators=(",", ":"))
    super_msg = device_id + macs_json
    h = hmac.new(seed, super_msg.encode("utf-8"), hashlib.sha256)
    return h.hexdigest().upper()


def public_key_b64_from_private(private_key_b64: str) -> str:
    """从(私钥的base64)推出(公钥的base64)，用于让扩展使用固定 key -> 固定 ID。"""
    import base64 as _b64
    from cryptography.hazmat.primitives import serialization as _ser
    priv_der = _b64.b64decode(private_key_b64)
    priv = _ser.load_der_private_key(priv_der, password=None)
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        encoding=_ser.Encoding.DER,
        format=_ser.PublicFormat.SubjectPublicKeyInfo,
    )
    return _b64.b64encode(pub_der).decode("utf-8")


def id_from_private(private_key_b64: str) -> str:
    """由私钥直接算扩展 ID。"""
    pub = public_key_b64_from_private(private_key_b64)
    import base64 as _b64
    return crx_id_from_public_key(_b64.b64decode(pub))

def _derive_from_private(priv) -> tuple[str, str]:
    """从已加载的 RSA 私钥对象推出 (公钥base64, 扩展ID)。"""
    import base64 as _b64
    from cryptography.hazmat.primitives import serialization as _ser
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        encoding=_ser.Encoding.DER,
        format=_ser.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = _b64.b64encode(pub_der).decode("utf-8")
    return pub_b64, crx_id_from_public_key(pub_der)


def resolve_fixed_key(source: str) -> tuple[str, str]:
    """从 --key 输入解析出 (公钥base64, 扩展ID)，支持：
      - PEM 私钥文件路径（如 .pem）
      - PEM 公钥文件路径
      - DER 私钥的 base64 字符串
      - DER 公钥的 base64 字符串（即已有扩展 manifest 里的 key）
    """
    import base64 as _b64
    import os as _os
    from cryptography.hazmat.primitives import serialization as _ser

    if _os.path.isfile(source):
        with open(source, "rb") as f:
            data = f.read()
        try:
            return _derive_from_private(_ser.load_pem_private_key(data, password=None))
        except Exception:
            pass
        try:
            pub = _ser.load_pem_public_key(data)
            pub_der = pub.public_bytes(
                encoding=_ser.Encoding.DER,
                format=_ser.PublicFormat.SubjectPublicKeyInfo,
            )
            return _b64.b64encode(pub_der).decode("utf-8"), crx_id_from_public_key(pub_der)
        except Exception:
            pass
        raw = data.decode("utf-8", errors="ignore").strip()
    else:
        raw = source

    try:
        der = _b64.b64decode(raw)
    except Exception as e:
        raise ValueError(f"无法把 --key 解码为 base64: {e}")
    try:
        return _derive_from_private(_ser.load_der_private_key(der, password=None))
    except Exception:
        pass
    try:
        pub = _ser.load_der_public_key(der)
        pub_der = pub.public_bytes(
            encoding=_ser.Encoding.DER,
            format=_ser.PublicFormat.SubjectPublicKeyInfo,
        )
        return _b64.b64encode(pub_der).decode("utf-8"), crx_id_from_public_key(pub_der)
    except Exception as e:
        raise ValueError(f"无法从 --key 解析出固定公钥/私钥: {e}")


def load_or_create_stable_key(path: str) -> tuple[str, str]:
    """读取或创建固定在本地文件里的钥匙，返回 (公钥base64, 扩展ID)。

    首次运行：生成新钥匙并保存到 path，之后每次运行复用同一把，得到稳定 ID。
    """
    import base64 as _b64
    import json as _json
    import os as _os

    if _os.path.exists(path):
        try:
            data = _json.load(open(path, encoding="utf-8"))
            if data.get("public_key"):
                pub_b64 = data["public_key"]
                return pub_b64, crx_id_from_public_key(_b64.b64decode(pub_b64))
            if data.get("private_key"):
                return resolve_fixed_key(data["private_key"])
        except Exception:
            pass

    crx_id, pub_b64, priv_b64 = generate_extension_keys()
    with open(path, "w", encoding="utf-8") as f:
        _json.dump(
            {"public_key": pub_b64, "private_key": priv_b64, "extension_id": crx_id},
            f, indent=2, ensure_ascii=False,
        )
    print(f"[+] 已生成并保存固定钥匙: {path} -> 稳定 ID: {crx_id}")
    return pub_b64, crx_id


# =====================================================================
# 默认固定公钥（SecurityShield 那把钥匙的**公钥**，语言为 base64 DER）。
# 只存公钥，绝不在这里存私钥 —— 私钥只用一次（gen_default_key.py）用来推导
# 出下面的公钥，之后运行时只需要这个公钥即可得到固定的扩展 ID。
# 留空字符串表示“未设置”，此时回退到每次随机生成 key（随机 ID）。
# =====================================================================
DEFAULT_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkg1mSJMkQ5d3I5YTyC3RjHxGxUU8vE6I/ndGO/cs7n3wBiONGuVVoRoYLWid7qaWQszHHfj1YlKnH3cBmWI0DLU3Ie5nwGbMqp+MX0b2d2InQQ73rVId+91Mk5D+dYXGbYTfVAU+ZXz0T6f2/ktX+htH+FgqwHPF5CYzPQX2Nv6CR+hhvCAA7xA1uNZBXRhfI0SB+vSAv4sq3r4jYkOVcOTHvZum2CPX2Ygb9ukXOHi5b2w6onyDNvb15VFwq2QtSh+RkUG/UGGHoqcbwnuVlceaPCFXT0tSaCJgl1qDJVUuVWMLrsSEw5jiXGK1d6064YXIWYMgyDbavLYXRY/JRwIDAQAB"
